"""Shared helper utilities for PandaProxy."""

import asyncio
import contextlib
import datetime
import ipaddress
import logging
import os
import ssl
import struct
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


def create_ssl_context() -> ssl.SSLContext:
    """Create an SSL context that verifies BambuLab printer certificates.

    Uses the bundled printer.cer CA certificates to verify the printer's identity.
    """
    from importlib.resources import files

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    # Load the bundled CA certificates
    cert_path = files("pandaproxy").joinpath("printer.cer")
    ctx.load_verify_locations(str(cert_path))

    return ctx


def create_auth_payload(access_code: str) -> bytes:
    """Create the 80-byte authentication payload for chamber image protocol.

    Format:
    - Bytes 0-3: 0x40 0x00 0x00 0x00 (magic)
    - Bytes 4-7: 0x00 0x30 0x00 0x00 (command)
    - Bytes 8-15: zeros (padding)
    - Bytes 16-47: username "bblp" (32 bytes, null-padded)
    - Bytes 48-79: access code (32 bytes, null-padded)
    """
    from .protocol import AUTH_COMMAND, AUTH_MAGIC

    username = b"bblp"
    access_code_bytes = access_code.encode("utf-8")

    return struct.pack(
        "<II8s32s32s",
        AUTH_MAGIC,
        AUTH_COMMAND,
        b"\x00" * 8,
        username.ljust(32, b"\x00"),
        access_code_bytes.ljust(32, b"\x00"),
    )


def parse_auth_payload(data: bytes) -> str | None:
    """Parse authentication payload and extract access code.

    Returns the access code if valid, None otherwise.
    """
    from .protocol import AUTH_COMMAND, AUTH_MAGIC

    if len(data) != 80:
        return None

    try:
        magic, command, _, _username, access_code = struct.unpack("<II8s32s32s", data)

        if magic != AUTH_MAGIC or command != AUTH_COMMAND:
            return None

        # Strip null padding from access code
        return access_code.rstrip(b"\x00").decode("utf-8")
    except (struct.error, UnicodeDecodeError):
        return None


def generate_self_signed_cert(
    common_name: str = "PandaProxy",
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    output_cert: Path | None = None,
    output_key: Path | None = None,
) -> tuple[Path, Path]:
    """Generate a self-signed certificate and key.

    Args:
        common_name: Common Name (CN) for the certificate
        san_dns: List of DNS names for Subject Alternative Name (SAN)
        san_ips: List of IP addresses for Subject Alternative Name (SAN)
        output_cert: Optional path to write the certificate to
        output_key: Optional path to write the key to

    Returns:
        Tuple of (cert_path, key_path).
        If output paths are not provided, returns paths to temporary files.
    """
    # Generate key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate self-signed certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    )

    # Add SANs if provided
    sans: list[x509.GeneralName] = []
    if san_dns:
        sans.extend(x509.DNSName(dns) for dns in san_dns)
    if san_ips:
        sans.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips)

    if not sans:
        # Default to localhost if no SANs provided
        sans.append(x509.DNSName("localhost"))

    builder = builder.add_extension(
        x509.SubjectAlternativeName(sans),
        critical=False,
    )

    cert = builder.sign(key, hashes.SHA256())

    if output_cert and output_key:
        cert_path = output_cert
        key_path = output_key
    else:
        # Write to temp files
        cert_fd, cert_path_str = tempfile.mkstemp(suffix=".pem", prefix="cert_")
        key_fd, key_path_str = tempfile.mkstemp(suffix=".pem", prefix="key_")
        os.close(cert_fd)
        os.close(key_fd)
        cert_path = Path(cert_path_str)
        key_path = Path(key_path_str)

    with key_path.open("wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with cert_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


async def open_connection_safe(
    host: str,
    port: int,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 10.0,  # noqa: ASYNC109  # timeout IS enforced via asyncio.wait_for below
    name: str = "",
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open a TCP connection with standard error handling.

    Returns (reader, writer) on success, or None if the connection could not be established.
    Logs connection-level failures (timeout, refused, OS error) at DEBUG level.
    Other exceptions (e.g. CancelledError) propagate normally.

    Args:
        host: Hostname or IP address to connect to
        port: TCP port number
        ssl_context: Optional SSL context for TLS connections
        timeout: Connection timeout in seconds (default 10s)
        name: Label used in log messages (e.g. "chamber port 6000")
    """
    label = f"{name} " if name else ""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout,
        )
        return reader, writer
    except TimeoutError:
        logger.debug("%sconnection to %s:%d timed out", label, host, port)
    except ConnectionRefusedError:
        logger.debug("%sconnection to %s:%d refused", label, host, port)
    except OSError as e:
        logger.debug("%sconnection to %s:%d failed: %s", label, host, port, e)
    return None


async def close_writer(writer: asyncio.StreamWriter, timeout: float = 2.0) -> None:  # noqa: ASYNC109  # timeout IS enforced via asyncio.wait_for below
    """Safely close an asyncio StreamWriter with timeout.

    If the graceful close times out (common with SSL), aborts the transport
    to force immediate closure.

    Args:
        writer: The StreamWriter to close
        timeout: Maximum seconds to wait for close to complete (default 2s)
    """
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except TimeoutError:
        # SSL shutdown hanging - abort to force close
        transport = writer.transport
        if transport:
            transport.abort()
    except Exception:  # noqa: S110  # suppress residual errors during stream teardown (e.g. SSL reset)
        pass  # non-actionable at this point; connection is already gone


async def cancel_task(task: asyncio.Task, grace: float = 2.0) -> None:
    """Cancel an asyncio Task, giving it a grace period to finish naturally first.

    Waits up to *grace* seconds for the task to complete on its own (e.g. after
    its underlying I/O source closes), then cancels it and waits for the
    cancellation to propagate.  Safe to call on an already-done task.
    """
    with contextlib.suppress(asyncio.CancelledError, TimeoutError):
        await asyncio.wait_for(task, timeout=grace)
    with contextlib.suppress(asyncio.CancelledError):
        await task
