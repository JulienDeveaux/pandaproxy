"""A local certificate authority, so slicers can be made to trust the proxy.

BambuStudio validates the MQTT certificate against BambuLab's own roots and
answers a fatal ``unknown_ca`` alert to anything else - measured on the wire,
seven bytes: ``15 03 03 00 02 02 30``. A self-signed certificate can therefore
never work, and no amount of getting the subject or the SANs right changes
that: the chain is what it objects to.

What *can* work is a certificate signed by an authority the user has chosen to
trust. This module keeps such an authority next to the proxy's own key and
signs its leaf with it. The user then adds the authority - the certificate
only, never the key - to the slicer's trust store.

That is a real trust decision, not a workaround to be applied silently:
anything this authority signs will be accepted by that slicer. The private key
stays in the proxy's cert volume and must not travel.
"""

from __future__ import annotations

import datetime
import ipaddress
import logging
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

CA_CERT_FILENAME = "pandaproxy-ca.crt"
CA_KEY_FILENAME = "pandaproxy-ca.key"

# Long enough that nobody has to think about it again soon, short enough to
# stay a defensible thing to trust.
CA_VALID_DAYS = 3650
LEAF_VALID_DAYS = 825  # what public CAs are held to; a sane ceiling


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


def load_ca(
    cert_path: Path, key_path: Path
) -> tuple[x509.Certificate, rsa.RSAPrivateKey] | None:
    """Load an existing authority, or None if it is absent or unreadable."""
    if not cert_path.exists() or not key_path.exists():
        return None
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError) as e:
        logger.warning("Cannot read the existing authority (%s); regenerating", e)
        return None
    if not isinstance(key, rsa.RSAPrivateKey):
        logger.warning("Existing authority key is not RSA; regenerating")
        return None
    return cert, key


def create_ca(
    cert_path: Path, key_path: Path, common_name: str = "PandaProxy Local CA"
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Create an authority and write it out.

    The key is written with owner-only permissions: it is the one file here
    that must never be handed to a slicer.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    logger.info("Created a local certificate authority at %s", cert_path)
    return cert, key


def issue_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    cert_path: Path,
    key_path: Path,
    common_name: str = "PandaProxy",
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
) -> None:
    """Issue the proxy's own certificate, signed by the authority."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    names: list[x509.GeneralName] = [x509.DNSName(dns) for dns in san_dns or []]
    for address in san_ips or []:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(address)))
        except ValueError:
            logger.warning("Skipping %r in the certificate: not an address", address)
    if not names:
        names.append(x509.DNSName("localhost"))

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now())
        .not_valid_after(_now() + datetime.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    # The chain, leaf first: a client that only trusts the authority still
    # needs to be handed the path to it.
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )


def is_signed_by(cert_path: Path, ca_cert: x509.Certificate) -> bool:
    """Whether the leaf at ``cert_path`` was really issued by ``ca_cert``.

    Verifies the signature rather than comparing issuer names: every authority
    this module creates carries the same subject, so a name match would also
    accept a leaf signed by a *different* one - and the proxy would go on
    serving a certificate no client trusts.
    """
    try:
        leaf = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except OSError, ValueError:
        return False
    try:
        leaf.verify_directly_issued_by(ca_cert)
    except InvalidSignature, ValueError, TypeError:
        # InvalidSignature: another authority with the same name signed it.
        # ValueError/TypeError: mismatched names, or an algorithm we cannot check.
        return False
    return True
