"""CLI entry point for PandaProxy."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer

from pandaproxy.ca import (
    CA_CERT_FILENAME,
    CA_KEY_FILENAME,
    create_ca,
    is_signed_by,
    issue_leaf,
    load_ca,
)
from pandaproxy.chamber_proxy import ChamberImageProxy
from pandaproxy.detection import detect_camera_type
from pandaproxy.ftp_proxy import (
    FTP_DATA_PORT_END,
    FTP_DATA_PORT_START,
    FTPProxy,
)
from pandaproxy.helper import certificate_expires_soon
from pandaproxy.mqtt_proxy import MQTTProxy
from pandaproxy.protocol import CERT_FILENAME, KEY_FILENAME, PRINTER_CERT_FILENAME
from pandaproxy.rtsp_proxy import RTSPProxy
from pandaproxy.ssdp import BROADCAST as SSDP_BROADCAST
from pandaproxy.ssdp import (
    DEFAULT_DEV_MODEL,
    DEFAULT_DEV_NAME,
    DEFAULT_INTERVAL,
    SsdpAnnouncer,
)
from pandaproxy.state_cache import is_ipv4


def resolve_file_env_var(var: str) -> None:
    """Populate ``var`` from ``{var}_FILE`` if set and ``var`` itself isn't (Docker secrets convention)."""
    if os.environ.get(var):
        return
    file_path = os.environ.get(f"{var}_FILE")
    if file_path:
        try:
            os.environ[var] = Path(file_path).read_text().strip()
        except FileNotFoundError:
            raise RuntimeError(
                f"{var}_FILE points to a nonexistent file: {file_path}"
            ) from None
        except OSError as e:
            raise RuntimeError(f"Failed to read {var}_FILE ({file_path}): {e}") from e


resolve_file_env_var("ACCESS_CODE")


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"PandaProxy v{version('PandaProxy')}")
        raise typer.Exit()


app = typer.Typer(
    name="PandaProxy",
    help="BambuLab Multi-Service Proxy - Proxy camera, MQTT, and FTP from BambuLab printers to multiple clients.",
    add_completion=False,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def check_dependencies(
    services: set[str], camera_type: str | None
) -> tuple[bool, list[str]]:
    """Check for required external dependencies based on enabled services."""
    missing = []

    # Camera service dependencies
    if "camera" in services and camera_type == "rtsp":
        if not shutil.which("ffmpeg"):
            missing.append("ffmpeg")
        if not shutil.which("mediamtx"):
            missing.append("mediamtx")

    return len(missing) == 0, missing


def parse_services(services_str: str | None, enable_all: bool) -> set[str]:
    """Parse services string into a set of service names."""
    all_services = {"camera", "mqtt", "ftp"}

    if enable_all:
        return all_services

    if not services_str:
        return {"camera"}  # Default to camera only

    services = {s.strip().lower() for s in services_str.split(",")}

    # Validate service names
    invalid = services - all_services
    if invalid:
        raise typer.BadParameter(
            f"Invalid service(s): {', '.join(invalid)}. Valid services: {', '.join(all_services)}"
        )

    return services


def certificate_covers(cert_path: Path, address: str) -> bool:
    """Whether an existing certificate lists ``address`` in its SANs.

    The certificate is deliberately persisted across restarts, so adding
    ADVERTISE_IP later must not leave clients validating against a name the
    certificate never claimed.
    """
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return address in {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    except Exception as e:
        # An unreadable or SAN-less certificate is treated as not covering it,
        # so it gets regenerated rather than silently kept.
        logger.warning("Could not inspect %s: %s", cert_path, e)
        return False


def is_running_in_docker() -> bool:
    """Check if the application is running inside a Docker container."""
    # Check for the existence of .dockerenv file
    if Path("/.dockerenv").exists():
        return True

    # Check for RUNNING_IN_DOCKER environment variable (used in our Dockerfile)
    if os.environ.get("RUNNING_IN_DOCKER"):
        return True

    # Check cgroup for "docker" string on Linux
    try:
        with Path("/proc/1/cgroup").open() as f:
            return "docker" in f.read()
    except FileNotFoundError:
        pass  # File doesn't exist, not a Linux-based container

    return False


async def run_proxy(
    printer_ip: str,
    access_code: str,
    serial_number: str,
    bind: str,
    services: set[str],
    camera_type: str | None,
    printer_cert_path: Path,
    advertise_ip: str | None = None,
    data_port_start: int = FTP_DATA_PORT_START,
    data_port_end: int = FTP_DATA_PORT_END,
    ssdp_targets: list[str] | None = None,
    ssdp_dev_model: str = DEFAULT_DEV_MODEL,
    ssdp_dev_name: str = DEFAULT_DEV_NAME,
    ssdp_dev_version: str = "",
    ssdp_interval: float = DEFAULT_INTERVAL,
) -> None:
    """Run the proxy servers based on enabled services."""
    chamber_proxy: ChamberImageProxy | None = None
    rtsp_proxy: RTSPProxy | None = None
    mqtt_proxy: MQTTProxy | None = None
    ftp_proxy: FTPProxy | None = None
    announcer: SsdpAnnouncer | None = None
    background_tasks = []

    # Setup signal handlers for graceful shutdown
    stop_event = asyncio.Event()

    def signal_handler() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # noinspection PyTypeChecker
        loop.add_signal_handler(sig, signal_handler)

    # Under bridge networking the socket only ever sees the container's own
    # private address, so PASV replies and the MQTT-reported printer address
    # would both point somewhere no LAN client can reach.
    if not advertise_ip and is_running_in_docker():
        logger.warning(
            "Running in Docker without --advertise-ip / ADVERTISE_IP. If this "
            "container uses bridge networking with published ports, set it to "
            "the Docker host's LAN address or passive FTP transfers and slicer "
            "uploads will be sent to an unreachable address."
        )

    try:
        # Generate shared TLS certificate
        certs_dir = Path("certs")
        certs_dir.mkdir(exist_ok=True)  # noqa: ASYNC240  # asyncio-native app; trio/anyio not used
        cert_path = certs_dir / CERT_FILENAME
        key_path = certs_dir / KEY_FILENAME

        # Signed by a local authority rather than self-signed: BambuStudio
        # validates the chain and answers a fatal unknown_ca alert to anything
        # self-signed, whatever its subject or SANs say.
        ca_cert_path = certs_dir / CA_CERT_FILENAME
        ca_key_path = certs_dir / CA_KEY_FILENAME
        loaded = load_ca(ca_cert_path, ca_key_path)
        if loaded is None:
            loaded = create_ca(ca_cert_path, ca_key_path)
        ca_cert, ca_key = loaded

        san_ips = ["127.0.0.1", "::1"]
        if bind != "0.0.0.0":  # noqa: S104  # intentional: skip adding default bind-all to SAN
            san_ips.append(bind)
        # This is the address clients are told to dial, so a client that
        # validates the certificate against it needs it listed.
        if advertise_ip and advertise_ip not in san_ips:
            san_ips.append(advertise_ip)

        reason = None
        if not cert_path.exists() or not key_path.exists():
            reason = "no certificate yet"
        elif not is_signed_by(cert_path, ca_cert):
            reason = "the existing certificate is not signed by the local CA"
        elif advertise_ip and not certificate_covers(cert_path, advertise_ip):
            reason = f"the existing certificate does not cover {advertise_ip}"
        elif certificate_expires_soon(cert_path):
            reason = "the existing certificate has expired or is about to"

        if reason:
            logger.info("Issuing the proxy certificate: %s", reason)
            issue_leaf(
                ca_cert,
                ca_key,
                cert_path,
                key_path,
                common_name="PandaProxy",
                san_dns=["localhost"],
                san_ips=san_ips,
            )

        logger.info(
            "Slicers that verify certificates must trust %s. BambuStudio reads "
            "its trust store from Contents/Resources/cert/printer.cer inside "
            "its app bundle; append that file's contents there. Never copy the "
            "matching .key.",
            ca_cert_path,
        )

        # Instantiate camera proxy if enabled
        if "camera" in services and camera_type:
            if camera_type == "chamber":
                chamber_proxy = ChamberImageProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    cert_path=cert_path,
                    key_path=key_path,
                    bind_address=bind,
                    printer_cert_path=printer_cert_path,
                )
            elif camera_type == "rtsp":
                rtsp_proxy = RTSPProxy(
                    printer_ip=printer_ip,
                    access_code=access_code,
                    cert_path=cert_path,
                    key_path=key_path,
                    bind_address=bind,
                )

        # Instantiate MQTT proxy if enabled
        if "mqtt" in services:
            mqtt_proxy = MQTTProxy(
                printer_ip=printer_ip,
                access_code=access_code,
                serial_number=serial_number,
                cert_path=cert_path,
                key_path=key_path,
                bind_address=bind,
                printer_cert_path=printer_cert_path,
                advertise_ip=advertise_ip,
            )

        # Instantiate FTP proxy if enabled
        if "ftp" in services:
            ftp_proxy = FTPProxy(
                printer_ip=printer_ip,
                access_code=access_code,
                cert_path=cert_path,
                key_path=key_path,
                bind_address=bind,
                printer_cert_path=printer_cert_path,
                advertise_ip=advertise_ip,
                data_port_start=data_port_start,
                data_port_end=data_port_end,
            )

        # Start all services concurrently
        # Collect start coroutines from instantiated proxies
        start_tasks = []
        if chamber_proxy:
            start_tasks.append(chamber_proxy.start())
        if rtsp_proxy:
            start_tasks.append(rtsp_proxy.start())
        if mqtt_proxy:
            start_tasks.append(mqtt_proxy.start())
        if ftp_proxy:
            start_tasks.append(ftp_proxy.start())

        if start_tasks:
            await asyncio.gather(*start_tasks)

        # IMPORTANT: Background tasks must be created AFTER start() completes
        # because they depend on _running being True (set in start())
        if chamber_proxy:
            background_tasks.append(
                asyncio.create_task(chamber_proxy.run_upstream_loop())
            )
        if rtsp_proxy:
            background_tasks.append(asyncio.create_task(rtsp_proxy.run_monitor_loop()))
        if mqtt_proxy:
            background_tasks.append(asyncio.create_task(mqtt_proxy.run_upstream_loop()))

        # BambuStudio only dials addresses it has seen announced, so without
        # this it cannot reach the proxy at all - whatever the user types.
        if ssdp_targets and advertise_ip:
            announcer = SsdpAnnouncer(
                advertise_ip=advertise_ip,
                serial=serial_number,
                targets=ssdp_targets,
                interval=ssdp_interval,
                dev_model=ssdp_dev_model,
                dev_name=ssdp_dev_name,
                dev_version=ssdp_dev_version,
                # The printer reports its own version, so the user does not
                # have to know it - and an empty one makes Studio refuse.
                version_provider=(
                    mqtt_proxy.firmware_version if mqtt_proxy is not None else None
                ),
            )
            announcer.start()
            background_tasks.append(asyncio.create_task(announcer.run()))
        elif ssdp_targets and not advertise_ip:
            logger.warning(
                "SSDP targets given without --advertise-ip; announcing the "
                "container's own address would be useless, so it is disabled"
            )

        # Print startup banner
        typer.echo("\n" + "=" * 60)
        typer.echo(f"PandaProxy v{version('PandaProxy')} is running!")
        typer.echo("=" * 60)
        typer.echo(f"Printer: {printer_ip}")
        typer.echo(f"Serial Number: {serial_number}")
        typer.echo("-" * 60)
        typer.echo("Active Services:")

        if "camera" in services and camera_type:
            if camera_type == "chamber":
                typer.echo(f"  Camera: {bind}:6000 (TLS) - Chamber Image")
            elif camera_type == "rtsp":
                typer.echo(f"  Camera: rtsp://bblp:<access_code>@{bind}:322/stream")

        if "mqtt" in services:
            typer.echo(f"  MQTT: mqtts://{bind}:8883 (TLS)")

        if "ftp" in services:
            typer.echo(f"  FTP: ftps://{bind}:990 (implicit TLS, passive mode)")

        typer.echo("=" * 60)
        if not is_running_in_docker():
            typer.echo("Press Ctrl+C to stop\n")

        # Wait for shutdown signal
        await stop_event.wait()

    finally:
        logger.info("Shutting down...")

        # Cancel background tasks
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        # Create a list of stop coroutines from the proxies that were started
        stop_tasks = []
        if chamber_proxy:
            stop_tasks.append(chamber_proxy.stop())
        if rtsp_proxy:
            stop_tasks.append(rtsp_proxy.stop())
        if mqtt_proxy:
            stop_tasks.append(mqtt_proxy.stop())
        if ftp_proxy:
            stop_tasks.append(ftp_proxy.stop())
        if announcer:
            announcer.stop()

        # Stop all services concurrently
        if stop_tasks:
            await asyncio.gather(*stop_tasks)

        logger.info("Shutdown complete")


@app.command()
def main(
    printer_ip: Annotated[
        str,
        typer.Option(
            "--printer-ip",
            "-p",
            help="IP address of the BambuLab printer",
            envvar="PRINTER_IP",
        ),
    ],
    access_code: Annotated[
        str,
        typer.Option(
            "--access-code",
            "-a",
            help="Access code for the printer (found in printer settings)",
            envvar="ACCESS_CODE",
        ),
    ],
    serial_number: Annotated[
        str,
        typer.Option(
            "--serial-number",
            "-s",
            help="Serial number of the printer (required for MQTT)",
            envvar="SERIAL_NUMBER",
        ),
    ],
    bind: Annotated[
        str,
        typer.Option(
            "--bind",
            "-b",
            help="Address to bind the proxy servers to",
            envvar="BIND_ADDRESS",
        ),
    ] = "0.0.0.0",  # noqa: S104  # pandaproxy defaults to bind all interfaces
    services: Annotated[
        str | None,
        typer.Option(
            "--services",
            help="Comma-separated list of services to enable: camera,mqtt,ftp",
            envvar="SERVICES",
        ),
    ] = None,
    enable_all: Annotated[
        bool,
        typer.Option(
            "--enable-all",
            help="Enable all services (camera, mqtt, ftp)",
            envvar="ENABLE_ALL",
        ),
    ] = False,
    cert: Annotated[
        Path,
        typer.Option(
            "--cert",
            help="Path to the printer's CA certificate used to verify TLS connections",
            envvar="PRINTER_CERT",
        ),
    ] = Path(PRINTER_CERT_FILENAME),
    data_port_start: Annotated[
        int,
        typer.Option(
            "--data-port-start",
            help="First passive FTP data port (must be published in Docker)",
            envvar="FTP_DATA_PORT_START",
        ),
    ] = FTP_DATA_PORT_START,
    data_port_end: Annotated[
        int,
        typer.Option(
            "--data-port-end",
            help="Last passive FTP data port",
            envvar="FTP_DATA_PORT_END",
        ),
    ] = FTP_DATA_PORT_END,
    ssdp_targets: Annotated[
        str | None,
        typer.Option(
            "--ssdp-targets",
            help=(
                "Comma-separated addresses to send SSDP announcements to, so "
                "BambuStudio can find the proxy. Usually the machines running "
                "a slicer: a container on a Docker bridge cannot broadcast "
                "onto the LAN but can unicast to them. Empty disables it; "
                "'broadcast' sends to 255.255.255.255."
            ),
            envvar="SSDP_TARGETS",
        ),
    ] = None,
    ssdp_dev_model: Annotated[
        str,
        typer.Option(
            "--ssdp-dev-model",
            help="Model code announced to slicers (C12 is the P1S)",
            envvar="SSDP_DEV_MODEL",
        ),
    ] = DEFAULT_DEV_MODEL,
    ssdp_dev_name: Annotated[
        str,
        typer.Option(
            "--ssdp-dev-name",
            help="Name shown in the slicer's device list",
            envvar="SSDP_DEV_NAME",
        ),
    ] = DEFAULT_DEV_NAME,
    ssdp_dev_version: Annotated[
        str,
        typer.Option(
            "--ssdp-dev-version",
            help=(
                "Firmware version announced to slicers. BambuStudio refuses a "
                "device announcing an empty one; left unset it is taken from "
                "the printer's own MQTT reports."
            ),
            envvar="SSDP_DEV_VERSION",
        ),
    ] = "",
    ssdp_interval: Annotated[
        float,
        typer.Option(
            "--ssdp-interval",
            help="Seconds between announcements; must outpace the printer's own",
            envvar="SSDP_INTERVAL",
        ),
    ] = DEFAULT_INTERVAL,
    advertise_ip: Annotated[
        str | None,
        typer.Option(
            "--advertise-ip",
            help=(
                "Address to advertise to clients (FTP PASV replies and the "
                "printer address in MQTT reports). Required behind Docker "
                "bridge networking, where the container's own address is "
                "unreachable from the LAN."
            ),
            envvar="ADVERTISE_IP",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose/debug logging",
            envvar="DEBUG",
        ),
    ] = False,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    """Start the BambuLab multiservice proxy.

    This proxy connects to your BambuLab printer and serves multiple clients,
    preventing connection limit issues. It can proxy camera streams, MQTT
    (for printer control/status), and FTP (for file uploads).

    Services:
    - camera: Auto-detected (Chamber Image for A1/P1, RTSP for X1/H2/P2)
    - mqtt: MQTTS on port 8883 for printer control and status
    - ftp: Implicit FTPS on port 990 for file uploads

    Examples:
        # Camera only (default)
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001

        # All services
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --enable-all

        # Specific services
        pandaproxy -p 192.168.1.100 -a 12345678 -s 01P00A000000001 --services camera,mqtt
    """
    # Set log level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Parse services
    try:
        enabled_services = parse_services(services, enable_all)
    except typer.BadParameter as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1) from None

    # Before anything else: the value ends up inside FTP PASV replies and in
    # the printer address of MQTT reports, both numeric, so a hostname cannot
    # work and failing here beats failing on every report later.
    if advertise_ip and not is_ipv4(advertise_ip):
        typer.echo(
            f"Error: --advertise-ip must be an IPv4 address, got {advertise_ip!r}.",
            err=True,
        )
        raise typer.Exit(1)

    for name, value in (
        ("--data-port-start", data_port_start),
        ("--data-port-end", data_port_end),
    ):
        if not 1 <= value <= 65535:
            typer.echo(
                f"Error: {name} must be between 1 and 65535, got {value}.", err=True
            )
            raise typer.Exit(1)

    if data_port_start > data_port_end:
        typer.echo(
            f"Error: --data-port-start ({data_port_start}) is above "
            f"--data-port-end ({data_port_end}).",
            err=True,
        )
        raise typer.Exit(1)

    service_ports = {322: "RTSP", 990: "FTP control", 6000: "camera", 8883: "MQTT"}
    clash = {
        port: name
        for port, name in service_ports.items()
        if data_port_start <= port <= data_port_end
    }
    if clash:
        listed = ", ".join(f"{port} ({name})" for port, name in sorted(clash.items()))
        typer.echo(
            f"Error: the data port range {data_port_start}-{data_port_end} "
            f"covers a service port: {listed}.",
            err=True,
        )
        raise typer.Exit(1)

    parsed_ssdp_targets = [
        part.strip() for part in (ssdp_targets or "").split(",") if part.strip()
    ]
    if parsed_ssdp_targets == ["broadcast"]:
        parsed_ssdp_targets = [SSDP_BROADCAST]

    typer.echo(f"Connecting to printer at {printer_ip}...")
    typer.echo(f"Enabled services: {', '.join(sorted(enabled_services))}")

    # Detect camera type if camera service is enabled
    camera_type: str | None = None
    if "camera" in enabled_services:
        try:
            camera_type = asyncio.run(detect_camera_type(printer_ip, access_code, cert))
            if camera_type:
                typer.echo(f"Detected camera type: {camera_type.upper()}")
            else:
                typer.echo(
                    "Warning: Could not detect camera type. Camera service will be disabled.",
                    err=True,
                )
                enabled_services.discard("camera")
        except RuntimeError as e:
            typer.echo(f"Warning: Could not detect camera type: {e}", err=True)
            typer.echo("Camera service will be disabled.", err=True)
            enabled_services.discard("camera")

    # Check dependencies for enabled services
    dependencies_satisfied, dependencies_missing = check_dependencies(
        enabled_services, camera_type
    )
    if not dependencies_satisfied:
        typer.echo("Error: Missing required dependencies:", err=True)
        for dep in dependencies_missing:
            if dep == "ffmpeg":
                typer.echo("  - ffmpeg: Install via your package manager", err=True)
                typer.echo(
                    "      Linux: apt install ffmpeg / pacman -S ffmpeg", err=True
                )
                typer.echo("      macOS: brew install ffmpeg", err=True)
            elif dep == "mediamtx":
                typer.echo(
                    "  - mediamtx: Download from https://github.com/bluenviron/mediamtx/releases",
                    err=True,
                )
        raise typer.Exit(1)

    if not enabled_services:
        typer.echo("Error: No services enabled.", err=True)
        raise typer.Exit(1)

    typer.echo("Starting PandaProxy...")

    # Run the async proxy
    asyncio.run(
        run_proxy(
            printer_ip=printer_ip,
            access_code=access_code,
            serial_number=serial_number,
            bind=bind,
            services=enabled_services,
            camera_type=camera_type,
            printer_cert_path=cert,
            advertise_ip=advertise_ip,
            data_port_start=data_port_start,
            data_port_end=data_port_end,
            ssdp_targets=parsed_ssdp_targets,
            ssdp_dev_model=ssdp_dev_model,
            ssdp_dev_name=ssdp_dev_name,
            ssdp_dev_version=ssdp_dev_version,
            ssdp_interval=ssdp_interval,
        )
    )


if __name__ == "__main__":
    app()
