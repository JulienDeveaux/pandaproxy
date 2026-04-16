"""Camera stream type detection for BambuLab printers.

Detects whether a printer uses RTSP (port 322) or Chamber Image (port 6000)
protocol by probing both endpoints.
"""

import asyncio
import logging
import ssl
import struct

from pandaproxy.helper import (
    close_writer,
    create_auth_payload,
    create_ssl_context,
    open_connection_safe,
)
from pandaproxy.protocol import CHAMBER_PORT, MAX_PAYLOAD_SIZE, RTSP_PORT

logger = logging.getLogger(__name__)

# Connection timeout for detection
DETECT_TIMEOUT = 5.0


async def _probe_chamber_port(ip: str, access_code: str, ssl_context: ssl.SSLContext) -> bool:
    """Probe the chamber image port (6000) to see if it responds.

    Returns True if the printer responds to the chamber image protocol.
    """
    result = await open_connection_safe(
        ip, CHAMBER_PORT, ssl_context=ssl_context, timeout=DETECT_TIMEOUT, name=f"chamber port {CHAMBER_PORT}"
    )
    if result is None:
        return False

    reader, writer = result
    try:
        # Send authentication payload
        auth_payload = create_auth_payload(access_code)
        writer.write(auth_payload)
        await writer.drain()

        # Try to read the 16-byte header response
        header = await asyncio.wait_for(reader.read(16), timeout=DETECT_TIMEOUT)

        if len(header) >= 4:
            # Check if we got a valid payload size
            payload_size = struct.unpack("<I", header[0:4])[0]
            if 0 < payload_size < MAX_PAYLOAD_SIZE:
                logger.debug("Chamber image protocol detected (payload size: %d)", payload_size)
                return True

    except (TimeoutError, OSError) as e:
        logger.debug("Chamber port %d probe failed: %s", CHAMBER_PORT, e)
    finally:
        await close_writer(writer)

    return False


async def _probe_rtsp_port(ip: str, ssl_context: ssl.SSLContext) -> bool:
    """Probe the RTSP port (322) to see if it responds.

    Returns True if the printer has an open RTSPS port.
    """
    result = await open_connection_safe(
        ip, RTSP_PORT, ssl_context=ssl_context, timeout=DETECT_TIMEOUT, name=f"RTSP port {RTSP_PORT}"
    )
    if result is None:
        return False

    reader, writer = result
    try:
        # Send RTSP OPTIONS request
        request = f"OPTIONS rtsp://{ip}:{RTSP_PORT}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        # Try to read response
        response = await asyncio.wait_for(reader.read(1024), timeout=DETECT_TIMEOUT)

        if response:
            if b"RTSP/1.0" in response or b"RTSP/2.0" in response:
                logger.debug("RTSP protocol detected")
            else:
                # Port is open with TLS but no RTSP banner - still likely an RTSP printer
                logger.debug("RTSP port open but unexpected response, assuming RTSP")
            return True

    except (TimeoutError, OSError) as e:
        logger.debug("RTSP port %d probe failed: %s", RTSP_PORT, e)
    finally:
        await close_writer(writer)

    return False


async def detect_camera_type(ip: str, access_code: str) -> str:
    """Detect the camera stream type for a BambuLab printer.

    Args:
        ip: IP address of the printer
        access_code: Access code for authentication

    Returns:
        "chamber" for A1/P1 printers (port 6000)
        "rtsp" for X1/H2/P2 printers (port 322)

    Raises:
        RuntimeError: If neither protocol is detected
    """
    logger.info("Detecting camera type for printer at %s...", ip)

    # Build one SSL context shared by both probes (both verify the same printer.cer)
    ssl_context = create_ssl_context()

    # Probe both ports concurrently
    chamber_result, rtsp_result = await asyncio.gather(
        _probe_chamber_port(ip, access_code, ssl_context),
        _probe_rtsp_port(ip, ssl_context),
    )

    if chamber_result and not rtsp_result:
        logger.info("Detected camera type: Chamber Image (A1/P1 series)")
        return "chamber"
    if rtsp_result and not chamber_result:
        logger.info("Detected camera type: RTSP (X1/H2/P2 series)")
        return "rtsp"
    if chamber_result and rtsp_result:
        # Both responded - prefer chamber as it's more specific
        logger.info("Both protocols responded, using Chamber Image")
        return "chamber"
    raise RuntimeError(
        f"Could not detect camera type for printer at {ip}. "
        "Please ensure:\n"
        "  - The printer is powered on and connected to the network\n"
        "  - LAN Mode is enabled\n"
        "  - Development Mode is enabled\n"
        "  - The access code is correct"
    )
