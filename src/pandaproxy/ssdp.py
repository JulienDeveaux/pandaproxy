"""SSDP announcements, so slicers can find the proxy at all.

BambuStudio populates its LAN device list purely from SSDP announcements
received on UDP 2021, then dials the address the announcement names. Typing an
address by hand is not enough: a proxy stays invisible, and selecting the
printer fails instantly without so much as a socket being opened.

The announcement is a UDP datagram carrying an ``HTTP/1.1 200 OK`` response -
not a ``NOTIFY`` - and must be repeated continuously; BambuStudio drops the
device when they stop.

Header set verified against BambuStudio 02.08.02.60 and a P1S. The plugin's
parser recognises eight ``Dev*.bambu.com`` headers and widely-copied examples
send only five, which is why they no longer work.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from email.utils import formatdate
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

SSDP_PORT = 2021
BROADCAST = "255.255.255.255"

# BambuStudio drops a device whose announcements stop, so this is a heartbeat
# rather than a one-off. It also has to outpace the printer's own
# announcements, which carry the same USN and compete for the same list entry.
DEFAULT_INTERVAL = 2.0

# Model code, not a marketing name: BambuStudio maps it to a printer profile.
# C12 is the P1S - its own printers/C12.json says "Bambu Lab P1S". Look up
# another model the same way rather than guessing.
DEFAULT_DEV_MODEL = "C12"

DEFAULT_DEV_NAME = "PandaProxy"
DEFAULT_DEV_SIGNAL = "-44"

# How long to wait for the firmware version before announcing without it.
# The version makes for a more faithful announcement, but discovery works
# without it - measured against BambuStudio 02.08.02.60 - so a missing version
# must never be allowed to silence the heartbeat for good.
DEFAULT_VERSION_GRACE = 15.0


def build_announcement(
    advertise_ip: str,
    serial: str,
    *,
    dev_model: str = DEFAULT_DEV_MODEL,
    dev_name: str = DEFAULT_DEV_NAME,
    dev_version: str = "",
    dev_signal: str = DEFAULT_DEV_SIGNAL,
) -> bytes:
    """Build the announcement BambuStudio accepts.

    ``DevInf`` is deliberately empty: putting an address in it makes
    BambuStudio reject the device outright. ``DevVersion`` conversely must not
    be empty - between them they are why a proxy appears in the list and then
    fails the moment it is selected.
    """
    lines = [
        "HTTP/1.1 200 OK",
        "Server: Buildroot/2018.02-rc3 UPnP/1.0 ssdpd/1.8",
        f"Date: {formatdate(usegmt=True)}",
        # A bare address, not a URL.
        f"Location: {advertise_ip}",
        "ST: urn:bambulab-com:device:3dprinter:1",
        "EXT:",
        f"USN: {serial}",
        "Cache-Control: max-age=1800",
        f"DevModel.bambu.com: {dev_model}",
        f"DevName.bambu.com: {dev_name}",
        f"DevSignal.bambu.com: {dev_signal}",
        "DevConnect.bambu.com: lan",
        "DevBind.bambu.com: free",
        "Devseclink.bambu.com: 0",
        "DevInf.bambu.com:",
        f"DevVersion.bambu.com: {dev_version}",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


class SsdpAnnouncer:
    """Repeatedly announces the proxy as though it were the printer."""

    def __init__(
        self,
        advertise_ip: str,
        serial: str,
        targets: list[str] | None = None,
        interval: float = DEFAULT_INTERVAL,
        dev_model: str = DEFAULT_DEV_MODEL,
        dev_name: str = DEFAULT_DEV_NAME,
        dev_version: str = "",
        version_provider: Callable[[], str | None] | None = None,
        version_grace: float = DEFAULT_VERSION_GRACE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.advertise_ip = advertise_ip
        self.serial = serial
        # Explicit targets are usually required: a container on a Docker
        # bridge cannot broadcast onto the LAN, but it can unicast through
        # NAT to whichever machines run a slicer.
        self.targets = targets or [BROADCAST]
        self.interval = interval
        self.dev_model = dev_model
        self.dev_name = dev_name
        self.dev_version = dev_version
        # BambuStudio rejects an announcement with an empty DevVersion, and the
        # printer reports its own version over MQTT - so prefer asking rather
        # than making the user configure it.
        self.version_provider = version_provider
        self.version_grace = version_grace
        self._clock = clock
        self._started_at: float | None = None

        self._sock: socket.socket | None = None
        self._running = False
        self._sent = 0
        self._warned_no_version = False

    @property
    def sent(self) -> int:
        """Announcements sent so far."""
        return self._sent

    def start(self) -> None:
        """Open the sending socket."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._running = True
        self._started_at = self._clock()
        logger.info(
            "SSDP announcing %s as %s to %s every %.1fs",
            self.advertise_ip,
            self.serial,
            ", ".join(self.targets),
            self.interval,
        )

    def stop(self) -> None:
        """Close the sending socket."""
        self._running = False
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        logger.info("SSDP announcer stopped after %d announcements", self._sent)

    def resolve_version(self) -> str:
        """The version to announce: configured value, else whatever MQTT knows."""
        if self.dev_version:
            return self.dev_version
        if self.version_provider is not None:
            try:
                return self.version_provider() or ""
            except Exception as e:
                # Never let a reporting problem stop the heartbeat.
                logger.debug("Version provider failed: %s", e)
        return ""

    def _within_grace(self) -> bool:
        """Whether the wait for a firmware version may still continue."""
        if self._started_at is None or self.version_grace <= 0:
            return False
        return self._clock() - self._started_at < self.version_grace

    def announce_once(self) -> int:
        """Send one announcement to every target. Returns how many went out."""
        if self._sock is None:
            return 0

        version = self.resolve_version()
        if not version and self._within_grace():
            # Worth a brief wait: the printer reports its version over MQTT
            # shortly after the proxy connects, and announcing it makes for a
            # truer impersonation. But only a brief one - holding out for a
            # version that never arrives would leave the device undiscoverable,
            # which is far worse than announcing without it.
            if not self._warned_no_version:
                self._warned_no_version = True
                logger.info(
                    "Waiting up to %.0fs for the firmware version before "
                    "announcing; set SSDP_DEV_VERSION to skip the wait",
                    self.version_grace,
                )
            return 0

        if self._warned_no_version:
            self._warned_no_version = False
            if version:
                logger.info("Firmware version %s known, announcing", version)
            else:
                logger.info(
                    "No firmware version after %.0fs; announcing without one",
                    self.version_grace,
                )

        payload = build_announcement(
            self.advertise_ip,
            self.serial,
            dev_model=self.dev_model,
            dev_name=self.dev_name,
            dev_version=version,
        )
        delivered = 0
        for target in self.targets:
            try:
                self._sock.sendto(payload, (target, SSDP_PORT))
                delivered += 1
            except OSError as e:
                # One unreachable target must not stop the others, and a
                # transient failure is not worth ending the heartbeat over.
                logger.debug("SSDP send to %s failed: %s", target, e)
        self._sent += delivered
        return delivered

    async def run(self) -> None:
        """Announce until cancelled."""
        while self._running:
            self.announce_once()
            await asyncio.sleep(self.interval)
