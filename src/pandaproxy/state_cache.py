"""Merged printer-state cache for the MQTT proxy.

BambuLab printers send full state only in reply to a ``pushall``, then emit
incremental deltas. A late client would see nothing but fragments and have to
request its own dump - so N clients mean N full dumps, the very load the proxy
exists to remove. Merging the deltas here lets the proxy replay a full report
to each new subscriber while only ever asking the printer once.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import logging
import socket
from typing import Any

logger = logging.getLogger(__name__)

# A P1S full dump is a few KB; 1 MB is a generous ceiling past which a payload
# is not state. Oversized payloads are still relayed, just not merged.
MAX_CACHEABLE_PAYLOAD = 1_000_000


def deep_merge(base: dict[str, Any], delta: dict[str, Any]) -> None:
    """Recursively merge ``delta`` into ``base`` in place.

    Lists replace wholesale rather than merging element-wise: the printer
    resends whole arrays (e.g. ``ams.tray``), so a per-index merge would
    resurrect entries it just removed.
    """
    for key, value in delta.items():
        existing = base.get(key)
        if isinstance(value, dict) and isinstance(existing, dict):
            deep_merge(existing, value)
        else:
            base[key] = value


def as_ipv4(address: str) -> str | None:
    """Return ``address`` as a plain dotted quad, or None if it is not IPv4.

    Unwraps IPv4-mapped IPv6 literals: a dual-stack listener reports an
    ordinary IPv4 peer as ``::ffff:192.168.1.10``, which is usable once
    unwrapped and must not be mistaken for "no IPv4 address".
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    mapped = parsed.ipv4_mapped
    return str(mapped) if mapped is not None else None


def is_ipv4(address: str) -> bool:
    """Whether ``address`` is a plain dotted-quad IPv4 literal.

    Stricter than ``inet_aton``, which accepts "192.168.1" and silently
    expands it to a different address.
    """
    try:
        ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError, ValueError:
        return False
    return True


def encode_ipv4(address: str) -> int:
    """Encode a dotted-quad address as the printer reports it: little-endian
    uint32, so 192.168.1.18 becomes 302098624.

    Raises ValueError for anything that is not an IPv4 literal.
    """
    if not is_ipv4(address):
        raise ValueError(f"not an IPv4 address: {address!r}")
    return int.from_bytes(socket.inet_aton(address), "little")


def decode_ipv4(value: int) -> str:
    """Decode the printer's little-endian uint32 address form."""
    return socket.inet_ntoa(value.to_bytes(4, "little"))


def rewrite_reported_ip(state: dict[str, Any], address: str) -> int:
    """Point ``net.info[*].ip`` at ``address``, returning how many changed.

    Slicers read this field to pick an upload target, so leaving the printer's
    real address in place would let a client bypass the proxy entirely.
    Mutates ``state`` in place.
    """
    section = state.get("print")
    if not isinstance(section, dict):
        return 0

    net = section.get("net")
    if not isinstance(net, dict):
        return 0

    entries = net.get("info")
    if not isinstance(entries, list):
        return 0

    try:
        encoded = encode_ipv4(address)
    except ValueError:
        # Never worth taking the printer connection down over: relay the
        # report untouched and log it instead. The CLI already refuses a bad
        # value at startup, so reaching here means it came from elsewhere.
        logger.warning("Cannot advertise %r: not an IPv4 address", address)
        return 0
    changed = 0
    for entry in entries:
        if isinstance(entry, dict) and "ip" in entry and entry["ip"] != encoded:
            entry["ip"] = encoded
            changed += 1
    return changed


def payload_reports_ip(payload: bytes) -> bool:
    """Cheap pre-check: could this payload carry a reported address?

    Most reports are deltas that never mention the network, so this avoids
    per-client JSON work in the common case.
    """
    return b'"net"' in payload


# Fields that describe a message rather than the printer: an ack is a section
# made of nothing else.
_METADATA_FIELDS = frozenset(
    {"command", "result", "reason", "sequence_id", "msg", "errno", "code", "param"}
)


def payload_is_full_state(payload: bytes) -> bool:
    """Whether a report payload is a full dump rather than a delta.

    The printer marks a full dump ``msg: 0`` and a delta ``msg: 1``. Only a
    full dump can prime the cache: priming on a delta would let the proxy
    hand a new client a partial document relabelled as complete, which is
    worse than handing it nothing.
    """
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError, UnicodeDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False
    return any(
        isinstance(section, dict) and section.get("msg") == 0
        for section in parsed.values()
    )


def _is_command_ack(section: object) -> bool:
    """Whether a report section is only a reply to a command.

    Acks travel on the same topic and inside the same ``print`` object as real
    state, so merging one replays another client's command outcome to everyone
    who subscribes later. A reply that also carries state - ``get_version``
    answers with a ``module`` array - is kept: clients need it and would
    otherwise have to ask for it themselves.
    """
    if not isinstance(section, dict) or "result" not in section:
        return False
    return not (set(section) - _METADATA_FIELDS)


class PrinterStateCache:
    """Accumulates printer report deltas into a single replayable document.

    Schema-agnostic: it merges whatever top-level sections the printer sends,
    so new firmware fields keep working.
    """

    def __init__(self) -> None:
        self._state: dict[str, Any] = {}
        self._updates = 0

    @property
    def has_state(self) -> bool:
        """Whether at least one report has been merged."""
        return bool(self._state)

    @property
    def update_count(self) -> int:
        """Number of reports merged so far (useful for diagnostics)."""
        return self._updates

    def update(self, payload: bytes) -> bool:
        """Merge a printer report payload into the cached state.

        False means ignored (non-JSON, not an object, or oversized); the
        caller still broadcasts it, so this is never fatal.
        """
        if not payload or len(payload) > MAX_CACHEABLE_PAYLOAD:
            return False

        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError, UnicodeDecodeError:
            logger.debug("Report payload is not valid JSON, not cached")
            return False

        if not isinstance(parsed, dict):
            logger.debug("Report payload is not a JSON object, not cached")
            return False

        state = {
            name: section
            for name, section in parsed.items()
            if not _is_command_ack(section)
        }
        if not state:
            return False

        deep_merge(self._state, state)
        self._updates += 1
        return True

    def snapshots(self, advertise_ip: str | None = None) -> list[bytes]:
        """Serialise the merged state as one payload per top-level section.

        The printer sends one section per message, and clients commonly
        dispatch on the top-level key with an if/elif chain - so bundling
        several sections into one report would have them ingest the first and
        drop the rest, leaving the replay less complete than a real pushall.
        """
        if not self._state:
            return []

        payloads: list[bytes] = []
        for name in self._state:
            single = self.snapshot(advertise_ip=advertise_ip, section=name)
            if single is not None:
                payloads.append(single)
        return payloads

    def snapshot(
        self, advertise_ip: str | None = None, section: str | None = None
    ) -> bytes | None:
        """Serialise the merged state as a report payload, or None if empty.

        The ``sequence_id`` is stripped: it belongs to whichever delta
        happened to carry it last, and replaying a stale one to a new client
        can make it think one of its own commands was acknowledged.

        If ``advertise_ip`` is given, the reported network address is
        rewritten to it so clients keep talking to the proxy. ``section``
        limits the payload to one top-level key.
        """
        if not self._state:
            return None

        if section is not None:
            if section not in self._state:
                return None
            state = {section: copy.deepcopy(self._state[section])}
        else:
            state = copy.deepcopy(self._state)
        for body in state.values():
            if not isinstance(body, dict):
                continue
            # These belong to whichever message carried them last; a new
            # client must not read them as answers to its own commands.
            for field in ("sequence_id", "result", "reason"):
                body.pop(field, None)
            # What we hand over is a full document, whatever the last delta
            # that touched this field claimed. Clients gate full-state
            # ingestion on msg == 0.
            if "msg" in body:
                body["msg"] = 0

        if advertise_ip:
            rewrite_reported_ip(state, advertise_ip)

        return json.dumps(state, separators=(",", ":")).encode("utf-8")

    def clear(self) -> None:
        """Drop the cached state.

        Called when upstream drops: a snapshot that stopped being refreshed
        is worse than none.
        """
        self._state.clear()
        self._updates = 0
