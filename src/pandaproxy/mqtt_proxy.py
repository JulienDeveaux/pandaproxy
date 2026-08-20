"""MQTT multiplexing proxy for BambuLab printers on port 8883.

Maintains a single MQTT connection to the printer (via aiomqtt) and accepts
multiple client connections, fanning out printer messages to all clients and
forwarding client commands to the printer.

Architecture:
    - Upstream (printer): Single persistent aiomqtt client with auto-reconnect.
      Subscribes to all topics (#) and publishes client commands.
    - Clients: TLS server accepting MQTT connections. Each client's CONNECT,
      SUBSCRIBE, PINGREQ, and DISCONNECT are handled locally by the proxy.
      PUBLISH messages from clients are forwarded to the upstream printer.
      PUBLISH messages from the printer are broadcast to all connected clients.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import logging
import ssl
from typing import TYPE_CHECKING

import aiomqtt

if TYPE_CHECKING:
    from pathlib import Path

from pandaproxy.helper import close_writer, create_ssl_context
from pandaproxy.mqtt_protocol import (
    CONNACK_ACCEPTED,
    CONNACK_NOT_AUTHORIZED,
    PacketType,
    build_connack,
    build_pingresp,
    build_puback,
    build_publish,
    build_suback,
    build_unsuback,
    parse_connect,
    parse_publish,
    parse_subscribe,
    parse_unsubscribe,
    read_packet,
)
from pandaproxy.protocol import MQTT_PORT, PRINTER_CERT_FILENAME
from pandaproxy.state_cache import (
    PrinterStateCache,
    as_ipv4,
    payload_is_full_state,
    payload_reports_ip,
    rewrite_reported_ip,
)

logger = logging.getLogger(__name__)


def topic_matches(topic_filter: str, topic: str) -> bool:
    """Return whether an MQTT topic filter matches a concrete topic name.

    Implements the '+' (single level) and '#' (multi level) wildcards.
    """
    if topic_filter == topic:
        return True

    filter_levels = topic_filter.split("/")
    topic_levels = topic.split("/")

    for i, level in enumerate(filter_levels):
        if level == "#":
            # '#' is only legal as the last level and matches the remainder.
            return i == len(filter_levels) - 1
        if i >= len(topic_levels):
            return False
        if level != "+" and level != topic_levels[i]:
            return False

    return len(filter_levels) == len(topic_levels)


# Keepalive interval for the upstream printer connection (seconds)
UPSTREAM_KEEPALIVE = 60

# How long to wait before reconnecting to the printer after a failure
RECONNECT_DELAY = 5

# Maximum queued packets per client before disconnecting slow clients
CLIENT_QUEUE_SIZE = 200

# Timeout for initial client MQTT CONNECT handshake
CLIENT_CONNECT_TIMEOUT = 10.0

# Timeout for upstream connection establishment
UPSTREAM_CONNECT_TIMEOUT = 10.0

# How long clients wait for upstream to become available
UPSTREAM_WAIT_TIMEOUT = 30.0

# Sent once per upstream connection to prime the state cache; otherwise every
# client sends its own, costing N full state dumps instead of one.
# How long a subscribing client waits for a full dump before giving up and
# letting the client ask for its own.
CACHE_PRIMING_TIMEOUT = 12.0

# Minimum spacing between full-state requests, so simultaneous subscribers
# collapse into one instead of each asking the printer. Deliberately shorter
# than CACHE_PRIMING_TIMEOUT: a QoS 0 request can be lost, and a waiter must
# be able to re-ask within its own wait rather than time out first.
PUSHALL_RETRY_INTERVAL = 4.0

PUSHALL_PAYLOAD = json.dumps(
    {"pushing": {"sequence_id": "0", "command": "pushall"}}
).encode("utf-8")


class MQTTProxy:
    """MQTT multiplexing proxy for BambuLab printers.

    Maintains one upstream MQTT connection to the printer and fans out
    messages to multiple connected clients.
    """

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        serial_number: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",  # noqa: S104  # pandaproxy binds all interfaces by design
        printer_cert_path: Path | str = PRINTER_CERT_FILENAME,
        advertise_ip: str | None = None,
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.serial_number = serial_number
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.printer_cert_path = printer_cert_path
        self.port = MQTT_PORT
        self.report_topic = f"device/{serial_number}/report"
        self.request_topic = f"device/{serial_number}/request"
        # Address advertised in print.net.info[*].ip. Without an explicit
        # value the socket's own address is used, which is the container's
        # private address under Docker bridge networking - unreachable for
        # every LAN client.
        self.advertise_ip = advertise_ip

        # Merged printer state, replayed to each new subscriber
        self._state_cache = PrinterStateCache()
        # Set once the priming pushall reply has been merged. Subscribers wait
        # briefly on it rather than being handed an empty cache.
        self._cache_primed = asyncio.Event()
        # Snapshot replays run detached so they cannot stall a client's loop.
        self._snapshot_tasks: set[asyncio.Task] = set()
        # Collapses simultaneous full-state requests into one.
        self._pushall_pending = False
        self._pushall_timer: asyncio.TimerHandle | None = None

        self._running = False
        self._server: asyncio.Server | None = None

        # Upstream state
        self._upstream_client: aiomqtt.Client | None = None
        self._upstream_connected = asyncio.Event()
        self._upstream_lock = asyncio.Lock()
        self._upstream_task: asyncio.Task | None = None

        # Client tracking: client_id -> asyncio.Queue
        self._clients: dict[str, asyncio.Queue[bytes | None]] = {}
        # client_id -> local address it reached us on, so we can tell it
        # where the "printer" lives and keep it using the proxy.
        self._client_ips: dict[str, str] = {}
        # Needed to actually hang up on a client that cannot keep up: its
        # queue is full by definition at that point, so a sentinel cannot get
        # through it.
        self._client_writers: dict[str, asyncio.StreamWriter] = {}
        self._clients_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start the MQTT proxy server (TLS listener for clients)."""
        logger.info("Starting MQTT proxy on %s:%d", self.bind_address, self.port)
        self._running = True

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=ssl_context,
        )

        logger.info("MQTT proxy started on %s:%d (TLS)", self.bind_address, self.port)

    async def stop(self) -> None:
        """Stop the MQTT proxy.

        Shutdown order matters: stop clients first (so they stop publishing
        to upstream), then disconnect the upstream aiomqtt client. This
        prevents paho-mqtt internal futures from going unhandled.
        """
        logger.info("Stopping MQTT proxy")
        self._running = False

        # 1. Prevent any new publishes to upstream
        self._upstream_client = None

        # 2. Signal all client queues to stop (so recv/send loops exit)
        async with self._clients_lock:
            for queue in self._clients.values():
                with contextlib.suppress(asyncio.QueueFull):
                    queue.put_nowait(None)

        snapshots = list(self._snapshot_tasks)
        for task in snapshots:
            task.cancel()
        if snapshots:
            await asyncio.gather(*snapshots, return_exceptions=True)

        # 3. Close the TLS server (stop accepting new connections)
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # 4. Now cancel the upstream task (exits aiomqtt context cleanly)
        if self._upstream_task:
            self._upstream_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._upstream_task

        # 5. Only now can nothing broadcast any more. Clearing these earlier
        # meant a report arriving mid-shutdown went out unrewritten, naming
        # the printer, and a saturated client could no longer be hung up.
        async with self._clients_lock:
            self._client_ips.clear()
            self._client_writers.clear()

        logger.info("MQTT proxy stopped")

    async def run_upstream_loop(self) -> None:
        """Run the upstream connection loop as a standalone coroutine.

        Called from cli.py as a background task, matching the ChamberImageProxy pattern.
        """
        self._upstream_task = asyncio.current_task()
        await self._upstream_connection_loop()

    # ------------------------------------------------------------------
    # Upstream (printer) connection
    # ------------------------------------------------------------------

    async def _upstream_connection_loop(self) -> None:
        """Maintain a persistent MQTT connection to the printer, reconnecting on failure."""
        printer_ssl = create_ssl_context(self.printer_cert_path)

        while self._running:
            try:
                logger.info(
                    "Connecting to printer MQTT at %s:%d", self.printer_ip, self.port
                )

                async with aiomqtt.Client(
                    hostname=self.printer_ip,
                    port=self.port,
                    username="bblp",
                    password=self.access_code,
                    tls_context=printer_ssl,
                    keepalive=UPSTREAM_KEEPALIVE,
                    timeout=UPSTREAM_CONNECT_TIMEOUT,
                    identifier=f"pandaproxy-{self.serial_number}",
                ) as client:
                    self._upstream_client = client
                    await client.subscribe(self.report_topic)
                    self._upstream_connected.set()
                    logger.info(
                        "Connected to printer MQTT broker (subscribed to %s)",
                        self.report_topic,
                    )

                    # Deltas alone never let a late subscriber build a full
                    # picture, so prime the cache with one full dump. Routed
                    # through _request_pushall so a subscriber arriving before
                    # the reply does not ask for a second one.
                    await self._request_pushall()

                    async for message in client.messages:
                        logger.debug(
                            "Printer -> topic=%s qos=%d len=%d",
                            message.topic,
                            message.qos,
                            len(
                                message.payload
                                if isinstance(message.payload, bytes)
                                else b""
                            ),
                        )
                        payload = (
                            message.payload
                            if isinstance(message.payload, bytes)
                            else b""
                        )
                        topic = str(message.topic)
                        if topic == self.report_topic:
                            merged = self._state_cache.update(payload)
                            # Both conditions: a payload can look like a full
                            # dump and still be rejected (oversized, or nothing
                            # but an ack), and priming on it would relabel a
                            # partial cache as complete.
                            if merged and payload_is_full_state(payload):
                                self._cache_primed.set()
                        await self._broadcast_report(topic, payload)

            except aiomqtt.MqttError as e:
                logger.warning("Upstream MQTT connection error: %s", e)
            except asyncio.CancelledError:
                logger.debug("Upstream connection loop cancelled")
                return
            except Exception as e:
                logger.error("Unexpected upstream error: %s", e)
            finally:
                self._upstream_connected.clear()
                self._upstream_client = None
                # A snapshot that stopped being refreshed would hand a new
                # client state frozen at disconnect time.
                self._state_cache.clear()
                self._cache_primed.clear()
                self._clear_pushall_pending()

            if self._running:
                logger.info("Reconnecting to printer in %d seconds...", RECONNECT_DELAY)
                await asyncio.sleep(RECONNECT_DELAY)

    async def _forward_to_upstream(self, topic: str, payload: bytes, qos: int) -> None:
        """Forward a client PUBLISH to the upstream printer connection."""
        if not self._running:
            return
        async with self._upstream_lock:
            client = self._upstream_client
            if client:
                try:
                    await client.publish(topic, payload, qos=qos)
                except aiomqtt.MqttError as e:
                    logger.warning("Failed to forward to upstream: %s", e)
            else:
                logger.warning(
                    "Upstream not connected, dropping client publish to %s", topic
                )

    # ------------------------------------------------------------------
    # Client broadcast
    # ------------------------------------------------------------------

    async def _broadcast_report(self, topic: str, payload: bytes) -> None:
        """Relay a printer message to every client.

        Reports carrying the printer's own address are rebuilt per client,
        since each may reach the proxy on a different one. That is rare - only
        full dumps mention the network - so the common path shares one packet.
        """
        if not payload_reports_ip(payload):
            await self._broadcast_to_clients(build_publish(topic, payload))
            return

        try:
            state = json.loads(payload)
        except json.JSONDecodeError, UnicodeDecodeError:
            await self._broadcast_to_clients(build_publish(topic, payload))
            return

        if not isinstance(state, dict):
            # Rewriting expects an object; anything else is relayed as-is
            # rather than raising and taking the upstream connection down.
            await self._broadcast_to_clients(build_publish(topic, payload))
            return

        async with self._clients_lock:
            targets = list(self._clients.items())

        for client_id, queue in targets:
            local_ip = self._client_ips.get(client_id)
            if local_ip:
                personalised = copy.deepcopy(state)
                rewrite_reported_ip(personalised, local_ip)
                data = json.dumps(personalised, separators=(",", ":")).encode()
            else:
                data = payload
            await self._deliver(client_id, queue, build_publish(topic, data))

    async def _broadcast_to_clients(self, packet: bytes) -> None:
        """Put a packet into every connected client's queue."""
        async with self._clients_lock:
            targets = list(self._clients.items())
        for client_id, queue in targets:
            await self._deliver(client_id, queue, packet)

    async def _deliver(
        self, client_id: str, queue: asyncio.Queue[bytes | None], packet: bytes
    ) -> None:
        """Queue one packet for one client, dropping it if it cannot keep up."""
        try:
            queue.put_nowait(packet)
        except asyncio.QueueFull:
            logger.warning("Client %s cannot keep up, disconnecting it", client_id)
            async with self._clients_lock:
                self._clients.pop(client_id, None)
                self._client_ips.pop(client_id, None)
                writer = self._client_writers.pop(client_id, None)
            # Closing the socket is what actually ends both loops: the queue is
            # full, so no sentinel could ever reach the send loop.
            if writer is not None:
                await close_writer(writer)

    async def _request_pushall(self) -> None:
        """Ask the printer for a full state dump, at most one at a time.

        Several clients reconnecting together would otherwise each ask, which
        is the load this cache exists to remove.
        """
        if self._pushall_pending:
            return

        # Set before the await, or two subscribers both pass the check and the
        # printer produces the N dumps this cache exists to avoid.
        self._pushall_pending = True
        if not await self._publish_pushall():
            # Nothing went out, so nothing to wait for: stay re-askable rather
            # than muzzling retries for the next interval.
            self._pushall_pending = False
            return

        # A QoS 0 request can simply be lost, so it must become re-askable
        # even if no reply ever arrives. The handle is kept so a reconnect can
        # drop it instead of letting it clear a fresh flag.
        self._pushall_timer = asyncio.get_running_loop().call_later(
            PUSHALL_RETRY_INTERVAL, self._clear_pushall_pending
        )

    def _clear_pushall_pending(self) -> None:
        """Make a full-state request askable again, dropping any timer."""
        self._pushall_pending = False
        # Cancel, do not merely forget: a surviving handle would later clear a
        # flag armed by a fresh request and let every subscriber ask again.
        if self._pushall_timer is not None:
            self._pushall_timer.cancel()
            self._pushall_timer = None

    async def _publish_pushall(self) -> bool:
        """Publish one pushall request. False if nothing went out."""
        async with self._upstream_lock:
            client = self._upstream_client
            if client is None:
                return False
            try:
                await client.publish(self.request_topic, PUSHALL_PAYLOAD, qos=0)
            except aiomqtt.MqttError as e:
                logger.warning("Could not request a full state dump: %s", e)
                return False
        return True

    async def _send_state_snapshot(self, client_id: str) -> None:
        """Replay the merged printer state to a client that just subscribed,
        so it need not ask the printer for its own ``pushall``."""
        if not self._cache_primed.is_set():
            # The priming pushall is usually still in flight when a client
            # subscribes right after startup. It is published at QoS 0 and can
            # simply be lost, so re-ask across the wait instead of asking once
            # and hoping - a single attempt made this retry path dead code.
            deadline = asyncio.get_running_loop().time() + CACHE_PRIMING_TIMEOUT
            while not self._cache_primed.is_set():
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                await self._request_pushall()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._cache_primed.wait(),
                        timeout=min(PUSHALL_RETRY_INTERVAL, remaining),
                    )

        if not self._cache_primed.is_set():
            # Only a full dump can be replayed as one. Saying nothing lets the
            # client request its own; handing it a delta dressed up as full
            # state would leave it silently missing most fields.
            logger.info(
                "No full state yet, %s will have to ask the printer itself",
                client_id,
            )
            return

        # Resolve the queue *before* serialising: an await between building
        # the snapshot and queueing it lets a newer delta jump ahead, and the
        # client would then apply the older full document over it and regress.
        async with self._clients_lock:
            queue = self._clients.get(client_id)
            advertised = self._client_ips.get(client_id)
        if queue is None:
            return

        snapshots = self._state_cache.snapshots(advertise_ip=advertised)
        if not snapshots:
            logger.debug(
                "No cached state yet, client %s will wait for the next report",
                client_id,
            )
            return

        for payload in snapshots:
            await self._deliver(
                client_id, queue, build_publish(self.report_topic, payload)
            )
        logger.info(
            "Replayed cached state to %s (%d report(s), %d bytes, %d merged)",
            client_id,
            len(snapshots),
            sum(len(p) for p in snapshots),
            self._state_cache.update_count,
        )

    # ------------------------------------------------------------------
    # Client connection handling
    # ------------------------------------------------------------------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new MQTT client connection."""
        peer = writer.get_extra_info("peername")
        logger.info("New MQTT connection from %s", peer)
        client_id = str(peer)
        queue: asyncio.Queue[bytes | None] | None = None

        try:
            # --- MQTT CONNECT handshake ---
            try:
                pkt = await asyncio.wait_for(
                    read_packet(reader), timeout=CLIENT_CONNECT_TIMEOUT
                )
            except TimeoutError:
                logger.warning("Client %s CONNECT timeout", peer)
                return
            except asyncio.IncompleteReadError:
                logger.debug("Client %s disconnected during CONNECT", peer)
                return

            if pkt.packet_type != PacketType.CONNECT:
                logger.warning(
                    "Expected CONNECT from %s, got type %d", peer, pkt.packet_type
                )
                return

            connect_info = parse_connect(pkt.payload)
            if connect_info.password != self.access_code:
                writer.write(build_connack(return_code=CONNACK_NOT_AUTHORIZED))
                await writer.drain()
                logger.warning(
                    "Auth failed for %s (client_id=%s)", peer, connect_info.client_id
                )
                return

            writer.write(build_connack(return_code=CONNACK_ACCEPTED))
            await writer.drain()
            logger.info(
                "Client %s authenticated (client_id=%s)", peer, connect_info.client_id
            )

            # --- Wait for upstream to be ready ---
            if not self._upstream_connected.is_set():
                logger.info("Waiting for upstream connection for %s...", peer)
                try:
                    await asyncio.wait_for(
                        self._upstream_connected.wait(), timeout=UPSTREAM_WAIT_TIMEOUT
                    )
                except TimeoutError:
                    logger.warning("Upstream not available for %s, disconnecting", peer)
                    return

            # --- Register client queue ---
            queue = asyncio.Queue(maxsize=CLIENT_QUEUE_SIZE)
            sockname = writer.get_extra_info("sockname")
            raw_address = self.advertise_ip or (sockname[0] if sockname else None)
            # Unwrap ::ffff:a.b.c.d: a dual-stack listener reports ordinary
            # IPv4 peers that way, and refusing them dropped every client.
            advertised = as_ipv4(raw_address) if raw_address else None
            if not advertised:
                # The printer reports its address as an IPv4 uint32, so a
                # non-IPv4 value cannot be rewritten and the report would go
                # out naming the printer - the bypass this exists to prevent.
                # Refusing is the safe failure.
                logger.error(
                    "No IPv4 address to advertise to %s (got %r); set --advertise-ip",
                    peer,
                    raw_address,
                )
                return
            async with self._clients_lock:
                self._clients[client_id] = queue
                self._client_writers[client_id] = writer
                self._client_ips[client_id] = advertised

            # --- Run bidirectional forwarding ---
            keepalive = connect_info.keepalive
            send_task = asyncio.create_task(
                self._client_send_loop(client_id, queue, writer)
            )
            recv_task = asyncio.create_task(
                self._client_recv_loop(client_id, reader, writer, keepalive)
            )

            _done, pending = await asyncio.wait(
                [send_task, recv_task], return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

        except ssl.SSLError as e:
            if "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(e):
                logger.debug("Client %s TLS close: %s", peer, e)
            else:
                logger.error("Client %s SSL error: %s", peer, e)
        except Exception as e:
            logger.error("Error handling client %s: %s", peer, e)
        finally:
            if queue is not None:
                async with self._clients_lock:
                    self._clients.pop(client_id, None)
                    self._client_ips.pop(client_id, None)
                    self._client_writers.pop(client_id, None)
            await close_writer(writer)
            logger.info("Connection from %s closed", peer)

    @staticmethod
    async def _client_send_loop(
        client_id: str,
        queue: asyncio.Queue[bytes | None],
        writer: asyncio.StreamWriter,
    ) -> None:
        """Drain the client's queue and write packets to its socket."""
        try:
            while True:
                packet = await queue.get()
                if packet is None:
                    break
                writer.write(packet)
                await writer.drain()
        except ConnectionResetError, BrokenPipeError:
            logger.debug("Client %s connection reset during send", client_id)
        except ssl.SSLError as e:
            logger.debug("Client %s SSL error during send: %s", client_id, e)

    async def _client_recv_loop(
        self,
        client_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        keepalive: int,
    ) -> None:
        """Read MQTT packets from a client, handling them locally or forwarding."""
        # MQTT spec: disconnect if no packet within 1.5x keepalive
        timeout = keepalive * 1.5 if keepalive > 0 else 120.0

        try:
            while self._running:
                try:
                    pkt = await asyncio.wait_for(read_packet(reader), timeout=timeout)
                except TimeoutError:
                    logger.info("Client %s keepalive timeout", client_id)
                    return

                match pkt.packet_type:
                    case PacketType.PUBLISH:
                        info = parse_publish(pkt.flags, pkt.payload)
                        # ACK QoS 1 locally, then forward
                        if info.qos == 1 and info.packet_id is not None:
                            writer.write(build_puback(info.packet_id))
                            await writer.drain()
                        await self._forward_to_upstream(info.topic, info.payload, qos=0)

                    case PacketType.SUBSCRIBE:
                        pkt_id, topics = parse_subscribe(pkt.payload)
                        # Grant QoS 0 for everything (upstream handles subscriptions)
                        writer.write(build_suback(pkt_id, [0] * len(topics)))
                        await writer.drain()
                        logger.debug("Client %s subscribed to %s", client_id, topics)

                        if any(
                            topic_matches(f, self.report_topic) for f, _qos in topics
                        ):
                            # As a task: this can wait seconds for the priming
                            # dump, and PINGREQ must keep being answered.
                            snapshot_task = asyncio.create_task(
                                self._send_state_snapshot(client_id)
                            )
                            self._snapshot_tasks.add(snapshot_task)
                            snapshot_task.add_done_callback(
                                self._snapshot_tasks.discard
                            )

                    case PacketType.UNSUBSCRIBE:
                        pkt_id, topics = parse_unsubscribe(pkt.payload)
                        writer.write(build_unsuback(pkt_id))
                        await writer.drain()
                        logger.debug(
                            "Client %s unsubscribed from %s", client_id, topics
                        )

                    case PacketType.PINGREQ:
                        writer.write(build_pingresp())
                        await writer.drain()

                    case PacketType.PUBACK:
                        pass  # We ACK upstream ourselves; ignore client PUBACKs

                    case PacketType.DISCONNECT:
                        logger.debug("Client %s sent DISCONNECT", client_id)
                        return

                    case _:
                        logger.debug(
                            "Client %s sent unhandled packet type %d",
                            client_id,
                            pkt.packet_type,
                        )

        except asyncio.IncompleteReadError:
            logger.debug("Client %s disconnected", client_id)
        except ssl.SSLError as e:
            logger.debug("Client %s SSL error during recv: %s", client_id, e)
