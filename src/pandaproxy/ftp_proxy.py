"""FTPS proxy for BambuLab printer file transfers (implicit TLS, port 990).

Terminating TLS on both sides and speaking FTP - rather than relaying bytes -
buys two things:

  * **Passive mode.** The printer answers ``PASV`` with its own address, which
    a passthrough cannot rewrite because the control channel is encrypted; the
    client would connect to the printer and bypass the proxy entirely.

  * **Queueing.** The printer accepts very few concurrent FTP sessions. The
    proxy answers the login itself and queues until a slot frees up, so a
    client waits inside its first command instead of failing to connect.

The data channel is relayed raw: BambuLab printers do not require it to resume
the control channel's TLS session, so the client negotiates end to end.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import posixpath
import socket
import ssl
import struct
import time
from typing import TYPE_CHECKING

from pandaproxy.ftp_queue import (
    PRIORITY_NORMAL,
    PRIORITY_UPLOAD,
    DataPortPool,
    SessionQueue,
)
from pandaproxy.helper import close_writer, create_ssl_context
from pandaproxy.protocol import FTP_PORT
from pandaproxy.state_cache import as_ipv4

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Passive-mode data ports. Fixed rather than ephemeral so the range can be
# published from a container.
#
# Sized for concurrent *clients*, not concurrent transfers: a port is reserved
# when PASV is answered, which is before the queue wait, so every client
# waiting its turn holds one. Exhausting the pool answers 425 - the generic
# mid-upload failure this proxy exists to remove. Docker spawns a
# userland-proxy process per published port, so it is not free either.
FTP_DATA_PORT_START = 2000
FTP_DATA_PORT_END = 2019

# One is the safe default: the point is to stop clients competing for the
# printer's few slots.
DEFAULT_MAX_CONCURRENT = 1

# Drop an idle upstream session after this long, freeing the slot. The client
# keeps its connection and reattaches on its next command.
UPSTREAM_IDLE_TIMEOUT = 30.0

# How often a queued session checks that its client is still there.
CLIENT_LIVENESS_CHECK = 1.0

# Give up on a client that connects and then says nothing at all.
CLIENT_IDLE_TIMEOUT = 300.0

# How long a passive data port waits for the client to connect to it.
DATA_ACCEPT_TIMEOUT = 30.0

# How long a relay waits for the printer's data endpoint, i.e. for the client
# to follow its passive request with an actual transfer command.
DATA_ENDPOINT_TIMEOUT = 120.0

# No bytes in either direction for this long means the transfer is wedged, not
# slow. Without it a vanished client holds the single printer slot for the
# whole completion timeout.
DATA_STALL_TIMEOUT = 120.0

# How often the stall watchdog looks.
DATA_STALL_CHECK = 5.0

# Once the data channel is over the 226 is imminent or never coming. Two
# figures because the cases differ: nothing transferred means the channel was
# never used and the reply will not come, while a printer that received a
# large file may still be committing it to SD.
DATA_COMMIT_GRACE = 300.0
DATA_POST_TRANSFER_GRACE = 30.0

# Grace for the idle direction of a transfer to notice the other side closed.
DATA_DRAIN_GRACE = 5.0

# Upper bound on data-relay teardown, so a wedged socket cannot hold up the
# queue.
DATA_TEARDOWN_TIMEOUT = 10.0

UPSTREAM_CONNECT_TIMEOUT = 15.0
UPSTREAM_REPLY_TIMEOUT = 120.0

# The completion reply (226) only lands once the data transfer is over, so it
# cannot share the per-command timeout: a large 3MF on a slow link would trip
# it and the proxy would abort a perfectly healthy upload.
TRANSFER_COMPLETION_TIMEOUT = 3600.0

MAX_CONTROL_LINE = 4096
DATA_CHUNK = 65536

# Commands whose effect must survive an upstream reconnect, and are therefore
# recorded and replayed when a new printer session is opened.
STATEFUL_COMMANDS = {"TYPE", "PBSZ", "PROT", "CWD", "CDUP"}

# Answerable before login: they need neither credentials nor the printer.
_PRE_AUTH_COMMANDS = {"USER", "PASS", "AUTH", "FEAT", "SYST", "NOOP", "OPTS"}

# Commands that create or replace a file: these jump the queue.
UPLOAD_COMMANDS = {"STOR", "STOU", "APPE"}

# Commands that open a data connection, and so need a passive port first.
_TRANSFER_COMMANDS = {"LIST", "NLST", "MLSD", "RETR", "STOR", "STOU", "APPE"}


def parse_pasv_reply(reply: str) -> tuple[str, int] | None:
    """Extract (host, port) from a ``227`` reply, or None if unparseable."""
    start = reply.find("(")
    end = reply.find(")", start + 1)
    if start == -1 or end == -1:
        return None

    parts = reply[start + 1 : end].split(",")
    if len(parts) != 6:
        return None

    try:
        numbers = [int(p.strip()) for p in parts]
    except ValueError:
        return None

    if any(n < 0 or n > 255 for n in numbers):
        return None

    host = ".".join(str(n) for n in numbers[:4])
    port = numbers[4] * 256 + numbers[5]
    if port == 0:
        return None
    return host, port


def format_pasv_reply(host: str, port: int) -> str:
    """Build a ``227`` reply advertising ``host:port``."""
    octets = host.split(".")
    return (
        f"227 Entering Passive Mode ({','.join(octets)},{port // 256},{port % 256})\r\n"
    )


def parse_epsv_reply(reply: str) -> int | None:
    """Extract the port from a ``229`` reply, or None if unparseable."""
    start = reply.find("(")
    end = reply.find(")", start + 1)
    if start == -1 or end == -1:
        return None

    body = reply[start + 1 : end]
    if len(body) < 4:
        return None

    # Format is (<d><d><d>port<d>) where <d> is any single delimiter char.
    delimiter = body[0]
    fields = body.split(delimiter)
    if len(fields) < 4:
        return None

    try:
        port = int(fields[3])
    except ValueError:
        return None
    # A port outside the valid range reaches open_connection as an
    # OverflowError, which is not an OSError and escapes the relay's handler.
    return port if 1 <= port <= 65535 else None


def format_epsv_reply(port: int) -> str:
    """Build a ``229`` reply advertising ``port``."""
    return f"229 Entering Extended Passive Mode (|||{port}|)\r\n"


class FTPProxy:
    """Queueing FTPS proxy that multiplexes clients onto one printer session."""

    def __init__(
        self,
        printer_ip: str,
        access_code: str,
        cert_path: Path,
        key_path: Path,
        bind_address: str = "0.0.0.0",  # noqa: S104  # pandaproxy binds all interfaces by design
        printer_cert_path: Path | str = "printer.cer",
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        data_port_start: int = FTP_DATA_PORT_START,
        data_port_end: int = FTP_DATA_PORT_END,
        port: int = FTP_PORT,
        printer_port: int = FTP_PORT,
        advertise_ip: str | None = None,
    ) -> None:
        self.printer_ip = printer_ip
        self.access_code = access_code
        self.cert_path = cert_path
        self.key_path = key_path
        self.bind_address = bind_address
        self.printer_cert_path = printer_cert_path
        self.port = port
        self.printer_port = printer_port
        # Address to put in PASV replies. Falls back to the address the client
        # connected to, which is right for host/macvlan but wrong under Docker
        # bridge networking: there the socket sees the container's private
        # address, which no LAN client can reach.
        self.advertise_ip = advertise_ip

        self.queue = SessionQueue(max_concurrent=max_concurrent)
        self.data_ports = DataPortPool(data_port_start, data_port_end)

        self._server: asyncio.Server | None = None
        self._running = False
        self._sessions: set[asyncio.Task] = set()

    @property
    def running(self) -> bool:
        """Whether the proxy is accepting and serving sessions."""
        return self._running

    async def start(self) -> None:
        """Start the FTPS control listener."""
        if self._running:
            return

        if not self.cert_path.exists() or not self.key_path.exists():
            raise FileNotFoundError(
                f"TLS certificates not found at {self.cert_path} or {self.key_path}. "
                "Please ensure the CLI entry point has generated them."
            )

        self._running = True
        server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ssl.load_cert_chain(self.cert_path, self.key_path)

        self._server = await asyncio.start_server(
            self._handle_client,
            self.bind_address,
            self.port,
            ssl=server_ssl,
            # Without this the reader uses its 64 KiB default and raises an
            # uncaught ValueError before the explicit length check is reached.
            limit=MAX_CONTROL_LINE,
        )
        if self._server.sockets:
            # Reflect the port actually bound (relevant when 0 was requested).
            self.port = self._server.sockets[0].getsockname()[1]
        logger.info(
            "FTPS proxy listening on %s:%d (implicit TLS, data ports %d-%d, "
            "%d concurrent printer session(s))",
            self.bind_address,
            self.port,
            self.data_ports.start,
            self.data_ports.end,
            self.queue.max_concurrent,
        )

    async def stop(self) -> None:
        """Stop the proxy and tear down every live session."""
        logger.info("Stopping FTPS proxy")
        self._running = False

        # Listener first: cancelling sessions while still accepting leaves any
        # connection taken during the wait unowned, holding a queue slot.
        server = self._server
        self._server = None
        if server:
            server.close()

        for task in list(self._sessions):
            task.cancel()
        if self._sessions:
            await asyncio.gather(*self._sessions, return_exceptions=True)
        self._sessions.clear()

        # Only now is the listening socket actually released, so stop() means
        # the port is free when it returns.
        if server:
            await server.wait_closed()

        logger.info("FTPS proxy stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Run one client control session."""
        task = asyncio.current_task()
        if task:
            self._sessions.add(task)

        session = ControlSession(self, reader, writer)
        try:
            await session.run()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # Broad by design: one malformed session must not take the
            # listener down for every other client.
            logger.error("FTP session error: %s: %s", type(e).__name__, e)
        finally:
            await session.close()
            if task:
                self._sessions.discard(task)


class ControlSession:
    """One client's control connection, and its on-demand printer session."""

    def __init__(
        self,
        proxy: FTPProxy,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.proxy = proxy
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")

        self.peer_ip = self.peer[0] if self.peer else None
        sockname = writer.get_extra_info("sockname")
        raw_local = proxy.advertise_ip or (sockname[0] if sockname else "127.0.0.1")
        # Unwrap ::ffff:a.b.c.d: a dual-stack listener reports ordinary IPv4
        # clients that way, and PASV would then answer 522 to every one.
        self.local_ip = as_ipv4(raw_local) or raw_local

        self.authenticated = False
        self._upstream_reader: asyncio.StreamReader | None = None
        self._upstream_writer: asyncio.StreamWriter | None = None
        self._holds_slot = False
        # When the printer was last actually used. Locally-answered commands
        # such as NOOP must not keep a session alive that nothing needs.
        self._upstream_last_used = 0.0

        # Session state replayed onto each new printer session. The working
        # directory is kept as one normalised path rather than a list of hops,
        # so CDUP out of a multi-segment path resolves correctly.
        self._state: dict[str, str] = {}
        self._cwd: str = "/"
        # Settings a replayed session refused. Per-command, not a single flag:
        # clearing on any of them let a client that lost TYPE clear it with a
        # PBSZ and then upload a 3MF in ASCII believing it was binary.
        self._lost_settings: set[str] = set()

        # Passive data port reserved by the most recent PASV/EPSV, plus the
        # printer endpoint the relay is waiting for and which form to use.
        self._data_task: asyncio.Task | None = None
        self._data_port: int | None = None
        self._data_endpoint: asyncio.Future[tuple[str, int]] | None = None
        self._data_command_seen: asyncio.Event | None = None
        self._data_handlers: set[asyncio.Task] = set()
        # Bytes the last data channel actually moved, so the completion wait
        # can tell "nothing happened" from "the printer is still writing".
        self._data_moved = 0
        self._passive_mode: str | None = None

    # ------------------------------------------------------------------
    # Client-facing helpers
    # ------------------------------------------------------------------

    async def _send(self, line: str) -> None:
        """Write one reply line to the client."""
        self.writer.write(line.encode("utf-8", errors="replace"))
        await self.writer.drain()

    async def _read_command(self) -> str | None:
        """Read one command line, or None if the client went away.

        A shorter timeout applies while a printer session is held: an idle
        client should not reserve one of the printer's few slots. It is
        reopened transparently on the next command.
        """
        while True:
            if self._upstream_writer is not None:
                unused = time.monotonic() - self._upstream_last_used
                timeout = max(1.0, UPSTREAM_IDLE_TIMEOUT - unused)
            else:
                timeout = CLIENT_IDLE_TIMEOUT
            try:
                raw = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
                break
            except TimeoutError:
                if self._upstream_writer is not None:
                    unused = time.monotonic() - self._upstream_last_used
                    if unused < UPSTREAM_IDLE_TIMEOUT:
                        # Woken early by the clamped timeout; keep waiting.
                        continue
                    logger.info(
                        "Printer unused for %.0fs, releasing the session held by %s",
                        unused,
                        self.peer,
                    )
                    # The passive relay is deliberately left alone: a 227
                    # already sent cannot be retracted, and the relay is
                    # independent of the printer session - _prepare_upstream_data
                    # re-issues PASV on whichever session comes next.
                    await self._release_upstream()
                    continue
                logger.info("Client %s idle, closing", self.peer)
                return None
            except ConnectionResetError, ssl.SSLError:
                return None
            except ValueError:
                # Line longer than the reader's limit.
                logger.warning("Client %s sent an oversized command line", self.peer)
                return None

        if not raw:
            return None
        if len(raw) > MAX_CONTROL_LINE:
            logger.warning("Client %s sent an oversized command line", self.peer)
            return None

        return raw.decode("utf-8", errors="replace").strip("\r\n")

    # ------------------------------------------------------------------
    # Upstream helpers
    # ------------------------------------------------------------------

    async def _read_upstream_reply(self, deadline: float | None = None) -> str | None:
        """Read one complete (possibly multi-line) reply from the printer."""
        if not self._upstream_reader:
            return None

        budget = deadline if deadline is not None else UPSTREAM_REPLY_TIMEOUT
        # An absolute deadline, not a per-line one: a printer emitting a
        # continuation line just under the limit would otherwise hold the
        # session, and the only printer slot, for ever.
        expires_at = time.monotonic() + budget
        try:
            first = await asyncio.wait_for(
                self._upstream_reader.readline(), timeout=budget
            )
        except TimeoutError, ConnectionResetError, ssl.SSLError:
            return None

        if not first:
            return None

        reply = first.decode("utf-8", errors="replace")
        code = reply[:3]
        # A '-' in the 4th column opens a multi-line reply, terminated by a
        # line repeating the same code followed by a space.
        if len(reply) > 3 and reply[3] == "-":
            while True:
                try:
                    remaining = expires_at - time.monotonic()
                    if remaining <= 0:
                        logger.warning("Multi-line reply from the printer timed out")
                        return None
                    more = await asyncio.wait_for(
                        self._upstream_reader.readline(),
                        timeout=remaining,
                    )
                except TimeoutError, ConnectionResetError, ssl.SSLError:
                    return None
                if not more:
                    break
                decoded = more.decode("utf-8", errors="replace")
                reply += decoded
                if decoded.startswith(f"{code} "):
                    break

        return reply

    async def _send_upstream(self, command: str) -> str | None:
        """Send a command to the printer and return its reply."""
        if not self._upstream_writer:
            return None
        self._upstream_last_used = time.monotonic()
        self._upstream_writer.write(f"{command}\r\n".encode())
        await self._upstream_writer.drain()
        return await self._read_upstream_reply()

    async def _ensure_upstream(self, priority: int) -> bool:
        """Open a printer session if we don't have one, queueing if needed."""
        if self._upstream_writer is not None:
            return True

        if not await self._acquire_slot(priority):
            return False
        self._holds_slot = True

        try:
            ssl_context = create_ssl_context(self.proxy.printer_cert_path)
            self._upstream_reader, self._upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.proxy.printer_ip, self.proxy.printer_port, ssl=ssl_context
                ),
                timeout=UPSTREAM_CONNECT_TIMEOUT,
            )
        except (TimeoutError, OSError, ssl.SSLError) as e:
            logger.error("Cannot reach printer FTP: %s: %s", type(e).__name__, e)
            await self._release_upstream()
            return False

        greeting = await self._read_upstream_reply()
        if greeting is None:
            logger.error("Printer sent no FTP greeting")
            await self._release_upstream()
            return False

        if not await self._login_upstream():
            await self._release_upstream()
            return False

        if not await self._replay_state():
            await self._release_upstream()
            return False

        self._upstream_last_used = time.monotonic()
        logger.info("Printer session opened for %s", self.peer)
        return True

    async def _acquire_slot(self, priority: int) -> bool:
        """Wait for a printer slot, giving up if the client goes away.

        Nothing reads the control socket during the queue wait, so without
        this a client that disconnected still kept its place and then spent a
        full printer session - TLS connect, login, state replay - only to find
        the socket dead.
        """
        acquire = asyncio.create_task(self.proxy.queue.acquire(priority))
        gone = asyncio.create_task(self._await_client_gone())
        granted = False
        try:
            done, _ = await asyncio.wait(
                {acquire, gone}, return_when=asyncio.FIRST_COMPLETED
            )
            if acquire in done:
                acquire.result()
                granted = True
                return True

            logger.info("Client %s left while queued, abandoning its turn", self.peer)
            return False
        finally:
            gone.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await gone

            if not granted:
                # Every exit path, cancellation of this task included: an
                # orphaned acquire would later take the slot with nobody left
                # to release it, and at max_concurrent=1 that ends the service.
                acquire.cancel()
                try:
                    await acquire
                except asyncio.CancelledError:
                    # SessionQueue.acquire hands back a slot it was granted
                    # while being cancelled, so nothing more to do.
                    pass
                else:
                    # It won the race before the cancel landed, so it owns a
                    # slot this session will never use.
                    self.proxy.queue.release()

    async def _await_client_gone(self) -> None:
        """Return once the control socket is known to be dead.

        Polls rather than reads: reading would consume a command the client
        may have pipelined behind the one being served.
        """
        while True:
            if self.reader is None:
                return
            if self.reader.at_eof() or self.reader.exception() is not None:
                return
            await asyncio.sleep(CLIENT_LIVENESS_CHECK)

    async def _login_upstream(self) -> bool:
        """Authenticate the printer session."""
        user_reply = await self._send_upstream("USER bblp")
        if user_reply is None or user_reply[0] not in "23":
            logger.error("Printer rejected USER: %s", (user_reply or "").strip())
            return False

        if user_reply.startswith("3"):
            pass_reply = await self._send_upstream(f"PASS {self.proxy.access_code}")
            if pass_reply is None or not pass_reply.startswith("2"):
                logger.error("Printer rejected PASS: %s", (pass_reply or "").strip())
                return False

        return True

    async def _replay_state(self) -> bool:
        """Reapply the session settings the client set before we connected.

        False means the printer refused one of them, which makes the session
        unsafe to use: a wrong TYPE corrupts a binary upload and a wrong
        directory silently misplaces the file.
        """
        replay = [
            (name, self._state[name])
            for name in ("PBSZ", "PROT", "TYPE")
            if name in self._state
        ]
        if self._cwd not in ("", "/"):
            replay.append(("CWD", self._cwd))

        for command, argument in replay:
            reply = await self._send_upstream(f"{command} {argument}")
            # Only 2xx means applied. 3xx is "more input needed", which for a
            # replayed setting means it did not take effect.
            if reply is None or not reply.startswith("2"):
                logger.error(
                    "Replaying '%s %s' failed (%s); abandoning the session",
                    command,
                    argument,
                    (reply or "").strip(),
                )
                # Forget it, or every future session would replay the same
                # refusal and the client would be stuck on 421 for good.
                if command == "CWD":
                    # Do not silently relocate the client: it was told 250 for
                    # this directory and has no way to learn otherwise, so a
                    # relative STOR would land in the printer's root.
                    self._cwd = "/"
                else:
                    # Same for a mode: dropping a refused TYPE would leave the
                    # printer in ASCII while the client thinks it is binary.
                    self._state.pop(command, None)
                self._lost_settings.add(command)
                return False
        return True

    async def _release_upstream(self) -> None:
        """Close the printer session and hand the slot back.

        Released in a ``finally`` so a socket wedged on TLS shutdown cannot
        keep the next client queued.
        """
        writer = self._upstream_writer
        self._upstream_reader = None
        self._upstream_writer = None

        try:
            if writer is not None:
                await close_writer(writer)
        finally:
            if self._holds_slot:
                self._holds_slot = False
                self.proxy.queue.release()

    # ------------------------------------------------------------------
    # Passive data channel
    # ------------------------------------------------------------------

    async def _open_passive_relay(self) -> int | None:
        """Reserve a pooled port and start listening on it.

        The printer is not contacted here. Its data endpoint is supplied later
        via :meth:`_prepare_upstream_data`, once the transfer command reveals
        whether this is an upload - which is what lets uploads be queued ahead
        of listings. A client that asks for a passive port and then goes away
        therefore never opens a printer session at all.
        """
        await self._cancel_data_relay()
        self._data_moved = 0

        port = self.proxy.data_ports.acquire()
        if port is None:
            return None

        loop = asyncio.get_running_loop()
        endpoint: asyncio.Future[tuple[str, int]] = loop.create_future()
        command_seen = asyncio.Event()
        accepted = asyncio.Event()
        finished = asyncio.Event()
        # Connection handlers are tasks asyncio owns; closing the server does
        # not cancel them, so they have to be tracked to be torn down.
        handlers: set[asyncio.Task] = set()

        async def relay(
            client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
        ) -> None:
            peer = client_writer.get_extra_info("peername")
            peer_ip = peer[0] if peer else None

            # Only the host holding the control session may use this port: it
            # is reachable by anyone on the LAN for the length of the accept
            # window, and its bytes would be spliced into the printer's data
            # channel.
            #
            # Caveat: under Docker bridge networking the userland proxy
            # rewrites the source of both connections to the bridge gateway,
            # so they always match and this cannot discriminate. It is
            # effective on host and macvlan networking; the one-connection
            # rule below still applies everywhere.
            if self.peer_ip is not None and peer_ip != self.peer_ip:
                logger.warning(
                    "Refusing data connection from %s on port %d (expected %s)",
                    peer_ip,
                    port,
                    self.peer_ip,
                )
                await close_writer(client_writer)
                return

            # One transfer per passive port: a second connection would await
            # the same endpoint and dial the printer's single port as well,
            # able to win the race against the real client.
            if accepted.is_set():
                logger.warning("Refusing a second data connection on port %d", port)
                await close_writer(client_writer)
                return

            accepted.set()
            handler = asyncio.current_task()
            if handler is not None:
                handlers.add(handler)
            upstream_writer: asyncio.StreamWriter | None = None
            try:
                # Clients connect as soon as they have the 227, so bound only
                # the wait for the transfer command to follow. The endpoint
                # itself arrives after the queue wait, which is legitimate and
                # can outlast any fixed deadline; the session's teardown is
                # what cancels this task if the client goes away.
                await command_seen.wait()
                host, upstream_port = await endpoint
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, upstream_port),
                    timeout=UPSTREAM_CONNECT_TIMEOUT,
                )
                self._data_moved = await _pipe_both_ways(
                    client_reader, client_writer, upstream_reader, upstream_writer
                )
            except (TimeoutError, OSError, ssl.SSLError) as e:
                logger.warning("Data relay failed: %s: %s", type(e).__name__, e)
            except asyncio.CancelledError:
                raise
            finally:
                await close_writer(client_writer)
                if upstream_writer:
                    await close_writer(upstream_writer)
                if handler is not None:
                    handlers.discard(handler)
                finished.set()

        try:
            server = await asyncio.start_server(relay, self.proxy.bind_address, port)
        except Exception as e:
            # Broad on purpose: anything from a port already in use (OSError)
            # to an out-of-range one (OverflowError) must give the port back
            # rather than leak it out of the pool for the process lifetime.
            logger.warning(
                "Cannot bind data port %d: %s: %s", port, type(e).__name__, e
            )
            self.proxy.data_ports.release(port)
            return None

        async def supervise() -> None:
            try:
                # Phase 1: did a transfer command follow the passive request at
                # all? Bounded, or an abandoned PASV would pin the port for the
                # life of the session.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        command_seen.wait(), timeout=DATA_ENDPOINT_TIMEOUT
                    )
                if not command_seen.is_set():
                    # The port returns to the pool while the client may still
                    # hold a valid 227 for it. Holding it for ever is not an
                    # option either; what protects the next session is the
                    # one-connection-per-port rule plus the "relay is gone"
                    # refusal on the control side.
                    logger.debug("No transfer followed on data port %d", port)
                    return

                # Phase 2: the printer's endpoint only lands after the queue
                # wait, which can legitimately outlast any deadline.
                await endpoint

                # Phase 3: only now can the client be expected to connect, so
                # only now does the accept window mean anything. Timing it from
                # earlier would recycle a port the client still holds a 227 for.
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(accepted.wait(), timeout=DATA_ACCEPT_TIMEOUT)
                if accepted.is_set():
                    await finished.wait()
            finally:
                # Handlers must go before the server: one parked on
                # command_seen will never be woken by anything else, and
                # wait_closed() blocks on in-flight handlers, which would keep
                # this port out of the pool for good.
                for handler in list(handlers):
                    handler.cancel()
                server.close()
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.gather(*handlers, return_exceptions=True)
                    await server.wait_closed()
                self.proxy.data_ports.release(port)

        self._data_task = asyncio.create_task(supervise())
        self._data_port = port
        self._data_endpoint = endpoint
        self._data_command_seen = command_seen
        self._data_handlers = handlers
        return port

    async def _prepare_upstream_data(self) -> bool:
        """Ask the printer for a data port and hand it to the waiting relay.

        Called just before a transfer command is forwarded. Returns False if
        the client has already been sent an error reply.
        """
        endpoint = self._data_endpoint
        if endpoint is None or endpoint.done():
            # No passive port pending: the client may be using active mode, in
            # which case the printer answers for itself.
            return True

        if self._data_task is None or self._data_task.done():
            # The relay gave up (nobody connected, or the request was
            # abandoned). Asking the printer to open a channel nobody will
            # service would block on the completion reply while holding the
            # only printer slot.
            logger.warning("Passive relay is gone; refusing the transfer")
            await self._cancel_data_relay()
            await self._send("425 Data connection expired, use PASV again\r\n")
            return False

        # PASV first regardless of what the client asked for: the proxy owns
        # the client-facing endpoint, so the upstream verb is ours to choose,
        # and PASV is the one verified against real firmware. EPSV is only a
        # fallback for a printer that refuses it.
        parsed: tuple[str, int] | None = None
        for command in ("PASV", "EPSV"):
            reply = await self._send_upstream(command)
            if reply is None:
                await self._cancel_data_relay()
                await self._send("421 Lost connection to printer\r\n")
                await self._release_upstream()
                return False

            expected = "227" if command == "PASV" else "229"
            if not reply.startswith(expected):
                logger.debug("Printer refused %s: %r", command, reply.strip())
                continue

            if command == "PASV":
                endpoint_reply = parse_pasv_reply(reply)
                # Use the address we already reach the printer on rather than
                # the one it reports: embedded servers sometimes answer with
                # 0.0.0.0 or a stale interface.
                port = endpoint_reply[1] if endpoint_reply else None
            else:
                port = parse_epsv_reply(reply)
            parsed = (self.proxy.printer_ip, port) if port is not None else None

            if parsed is not None:
                break
            logger.debug(
                "Printer did not answer %s usefully: %r", command, reply.strip()
            )

        if parsed is None:
            logger.warning("Printer offered no usable passive port")
            await self._cancel_data_relay()
            await self._send("425 Cannot open passive connection\r\n")
            return False

        logger.debug("Data channel %s:%d -> local %s", *parsed, self._data_port)
        endpoint.set_result(parsed)
        return True

    async def _cancel_data_relay(self) -> None:
        """Tear down a passive port, including any connection still on it."""
        task = self._data_task
        handlers = self._data_handlers
        self._data_task = None
        self._data_port = None
        self._data_endpoint = None
        self._data_command_seen = None
        self._data_handlers = set()
        self._passive_mode = None

        # Handlers first: they may be parked waiting for a transfer command or
        # for the printer's endpoint, and nothing else would ever wake them.
        for handler in list(handlers):
            handler.cancel()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)

        if task is None:
            return

        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(task, timeout=DATA_TEARDOWN_TIMEOUT)

    # ------------------------------------------------------------------
    # Command handling
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Serve this client until it disconnects."""
        logger.info("FTP client connected from %s", self.peer)
        await self._send("220 PandaProxy FTP ready\r\n")

        while self.proxy.running:
            line = await self._read_command()
            if line is None:
                break

            command, _, argument = line.partition(" ")
            command = command.upper()
            argument = argument.strip()

            if not command:
                # A stray CRLF must not cost a TLS connect, a login and 30s of
                # the single printer slot.
                await self._send("500 Syntax error\r\n")
                continue

            if command == "QUIT":
                await self._send("221 Goodbye\r\n")
                break

            if not self.authenticated and command not in _PRE_AUTH_COMMANDS:
                await self._send("530 Please login with USER and PASS\r\n")
                continue

            if command in {"PASV", "EPSV"}:
                await self._handle_passive_request(command, argument)
                continue

            handled = await self._handle_local(command, argument)
            if handled:
                continue

            await self._handle_upstream(command, argument, line)

        logger.info("FTP client %s disconnected", self.peer)

    async def _handle_local(self, command: str, argument: str) -> bool:
        """Answer a command without the printer. Returns True if handled."""
        if command == "USER":
            await self._send("331 Password required\r\n")
            return True

        if command == "PASS":
            if argument != self.proxy.access_code:
                logger.warning("FTP auth failed for %s", self.peer)
                await self._send("530 Login incorrect\r\n")
                return True
            self.authenticated = True
            logger.info("FTP client %s authenticated", self.peer)
            await self._send("230 Login successful\r\n")
            return True

        if command in {"PORT", "EPRT"}:
            # Active mode would have the printer dial the client directly,
            # bypassing the proxy - and the queueing that is its purpose.
            await self._send("502 Active mode not supported, use PASV\r\n")
            return True

        if command == "AUTH":
            # The connection is already implicitly TLS-wrapped.
            await self._send("534 Already using TLS\r\n")
            return True

        if command == "FEAT":
            await self._send("211-Features:\r\n PASV\r\n EPSV\r\n PBSZ\r\n PROT\r\n")
            await self._send("211 End\r\n")
            return True

        if command == "SYST":
            await self._send("215 UNIX Type: L8\r\n")
            return True

        if command in {"NOOP", "OPTS"}:
            await self._send("200 OK\r\n")
            return True

        # Settings are recorded so they can be replayed onto a future printer
        # session, and answered locally while we have none.
        if command in STATEFUL_COMMANDS:
            if command in {"CWD", "CDUP"}:
                # Always the printer's call: only it knows whether the
                # directory exists, and answering locally would confirm a path
                # that does not, sending a later upload somewhere else.
                return False

            if self._upstream_writer is None:
                # No session to ask, so accept it and replay it later.
                self._state[command] = argument
                self._lost_settings.discard(command)
                await self._send(f"200 {command} set to {argument}\r\n")
                return True
            # A session is held: let the printer rule, and only record what it
            # accepts. Keeping a rejected value would fail every future replay
            # and lock the client out with 421 for good.
            return False

        return False

    def _record_cwd(self, argument: str) -> None:
        """Track the working directory so it can be replayed after a reconnect."""
        self._lost_settings.discard("CWD")
        if argument.startswith("/"):
            self._cwd = posixpath.normpath(argument)
        else:
            self._cwd = posixpath.normpath(posixpath.join(self._cwd, argument))
        # normpath keeps a leading ".." when it cannot resolve it; the printer
        # root is the top, so clamp instead of climbing above it.
        if not self._cwd.startswith("/"):
            self._cwd = "/"

    async def _handle_upstream(self, command: str, argument: str, line: str) -> None:
        """Forward a command to the printer, opening a session if needed."""
        if self._lost_settings and command not in STATEFUL_COMMANDS:
            missing = ", ".join(sorted(self._lost_settings))
            await self._send(f"521 Re-issue {missing} before continuing\r\n")
            return

        priority = PRIORITY_UPLOAD if command in UPLOAD_COMMANDS else PRIORITY_NORMAL

        if command in _TRANSFER_COMMANDS and (
            self._data_endpoint is None or self._data_endpoint.done()
        ):
            # No passive channel waiting, and active mode is refused, so this
            # cannot succeed. Answering here also spares a printer session.
            await self._send("425 Use PASV first\r\n")
            return

        if command in _TRANSFER_COMMANDS and self._data_command_seen is not None:
            # Unblocks the relay before we queue, so a long queue wait is not
            # mistaken for an absent client.
            self._data_command_seen.set()

        connected = await self._ensure_upstream(priority)

        if not connected:
            await self._cancel_data_relay()
            await self._send("421 Printer unavailable, try again later\r\n")
            return

        if command in _TRANSFER_COMMANDS and not await self._prepare_upstream_data():
            return

        reply = await self._send_upstream(line)
        if reply is None:
            await self._cancel_data_relay()
            await self._send("421 Lost connection to printer\r\n")
            await self._release_upstream()
            return

        if reply[0] == "2":
            if command in {"CWD", "CDUP"}:
                self._record_cwd(".." if command == "CDUP" else argument)
            elif command in STATEFUL_COMMANDS:
                self._state[command] = argument
                self._lost_settings.discard(command)

        await self._send(reply)

        # A transfer command gets a preliminary reply first; the completion
        # reply only arrives once the data connection is done.
        if reply.startswith("1") and command in _TRANSFER_COMMANDS:
            final = await self._await_completion()
            if final is None:
                await self._send("426 Transfer aborted\r\n")
                await self._release_upstream()
                return
            await self._send(final)

    async def _await_completion(self) -> str | None:
        """Wait for the transfer's completion reply, bounded by the data channel.

        A long upload legitimately takes a long time, but once the data
        channel is finished the reply is imminent - and if the channel was
        abandoned it will never come, so waiting the full completion timeout
        would pin the only printer slot for an hour.
        """
        reply_task = asyncio.create_task(
            self._read_upstream_reply(deadline=TRANSFER_COMPLETION_TIMEOUT)
        )
        watch = {reply_task}
        data_task = self._data_task
        if data_task is not None:
            watch.add(data_task)

        done, _pending = await asyncio.wait(watch, return_when=asyncio.FIRST_COMPLETED)
        if reply_task in done:
            return reply_task.result()

        # The data channel ended first: give the printer a grace to announce
        # the outcome, generous only if there was something to commit.
        grace = DATA_COMMIT_GRACE if self._data_moved else DATA_POST_TRANSFER_GRACE
        try:
            return await asyncio.wait_for(reply_task, timeout=grace)
        except TimeoutError:
            logger.warning("No completion reply after the data channel ended")
            reply_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reply_task
            return None

    async def _handle_passive_request(self, command: str, argument: str) -> None:
        """Answer PASV/EPSV locally, reserving a port for the coming transfer."""
        if command == "EPSV" and argument.upper() == "ALL":
            # A declaration that only extended passive mode will be used, not
            # a request for a port. lftp and ncftp send it.
            await self._send("200 EPSV ALL accepted\r\n")
            return

        if command == "PASV" and as_ipv4(self.local_ip) is None:
            # PASV can only express IPv4. An IPv6 client must use EPSV.
            logger.warning("Cannot advertise %s in a PASV reply", self.local_ip)
            await self._send("522 Use EPSV; PASV cannot express this address\r\n")
            return

        local_port = await self._open_passive_relay()
        if local_port is None:
            await self._send("425 No data port available, try again\r\n")
            return

        # Only the bare verb: the argument is the client's own addressing
        # preference and must not be echoed to the printer.
        self._passive_mode = command
        if command == "EPSV":
            await self._send(format_epsv_reply(local_port))
        else:
            await self._send(format_pasv_reply(self.local_ip, local_port))

    async def close(self) -> None:
        """Release everything this session holds.

        The printer slot goes back first, so a queued client does not wait on
        this session's socket teardown.
        """
        await self._release_upstream()
        await self._cancel_data_relay()
        await close_writer(self.writer)


def _other(direction: str) -> str:
    """The opposite relay direction."""
    return "printer->client" if direction == "client->printer" else "client->printer"


def _force_reset(writer: asyncio.StreamWriter) -> None:
    """Close a data socket so the peer sees a reset, not an end of file.

    ``transport.abort()`` alone usually still sends a FIN, which the printer
    reads as a clean end of file - and it will answer 226 for a file that was
    only partly written. SO_LINGER with a zero timeout turns the close into an
    RST, so a truncated transfer is unmistakably a failure.
    """
    with contextlib.suppress(OSError, ssl.SSLError, AttributeError):
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
    with contextlib.suppress(OSError, ssl.SSLError):
        transport = writer.transport
        if transport is not None:
            transport.abort()


async def _pipe_both_ways(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> int:
    """Relay bytes in both directions until either side closes.

    Returns how lopsided the traffic was, which tells the control side whether
    a payload went through and the printer may still be committing it.
    """

    # Shared across both directions: a download is silent upstream for its
    # whole duration, so only total silence counts as a stall.
    activity = [time.monotonic()]

    # Bytes moved per direction: the one that carried data *is* the transfer
    # and must never be cut short, whatever the other side does.
    moved: dict[str, int] = {"client->printer": 0, "printer->client": 0}

    async def pump(
        src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str
    ) -> None:
        saw_eof = False
        try:
            while True:
                chunk = await src.read(DATA_CHUNK)
                if not chunk:
                    saw_eof = True
                    break
                activity[0] = time.monotonic()
                moved[direction] += len(chunk)
                dst.write(chunk)
                await dst.drain()
        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as e:
            logger.debug("Data pump %s ended: %s", direction, e)
        finally:
            if saw_eof:
                # A transfer's end is signalled by the sender closing its
                # side, so pass the half-close on.
                with contextlib.suppress(OSError, ssl.SSLError):
                    if dst.can_write_eof():
                        dst.write_eof()
            elif moved[direction] > moved[_other(direction)]:
                # Only the direction that carried the payload can be
                # truncated, and comparing the two volumes is what tells
                # payload from a TLS handshake, which moves a comparable few
                # KB both ways. Resetting on "is toward the printer" alone hit
                # the normal end of every download - the printer closes, the
                # idle upstream pump is cancelled, and the RST landed just as
                # it was about to emit 226.
                #
                # Trade-off: an upload aborted before its first byte gets a
                # clean close, so the printer may keep an empty file and
                # answer 226. An empty 3MF is unusable and obvious; resetting
                # healthy transfers is not.
                logger.debug("Data pump %s aborted, resetting the peer", direction)
                _force_reset(dst)

    async def watchdog() -> None:
        while True:
            await asyncio.sleep(DATA_STALL_CHECK)
            silent = time.monotonic() - activity[0]
            if silent > DATA_STALL_TIMEOUT:
                logger.warning("Data transfer silent for %.1fs, aborting it", silent)
                return

    upstream_pump = asyncio.create_task(
        pump(client_reader, upstream_writer, "client->printer")
    )
    downstream_pump = asyncio.create_task(
        pump(upstream_reader, client_writer, "printer->client")
    )
    stall = asyncio.create_task(watchdog())
    tasks = [upstream_pump, downstream_pump, stall]
    directions = {
        upstream_pump: "client->printer",
        downstream_pump: "printer->client",
    }
    try:
        # A transfer flows one way, so it ends when that direction sees EOF.
        # Waiting for both hangs forever on a download, where the client never
        # closes its side.
        # The watchdog stays in every wait set, so a wedged transfer is
        # bounded at each step rather than only at the first.
        done, _pending = await asyncio.wait(
            {upstream_pump, downstream_pump, stall},
            return_when=asyncio.FIRST_COMPLETED,
        )

        if stall not in done:
            live = [
                task for task in (upstream_pump, downstream_pump) if not task.done()
            ]
            if live:
                other = live[0]
                if moved[directions[other]] == 0:
                    # Idle direction: it only needs long enough to notice the
                    # close, and nothing is lost by cutting it off.
                    _flushed, stuck = await asyncio.wait(
                        {other}, timeout=DATA_DRAIN_GRACE
                    )
                    for task in stuck:
                        task.cancel()
                else:
                    # It carried bytes, but that alone is not liveness: a TLS
                    # handshake moves bytes both ways. Keep extending only
                    # while it is still making progress.
                    while True:
                        before = moved[directions[other]]
                        done2, _ = await asyncio.wait(
                            {other, stall},
                            timeout=DATA_DRAIN_GRACE,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if other in done2 or stall in done2:
                            break
                        if moved[directions[other]] == before:
                            # Silent for a whole grace period: the transfer is
                            # over and this is just an unclosed socket.
                            other.cancel()
                            break
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    # The asymmetry, not the total: a TLS handshake moves a comparable few KB
    # in both directions, while a transfer piles up on one side. This is what
    # separates "a file went through" from "only a handshake happened".
    return max(moved.values()) - min(moved.values())
