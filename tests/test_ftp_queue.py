"""Tests for FTPS session queueing, data ports and session state."""

import asyncio
import contextlib

import pytest

from pandaproxy.ftp_proxy import ControlSession, FTPProxy
from pandaproxy.ftp_queue import (
    PRIORITY_NORMAL,
    PRIORITY_UPLOAD,
    DataPortPool,
    SessionQueue,
)


async def _dummy_upstream() -> tuple[asyncio.Server, int]:
    """A listener the data relay can actually connect to."""

    async def hold(reader, writer):
        with contextlib.suppress(Exception):
            await reader.read()
        writer.close()

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


class _StubWriter:
    """Minimal StreamWriter stand-in for constructing a session offline."""

    def __init__(self, local_ip: str = "127.0.0.1", peer_ip: str = "127.0.0.1") -> None:
        self._local_ip = local_ip
        self._peer_ip = peer_ip

    def get_extra_info(self, name):
        if name == "sockname":
            return (self._local_ip, 990)
        if name == "peername":
            return (self._peer_ip, 51234)
        return None

    def close(self):
        pass


class TestSessionQueue:
    """Slot accounting, ordering and priority."""

    async def test_acquires_up_to_the_limit_without_blocking(self):
        queue = SessionQueue(max_concurrent=2)
        await asyncio.wait_for(queue.acquire(), timeout=1)
        await asyncio.wait_for(queue.acquire(), timeout=1)
        assert queue.active == 2
        assert queue.waiting == 0

    async def test_blocks_beyond_the_limit(self):
        queue = SessionQueue(max_concurrent=1)
        await queue.acquire()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(queue.acquire(), timeout=0.1)

    async def test_release_hands_the_slot_to_a_waiter(self):
        queue = SessionQueue(max_concurrent=1)
        await queue.acquire()
        waiter = asyncio.create_task(queue.acquire())
        await asyncio.sleep(0)
        assert queue.waiting == 1

        queue.release()
        await asyncio.wait_for(waiter, timeout=1)
        assert queue.active == 1
        assert queue.waiting == 0

    async def test_uploads_jump_ahead_of_listings(self):
        queue = SessionQueue(max_concurrent=1)
        await queue.acquire()

        served: list[str] = []

        async def contender(name: str, priority: int) -> None:
            await queue.acquire(priority)
            served.append(name)

        listing = asyncio.create_task(contender("listing", PRIORITY_NORMAL))
        await asyncio.sleep(0)
        upload = asyncio.create_task(contender("upload", PRIORITY_UPLOAD))
        await asyncio.sleep(0)

        queue.release()
        await asyncio.wait_for(upload, timeout=1)
        queue.release()
        await asyncio.wait_for(listing, timeout=1)

        # The upload arrived second but is served first.
        assert served == ["upload", "listing"]

    async def test_equal_priority_keeps_fifo_order(self):
        queue = SessionQueue(max_concurrent=1)
        await queue.acquire()

        served: list[int] = []

        async def contender(index: int) -> None:
            await queue.acquire(PRIORITY_NORMAL)
            served.append(index)

        tasks = []
        for i in range(3):
            tasks.append(asyncio.create_task(contender(i)))
            await asyncio.sleep(0)

        for _ in range(3):
            queue.release()
            await asyncio.sleep(0)
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)

        assert served == [0, 1, 2]

    async def test_cancelled_waiter_does_not_consume_a_slot(self):
        # A client that disconnects while queued must not have a slot handed
        # to its abandoned future, which would deadlock everyone behind it.
        queue = SessionQueue(max_concurrent=1)
        await queue.acquire()

        abandoned = asyncio.create_task(queue.acquire())
        await asyncio.sleep(0)
        abandoned.cancel()
        with pytest.raises(asyncio.CancelledError):
            await abandoned

        queue.release()
        await asyncio.wait_for(queue.acquire(), timeout=1)
        assert queue.active == 1

    async def test_slot_context_manager_releases_on_error(self):
        queue = SessionQueue(max_concurrent=1)
        with pytest.raises(ValueError, match="boom"):
            async with queue.slot():
                raise ValueError("boom")
        assert queue.active == 0

    def test_rejects_zero_concurrency(self):
        with pytest.raises(ValueError, match="at least 1"):
            SessionQueue(max_concurrent=0)


class TestDataPortPool:
    """Passive data-port reservation."""

    async def test_hands_out_distinct_ports(self):
        pool = DataPortPool(2000, 2002)
        ports = {pool.acquire() for _ in range(3)}
        assert ports == {2000, 2001, 2002}
        assert pool.available == 0

    async def test_returns_none_when_exhausted(self):
        pool = DataPortPool(2000, 2000)
        assert pool.acquire() == 2000
        assert pool.acquire() is None

    async def test_released_ports_come_back(self):
        pool = DataPortPool(2000, 2000)
        port = pool.acquire()
        pool.release(port)
        assert pool.available == 1
        assert pool.acquire() == 2000

    async def test_releasing_an_unknown_port_is_ignored(self):
        pool = DataPortPool(2000, 2001)
        pool.release(9999)
        assert pool.available == 2

    async def test_double_release_does_not_duplicate(self):
        pool = DataPortPool(2000, 2001)
        port = pool.acquire()
        pool.release(port)
        pool.release(port)
        assert pool.available == 2

    async def test_ports_cycle_rather_than_repeat_immediately(self):
        # Reusing a port straight away risks colliding with a TIME_WAIT socket.
        pool = DataPortPool(2000, 2001)
        first = pool.acquire()
        pool.release(first)
        second = pool.acquire()
        assert second != first

    def test_rejects_inverted_range(self):
        with pytest.raises(ValueError, match="greater than"):
            DataPortPool(2100, 2000)


class TestDataPortPoolBindFailure:
    """A port that cannot be bound must go back to the pool."""

    async def test_port_is_returned_when_bind_fails(self, temp_certs):
        # Regression: the pool leaked a port on every failed bind, so a
        # handful of collisions left the proxy permanently unable to open a
        # data channel, answering 425 until restart.
        cert, key = temp_certs

        squatter = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        taken = squatter.sockets[0].getsockname()[1]
        try:
            proxy = FTPProxy(
                printer_ip="127.0.0.1",
                access_code="x",
                cert_path=cert,
                key_path=key,
                bind_address="127.0.0.1",
                printer_cert_path=cert,
                data_port_start=taken,
                data_port_end=taken,
            )
            session = ControlSession(proxy, None, _StubWriter())
            assert proxy.data_ports.available == 1

            assert await session._open_passive_relay() is None
            assert proxy.data_ports.available == 1, "port leaked out of the pool"
        finally:
            squatter.close()
            await squatter.wait_closed()


class TestAdvertisedAddress:
    """PASV must name an address the client can actually reach."""

    def test_socket_address_is_used_by_default(self, temp_certs):
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        session = ControlSession(proxy, None, _StubWriter("10.1.2.3"))
        assert session.local_ip == "10.1.2.3"

    def test_explicit_advertise_ip_wins(self, temp_certs):
        # Under Docker bridge networking the socket sees the container's own
        # private address, which no LAN client can reach.
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            advertise_ip="192.168.1.60",
        )
        session = ControlSession(proxy, None, _StubWriter("172.18.0.2"))
        assert session.local_ip == "192.168.1.60"


class TestAcceptWindowTiming:
    """The accept window must not be consumed by the queue wait."""

    async def test_window_starts_after_the_printer_answers(
        self, temp_certs, monkeypatch
    ):
        # Regression: the window used to start when the transfer command was
        # seen, which is before queueing. A client that connects only after
        # the 150 reply - legal, and what curl does - lost its port whenever
        # the queue held it longer than the window.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ACCEPT_TIMEOUT", 0.3)
        monkeypatch.setattr(module, "DATA_ENDPOINT_TIMEOUT", 5.0)

        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            bind_address="127.0.0.1",
            printer_cert_path=cert,
            data_port_start=21983,
            data_port_end=21983,
        )
        session = ControlSession(proxy, None, _StubWriter())
        port = await session._open_passive_relay()

        # Transfer command seen, then a queue wait longer than the window.
        session._data_command_seen.set()
        await asyncio.sleep(0.6)
        assert proxy.data_ports.available == 0, "port recycled during the queue wait"

        # The printer finally answers and the client connects.
        upstream, upstream_port = await _dummy_upstream()
        try:
            session._data_endpoint.set_result(("127.0.0.1", upstream_port))
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.1)
            assert not session._data_task.done(), "relay ended despite a live client"

            writer.close()
            with contextlib.suppress(ConnectionResetError, OSError):
                await writer.wait_closed()
            assert reader is not None
        finally:
            await session._cancel_data_relay()
            upstream.close()
            await upstream.wait_closed()


class TestWorkingDirectory:
    """The replayed directory must match where the printer actually is."""

    def _session(self, temp_certs):
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        return ControlSession(proxy, None, _StubWriter())

    def test_starts_at_the_root(self, temp_certs):
        assert self._session(temp_certs)._cwd == "/"

    def test_relative_steps_accumulate(self, temp_certs):
        session = self._session(temp_certs)
        session._record_cwd("/cache")
        session._record_cwd("sub")
        assert session._cwd == "/cache/sub"

    def test_absolute_path_replaces(self, temp_certs):
        session = self._session(temp_certs)
        session._record_cwd("/cache/model")
        session._record_cwd("/timelapse")
        assert session._cwd == "/timelapse"

    def test_parent_of_a_multi_segment_path(self, temp_certs):
        # Regression: a list of hops stored "/cache/model" as one element, so
        # CDUP emptied it and replay put the session at the root while the
        # printer was really in /cache - a silent wrong-directory upload.
        session = self._session(temp_certs)
        session._record_cwd("/cache/model")
        session._record_cwd("..")
        assert session._cwd == "/cache"

    def test_parent_of_a_relative_multi_hop(self, temp_certs):
        session = self._session(temp_certs)
        session._record_cwd("a/b")
        session._record_cwd("..")
        assert session._cwd == "/a"

    def test_parent_at_the_root_is_clamped(self, temp_certs):
        session = self._session(temp_certs)
        session._record_cwd("..")
        assert session._cwd == "/"

    def test_climbing_above_the_root_is_clamped(self, temp_certs):
        session = self._session(temp_certs)
        session._record_cwd("/cache")
        session._record_cwd("../../..")
        assert session._cwd == "/"


class TestPassiveRelayLifecycle:
    """The reserved port must always find its way back to the pool."""

    def _proxy(self, temp_certs, port):
        cert, key = temp_certs
        return FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            bind_address="127.0.0.1",
            printer_cert_path=cert,
            data_port_start=port,
            data_port_end=port,
        )

    async def test_port_returns_when_no_transfer_command_follows(
        self, temp_certs, monkeypatch
    ):
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ENDPOINT_TIMEOUT", 0.2)
        proxy = self._proxy(temp_certs, 21980)
        session = ControlSession(proxy, None, _StubWriter())

        assert await session._open_passive_relay() == 21980
        assert proxy.data_ports.available == 0

        await asyncio.wait_for(session._data_task, timeout=5)
        assert proxy.data_ports.available == 1

    async def test_port_returns_when_the_client_never_connects(
        self, temp_certs, monkeypatch
    ):
        # Regression: asyncio.wait_for cancels the future it waits on, and a
        # cancelled future still reports done() - so the supervisor awaited a
        # handler that never ran, pinning the port and its listening socket.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ACCEPT_TIMEOUT", 0.2)
        proxy = self._proxy(temp_certs, 21981)
        session = ControlSession(proxy, None, _StubWriter())

        assert await session._open_passive_relay() == 21981
        session._data_command_seen.set()
        # The printer answered, so the client is now expected to connect.
        # Nobody does, so the accept window must lapse and free the port.
        session._data_endpoint.set_result(("127.0.0.1", 9))

        await asyncio.wait_for(session._data_task, timeout=5)
        assert proxy.data_ports.available == 1

    async def test_accept_window_does_not_run_during_the_queue_wait(
        self, temp_certs, monkeypatch
    ):
        # Regression: the 30s accept window used to start at PASV, so a queued
        # transfer could have its advertised port released and handed to
        # another session while its client was still about to connect.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ACCEPT_TIMEOUT", 0.2)
        monkeypatch.setattr(module, "DATA_ENDPOINT_TIMEOUT", 5.0)
        proxy = self._proxy(temp_certs, 21982)
        session = ControlSession(proxy, None, _StubWriter())

        port = await session._open_passive_relay()
        # Stand in for a long queue wait: no transfer command yet.
        await asyncio.sleep(0.5)
        assert proxy.data_ports.available == 0, "port recycled while advertised"
        assert not session._data_task.done()

        # The command finally lands, the printer answers, the client connects.
        upstream, upstream_port = await _dummy_upstream()
        try:
            session._data_command_seen.set()
            session._data_endpoint.set_result(("127.0.0.1", upstream_port))
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.1)
            assert not session._data_task.done(), "relay ended despite a live client"

            writer.close()
            with contextlib.suppress(ConnectionResetError, OSError):
                await writer.wait_closed()
            assert reader is not None
        finally:
            await session._cancel_data_relay()
            upstream.close()
            await upstream.wait_closed()


class TestRelayHandlerTeardown:
    """A parked connection handler must not outlive its session."""

    async def test_parked_handler_is_cancelled_and_its_socket_closed(self, temp_certs):
        # Regression: cancelling the supervisor left the connection handler
        # parked on command_seen/endpoint forever - server.close() does not
        # cancel in-flight handlers - leaking one task and socket per aborted
        # transfer for the lifetime of the process.
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            bind_address="127.0.0.1",
            printer_cert_path=cert,
            data_port_start=21984,
            data_port_end=21984,
        )
        session = ControlSession(proxy, None, _StubWriter())
        port = await session._open_passive_relay()

        # Client connects, then abandons: no transfer command ever arrives.
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        assert len(session._data_handlers) == 1, "handler not tracked"
        handler = next(iter(session._data_handlers))

        await session._cancel_data_relay()

        assert handler.done(), "handler still parked after teardown"
        assert proxy.data_ports.available == 1, "port not returned"
        writer.close()
        with contextlib.suppress(ConnectionResetError, OSError):
            await writer.wait_closed()


class TestPreAuthCommands:
    """FEAT must work before login (RFC 2389)."""

    def test_feat_and_syst_are_allowed_before_login(self):
        from pandaproxy.ftp_proxy import _PRE_AUTH_COMMANDS

        assert {"FEAT", "SYST", "NOOP"} <= _PRE_AUTH_COMMANDS

    def test_data_commands_still_require_login(self):
        from pandaproxy.ftp_proxy import _PRE_AUTH_COMMANDS

        assert not {"STOR", "RETR", "LIST", "PASV", "DELE"} & _PRE_AUTH_COMMANDS


class TestPortReclaimWithConnectedClient:
    """The port must come back even when a client is sitting on it."""

    async def test_connected_but_silent_client_does_not_pin_the_port(
        self, temp_certs, monkeypatch
    ):
        # Regression: clients connect on receipt of the 227, before sending the
        # transfer command. If none followed, the handler parked forever and
        # Server.wait_closed() blocked on it, so the supervisor never reached
        # its finally and the port never returned. Ten of those exhausted the
        # default pool and every later PASV got 425.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ENDPOINT_TIMEOUT", 0.3)

        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            bind_address="127.0.0.1",
            printer_cert_path=cert,
            data_port_start=21985,
            data_port_end=21985,
        )
        session = ControlSession(proxy, None, _StubWriter())
        port = await session._open_passive_relay()

        # Client connects and then says nothing at all.
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.1)
        assert len(session._data_handlers) == 1

        # The supervisor must finish on its own, without _cancel_data_relay.
        await asyncio.wait_for(session._data_task, timeout=5)
        assert proxy.data_ports.available == 1, "port pinned by a parked handler"

        writer.close()
        with contextlib.suppress(ConnectionResetError, OSError):
            await writer.wait_closed()


class TestStallWatchdog:
    """A wedged transfer must not hold the printer slot indefinitely."""

    async def test_silent_transfer_is_aborted(self, monkeypatch):
        # Regression: nothing bounded an established transfer. A client that
        # vanished without a FIN - or the P1S never answering close_notify,
        # which is documented behaviour - left both pumps blocked in read()
        # while the control side waited an hour for the 226, holding the only
        # printer slot the whole time.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_STALL_TIMEOUT", 0.3)
        monkeypatch.setattr(module, "DATA_STALL_CHECK", 0.1)

        # Two connected socket pairs that never send anything.
        left = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        right = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        try:
            lr, lw = await asyncio.open_connection(
                "127.0.0.1", left.sockets[0].getsockname()[1]
            )
            rr, rw = await asyncio.open_connection(
                "127.0.0.1", right.sockets[0].getsockname()[1]
            )
            await asyncio.wait_for(module._pipe_both_ways(lr, lw, rr, rw), timeout=5)
        finally:
            left.close()
            right.close()
            await left.wait_closed()
            await right.wait_closed()


class TestDataPortPeerCheck:
    """Only the host holding the control session may use the data port."""

    def _proxy(self, temp_certs, port):
        cert, key = temp_certs
        return FTPProxy(
            printer_ip="127.0.0.1",
            access_code="x",
            cert_path=cert,
            key_path=key,
            bind_address="127.0.0.1",
            printer_cert_path=cert,
            data_port_start=port,
            data_port_end=port,
        )

    async def test_connection_from_another_host_is_dropped(self, temp_certs):
        # The pooled port is reachable by anyone on the LAN for the length of
        # the accept window. A stranger used to be piped straight into the
        # printer's data channel.
        proxy = self._proxy(temp_certs, 21986)
        # The control session claims to come from a different host.
        session = ControlSession(proxy, None, _StubWriter(peer_ip="10.9.9.9"))
        port = await session._open_passive_relay()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Refused: the relay closes without ever registering a handler.
            assert await asyncio.wait_for(reader.read(), timeout=5) == b""
            assert not session._data_handlers
            writer.close()
            with contextlib.suppress(ConnectionResetError, OSError):
                await writer.wait_closed()
        finally:
            await session._cancel_data_relay()

    async def test_second_connection_is_dropped(self, temp_certs, monkeypatch):
        # A second handler would await the same endpoint and dial the
        # printer's single passive port too, able to beat the real client.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_ENDPOINT_TIMEOUT", 5.0)
        proxy = self._proxy(temp_certs, 21987)
        session = ControlSession(proxy, None, _StubWriter())
        port = await session._open_passive_relay()
        try:
            _r1, w1 = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.1)
            assert len(session._data_handlers) == 1

            r2, w2 = await asyncio.open_connection("127.0.0.1", port)
            assert await asyncio.wait_for(r2.read(), timeout=5) == b""
            assert len(session._data_handlers) == 1, "a second handler was admitted"

            for writer in (w1, w2):
                writer.close()
                with contextlib.suppress(ConnectionResetError, OSError):
                    await writer.wait_closed()
        finally:
            await session._cancel_data_relay()


class TestTransferIsNotTruncated:
    """A direction that carried bytes must never be cut short."""

    async def test_upload_survives_the_printer_half_closing(self, monkeypatch):
        # Regression: FTP servers commonly close their send side of the data
        # socket right after accepting a STOR, since they send nothing on an
        # upload. That made the printer->client pump finish first, and the
        # grace then cancelled the *upload* pump after 5s - write_eof() gave
        # the printer a clean end of file and it returned 226 for a partial
        # 3MF. Silent corruption.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_DRAIN_GRACE", 0.2)
        monkeypatch.setattr(module, "DATA_STALL_TIMEOUT", 30.0)

        payload = b"x" * (256 * 1024)
        received = bytearray()
        done = asyncio.Event()

        async def printer_side(reader, writer):
            # Nothing to send on an upload: half-close immediately.
            writer.write_eof()
            while chunk := await reader.read(8192):
                received.extend(chunk)
                # Slow enough that a 0.2s grace would have cut it off.
                await asyncio.sleep(0.02)
            done.set()
            writer.close()

        printer = await asyncio.start_server(printer_side, "127.0.0.1", 0)
        printer_port = printer.sockets[0].getsockname()[1]

        async def client_side(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.write_eof()

        client = await asyncio.start_server(client_side, "127.0.0.1", 0)
        client_port = client.sockets[0].getsockname()[1]

        try:
            cr, cw = await asyncio.open_connection("127.0.0.1", client_port)
            ur, uw = await asyncio.open_connection("127.0.0.1", printer_port)
            await asyncio.wait_for(module._pipe_both_ways(cr, cw, ur, uw), timeout=30)
            await asyncio.wait_for(done.wait(), timeout=5)
            assert len(received) == len(payload), (
                f"upload truncated: {len(received)} of {len(payload)} bytes"
            )
        finally:
            printer.close()
            client.close()
            await printer.wait_closed()
            await client.wait_closed()


class TestAbortDoesNotLookLikeSuccess:
    """A truncated transfer must never be signalled as a clean end of file."""

    async def test_cancelled_pump_resets_instead_of_half_closing(self, monkeypatch):
        # Regression: pump's finally called write_eof() unconditionally, so an
        # aborted upload reached the printer as a clean EOF and it answered
        # 226 for a partial 3MF - the file then looked intact in the listing.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_STALL_TIMEOUT", 0.3)
        monkeypatch.setattr(module, "DATA_STALL_CHECK", 0.1)

        saw_clean_eof = asyncio.Event()

        async def printer_side(reader, writer):
            # A clean half-close from the client shows up here as EOF.
            if await reader.read() == b"":
                pass
            if reader.at_eof():
                saw_clean_eof.set()
            writer.close()

        async def client_side(reader, writer):
            # Hold the connection open: a handler that returns lets asyncio
            # close the socket, and the pump would then see a legitimate EOF.
            with contextlib.suppress(Exception):
                await reader.read()
            writer.close()

        printer = await asyncio.start_server(printer_side, "127.0.0.1", 0)
        client = await asyncio.start_server(client_side, "127.0.0.1", 0)
        try:
            cr, cw = await asyncio.open_connection(
                "127.0.0.1", client.sockets[0].getsockname()[1]
            )
            ur, uw = await asyncio.open_connection(
                "127.0.0.1", printer.sockets[0].getsockname()[1]
            )
            # Nobody sends anything: the stall watchdog aborts the transfer.
            await asyncio.wait_for(module._pipe_both_ways(cr, cw, ur, uw), timeout=10)
            await asyncio.sleep(0.2)
            assert not saw_clean_eof.is_set(), (
                "an aborted transfer was half-closed as if it had completed"
            )
        finally:
            # The relay closes both writers in production; here we are calling
            # _pipe_both_ways directly, so the stubs need releasing by hand.
            for writer in (cw, uw):
                with contextlib.suppress(Exception):
                    writer.close()
            printer.close()
            client.close()
            await printer.wait_closed()
            await client.wait_closed()


class TestIdleClockTracksPrinterUse:
    """Locally-answered commands must not keep a printer session alive."""

    def test_local_commands_do_not_touch_the_clock(self, temp_certs):
        # Regression: the idle timer was reset by every command, so a client
        # sending NOOP every 20s held the only printer slot forever.
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        session = ControlSession(proxy, None, _StubWriter())
        assert session._upstream_last_used == 0.0


class TestPipeReportsVolume:
    """The control side needs to know whether anything was transferred."""

    async def test_returns_the_byte_count(self, monkeypatch):
        # Drives the completion grace: nothing transferred means the 226 is
        # never coming, while a printer that received a large file may still
        # be committing it and deserves the long wait.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_DRAIN_GRACE", 0.2)
        payload = b"y" * 4096

        async def sender(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.write_eof()

        async def sink(reader, writer):
            with contextlib.suppress(Exception):
                await reader.read()
            writer.close()

        src = await asyncio.start_server(sender, "127.0.0.1", 0)
        dst = await asyncio.start_server(sink, "127.0.0.1", 0)
        try:
            cr, cw = await asyncio.open_connection(
                "127.0.0.1", src.sockets[0].getsockname()[1]
            )
            ur, uw = await asyncio.open_connection(
                "127.0.0.1", dst.sockets[0].getsockname()[1]
            )
            moved = await asyncio.wait_for(
                module._pipe_both_ways(cr, cw, ur, uw), timeout=10
            )
            assert moved == len(payload)
        finally:
            for writer in (cw, uw):
                with contextlib.suppress(Exception):
                    writer.close()
            src.close()
            dst.close()
            await src.wait_closed()
            await dst.wait_closed()

    async def test_returns_zero_when_nothing_moves(self, monkeypatch):
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_STALL_TIMEOUT", 0.2)
        monkeypatch.setattr(module, "DATA_STALL_CHECK", 0.1)

        async def hold(reader, writer):
            with contextlib.suppress(Exception):
                await reader.read()
            writer.close()

        a = await asyncio.start_server(hold, "127.0.0.1", 0)
        b = await asyncio.start_server(hold, "127.0.0.1", 0)
        try:
            cr, cw = await asyncio.open_connection(
                "127.0.0.1", a.sockets[0].getsockname()[1]
            )
            ur, uw = await asyncio.open_connection(
                "127.0.0.1", b.sockets[0].getsockname()[1]
            )
            assert (
                await asyncio.wait_for(
                    module._pipe_both_ways(cr, cw, ur, uw), timeout=10
                )
                == 0
            )
        finally:
            for writer in (cw, uw):
                with contextlib.suppress(Exception):
                    writer.close()
            a.close()
            b.close()
            await a.wait_closed()
            await b.wait_closed()


class TestQueuedClientGivingUp:
    """A client that leaves while queued must free its place."""

    async def test_departed_client_abandons_its_turn(self, temp_certs):
        # Regression: nothing read the control socket during the queue wait,
        # so a client that disconnected kept its place and then spent a whole
        # printer session - TLS connect, login, replay - discovering the
        # socket was dead.
        import pandaproxy.ftp_proxy as module

        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        # Occupy the only slot.
        await proxy.queue.acquire()

        # A reader that is already at EOF stands in for a departed client.
        reader = asyncio.StreamReader()
        reader.feed_eof()
        session = module.ControlSession(proxy, reader, _StubWriter())

        granted = await asyncio.wait_for(
            session._acquire_slot(module.PRIORITY_NORMAL), timeout=5
        )
        assert granted is False, "a departed client was still given the slot"
        assert proxy.queue.waiting == 0, "it kept its place in the queue"

    async def test_live_client_still_gets_the_slot(self, temp_certs):
        import pandaproxy.ftp_proxy as module

        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        reader = asyncio.StreamReader()  # open, nothing pending
        session = module.ControlSession(proxy, reader, _StubWriter())

        assert await asyncio.wait_for(
            session._acquire_slot(module.PRIORITY_NORMAL), timeout=5
        )
        assert proxy.queue.active == 1


class TestStateLoss:
    """A refused replay must not silently leave a wrong session setting."""

    def _session(self, temp_certs):
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )
        return ControlSession(proxy, None, _StubWriter())

    def test_starts_clean(self, temp_certs):
        assert self._session(temp_certs)._lost_settings == set()

    def test_only_the_lost_setting_clears_it(self, temp_certs):
        # Regression: a single boolean was cleared by re-issuing *any* stateful
        # command, so a client that lost TYPE could clear it with a PBSZ and
        # then upload a 3MF in ASCII believing it was binary. The earlier test
        # asserted that behaviour, which is worse than having no test.
        session = self._session(temp_certs)
        session._lost_settings.add("TYPE")

        # A directory change says nothing about the transfer mode.
        session._record_cwd("/cache")
        assert session._lost_settings == {"TYPE"}
        assert session._cwd == "/cache"

    def test_a_directory_change_clears_a_lost_directory(self, temp_certs):
        session = self._session(temp_certs)
        session._lost_settings.add("CWD")
        session._record_cwd("/cache")
        assert session._lost_settings == set()

    def test_several_losses_are_tracked_independently(self, temp_certs):
        session = self._session(temp_certs)
        session._lost_settings.update({"TYPE", "CWD"})
        session._record_cwd("/model")
        assert session._lost_settings == {"TYPE"}


class TestPortValidation:
    """A port that cannot be dialled must be rejected by the parser."""

    def test_epsv_rejects_out_of_range(self):
        # It reached open_connection as an OverflowError, which is not an
        # OSError and escaped the relay's handler.
        from pandaproxy.ftp_proxy import parse_epsv_reply

        assert parse_epsv_reply("229 (|||99999999|)\r\n") is None
        assert parse_epsv_reply("229 (|||-1|)\r\n") is None
        assert parse_epsv_reply("229 (|||0|)\r\n") is None
        assert parse_epsv_reply("229 (|||2026|)\r\n") == 2026

    def test_pasv_rejects_port_zero(self):
        from pandaproxy.ftp_proxy import parse_pasv_reply

        assert parse_pasv_reply("227 (192,168,1,18,0,0)\r\n") is None
        assert parse_pasv_reply("227 (192,168,1,18,7,234)\r\n") is not None


class TestDownloadEndsCleanly:
    """A finished download must not be punished with a reset."""

    async def test_printer_socket_is_not_reset_after_a_download(self, monkeypatch):
        # Regression: resetting on "is toward the printer" fired on the normal
        # completion path of every download - the printer sends and closes, the
        # idle upstream pump is cancelled, and the RST landed just as it was
        # about to emit 226, turning healthy transfers into 426.
        #
        # The assertion is on the decision, not on observed TCP behaviour: an
        # earlier version of this test watched for ECONNRESET on the peer and
        # passed under both rules, so it proved nothing.
        import pandaproxy.ftp_proxy as module

        monkeypatch.setattr(module, "DATA_DRAIN_GRACE", 0.2)
        monkeypatch.setattr(module, "DATA_STALL_TIMEOUT", 30.0)

        reset_calls: list[object] = []
        monkeypatch.setattr(module, "_force_reset", reset_calls.append)

        payload = b"z" * 8192
        # Released in the finally, so the stub holds its socket for exactly as
        # long as the test needs rather than a fixed sleep.
        release = asyncio.Event()

        async def printer_side(reader, writer):
            # A download: send, then close our side.
            writer.write(payload)
            await writer.drain()
            writer.write_eof()
            with contextlib.suppress(Exception):
                await reader.read()
            writer.close()

        async def client_side(reader, writer):
            # Read the file, then hold the socket open like a client still in
            # unwrap(). Closing here would hand the upstream pump a legitimate
            # EOF and the cancellation path would never be exercised.
            with contextlib.suppress(Exception):
                await reader.read(len(payload))
            with contextlib.suppress(Exception):
                await release.wait()

        printer = await asyncio.start_server(printer_side, "127.0.0.1", 0)
        client = await asyncio.start_server(client_side, "127.0.0.1", 0)
        try:
            cr, cw = await asyncio.open_connection(
                "127.0.0.1", client.sockets[0].getsockname()[1]
            )
            ur, uw = await asyncio.open_connection(
                "127.0.0.1", printer.sockets[0].getsockname()[1]
            )
            moved = await asyncio.wait_for(
                module._pipe_both_ways(cr, cw, ur, uw), timeout=20
            )
            assert moved == len(payload)
            assert uw not in reset_calls, (
                "a completed download reset the printer's data socket"
            )
            assert reset_calls == [], f"unexpected resets: {reset_calls}"
        finally:
            release.set()
            for writer in (cw, uw):
                with contextlib.suppress(Exception):
                    writer.close()
            printer.close()
            client.close()
            await printer.wait_closed()
            await client.wait_closed()
