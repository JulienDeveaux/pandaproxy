"""Tests for the queueing FTPS proxy.

The integration tests run a stand-in printer that speaks just enough FTP to
exercise the paths that matter: login, passive transfers, and how many
sessions the proxy actually opens against it.
"""

import asyncio
import contextlib
import ssl

import pytest

from pandaproxy.ftp_proxy import (
    ControlSession,
    FTPProxy,
    format_epsv_reply,
    format_pasv_reply,
    parse_epsv_reply,
    parse_pasv_reply,
)
from pandaproxy.ftp_queue import PRIORITY_NORMAL, PRIORITY_UPLOAD

ACCESS_CODE = "testcode"
DATA_PORT_START = 21000
DATA_PORT_END = 21010


class TestPasvParsing:
    """Parsing and rendering of passive-mode replies."""

    def test_parses_a_real_p1s_reply(self):
        # Captured from a P1S: port 7*256+234 = 2026.
        assert parse_pasv_reply("227 (192,168,1,18,7,234)\r\n") == (
            "192.168.1.18",
            2026,
        )

    def test_parses_the_verbose_form(self):
        reply = "227 Entering Passive Mode (10,0,0,5,4,1)\r\n"
        assert parse_pasv_reply(reply) == ("10.0.0.5", 1025)

    @pytest.mark.parametrize(
        "reply",
        [
            "227 no parentheses\r\n",
            "227 (1,2,3)\r\n",
            "227 (1,2,3,4,5,6,7)\r\n",
            "227 (a,b,c,d,e,f)\r\n",
            "227 (1,2,3,4,5,999)\r\n",
            "227 (\r\n",
        ],
    )
    def test_rejects_malformed_replies(self, reply):
        assert parse_pasv_reply(reply) is None

    def test_round_trips(self):
        rendered = format_pasv_reply("192.168.1.50", 2026)
        assert parse_pasv_reply(rendered) == ("192.168.1.50", 2026)

    def test_format_ends_with_crlf(self):
        assert format_pasv_reply("127.0.0.1", 2000).endswith("\r\n")


class TestEpsvParsing:
    """Parsing and rendering of extended passive replies."""

    def test_parses_standard_reply(self):
        assert (
            parse_epsv_reply("229 Entering Extended Passive Mode (|||2026|)\r\n")
            == 2026
        )

    def test_accepts_alternative_delimiter(self):
        assert parse_epsv_reply("229 Entering (!!!2026!)\r\n") == 2026

    @pytest.mark.parametrize(
        "reply",
        ["229 no parens\r\n", "229 ()\r\n", "229 (|||abc|)\r\n", "229 (||)\r\n"],
    )
    def test_rejects_malformed_replies(self, reply):
        assert parse_epsv_reply(reply) is None

    def test_round_trips(self):
        assert parse_epsv_reply(format_epsv_reply(2026)) == 2026


class FakePrinterFTP:
    """Minimal FTP server standing in for a BambuLab printer."""

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        self.ssl_context = ssl_context
        self.server: asyncio.Server | None = None
        self.port = 0
        # Observability for the queueing assertions.
        self.sessions_opened = 0
        self.concurrent = 0
        self.max_concurrent_seen = 0
        self.commands: list[str] = []
        self.uploads: dict[str, bytes] = {}
        self.listing = b"drwxr-xr-x 2 root root 0 Jan 1 00:00 cache\r\n"
        self.missing_dirs: set[str] = set()
        self.hold = asyncio.Event()
        self.hold.set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, ssl=self.ssl_context
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.sessions_opened += 1
        self.concurrent += 1
        self.max_concurrent_seen = max(self.max_concurrent_seen, self.concurrent)

        data_server: asyncio.Server | None = None
        pending: asyncio.Future | None = None

        async def reply(text: str) -> None:
            writer.write(text.encode())
            await writer.drain()

        try:
            await reply("220 Fake Bambu FTP\r\n")
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                line = raw.decode().strip()
                self.commands.append(line)
                command, _, argument = line.partition(" ")
                command = command.upper()

                if command == "USER":
                    await reply("331 Password required\r\n")
                elif command == "PASS":
                    await reply("230 Login successful\r\n")
                elif command == "CWD":
                    if argument in self.missing_dirs:
                        await reply("550 No such directory\r\n")
                    else:
                        await reply("250 Directory changed\r\n")
                elif command in {"PBSZ", "PROT", "TYPE"}:
                    await reply(f"200 {command} ok\r\n")
                elif command == "PASV":
                    loop = asyncio.get_running_loop()
                    pending = loop.create_future()

                    async def on_data(r, w, fut=pending):
                        if not fut.done():
                            fut.set_result((r, w))

                    data_server = await asyncio.start_server(on_data, "127.0.0.1", 0)
                    dport = data_server.sockets[0].getsockname()[1]
                    await reply(
                        f"227 Entering Passive Mode (127,0,0,1,{dport // 256},{dport % 256})\r\n"
                    )
                elif command in {"LIST", "STOR"}:
                    if pending is None:
                        await reply("425 Use PASV first\r\n")
                        continue
                    await reply("150 Opening data connection\r\n")
                    # Lets a test keep a transfer in flight to create contention.
                    await self.hold.wait()
                    dreader, dwriter = await asyncio.wait_for(pending, timeout=5)
                    if command == "LIST":
                        dwriter.write(self.listing)
                        await dwriter.drain()
                        dwriter.close()
                    else:
                        self.uploads[argument] = await dreader.read()
                    if data_server:
                        data_server.close()
                        data_server = None
                    pending = None
                    await reply("226 Transfer complete\r\n")
                elif command == "QUIT":
                    await reply("221 Goodbye\r\n")
                    break
                else:
                    await reply("502 Not implemented\r\n")
        except ConnectionResetError, ssl.SSLError, asyncio.IncompleteReadError:
            pass
        finally:
            self.concurrent -= 1
            if data_server:
                data_server.close()
            writer.close()


class FTPTestClient:
    """Tiny FTP client that talks to the proxy over TLS."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    @classmethod
    async def connect(cls, port: int) -> FTPTestClient:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
        client = cls(reader, writer)
        await client.read_reply()  # greeting
        return client

    async def read_reply(self) -> str:
        line = (await asyncio.wait_for(self.reader.readline(), timeout=10)).decode()
        code = line[:3]
        if len(line) > 3 and line[3] == "-":
            while True:
                more = (await self.reader.readline()).decode()
                line += more
                if more.startswith(f"{code} ") or not more:
                    break
        return line

    async def command(self, text: str) -> str:
        self.writer.write(f"{text}\r\n".encode())
        await self.writer.drain()
        return await self.read_reply()

    async def login(self, code: str = ACCESS_CODE) -> str:
        await self.command("USER bblp")
        return await self.command(f"PASS {code}")

    async def close(self) -> None:
        self.writer.close()
        # A TLS peer closing mid-session routinely surfaces as a reset or a
        # dirty-shutdown SSLError; neither matters once we are tearing down.
        with contextlib.suppress(ConnectionResetError, ssl.SSLError, OSError):
            await self.writer.wait_closed()


@pytest.fixture
async def printer(temp_certs):
    cert_path, key_path = temp_certs
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server = FakePrinterFTP(ctx)
    await server.start()
    yield server
    await server.stop()


@pytest.fixture
async def proxy(printer, temp_certs):
    cert_path, key_path = temp_certs
    p = FTPProxy(
        printer_ip="127.0.0.1",
        access_code=ACCESS_CODE,
        cert_path=cert_path,
        key_path=key_path,
        bind_address="127.0.0.1",
        printer_cert_path=cert_path,
        port=0,
        printer_port=printer.port,
        data_port_start=DATA_PORT_START,
        data_port_end=DATA_PORT_END,
    )
    await p.start()
    yield p
    await p.stop()


class TestProxyLifecycle:
    """Startup, shutdown and configuration."""

    async def test_binds_and_reports_its_port(self, proxy):
        assert proxy.port != 0
        assert proxy.running

    async def test_stop_is_idempotent(self, proxy):
        await proxy.stop()
        await proxy.stop()
        assert not proxy.running

    async def test_missing_certificates_are_reported(self, tmp_path):
        p = FTPProxy(
            printer_ip="127.0.0.1",
            access_code=ACCESS_CODE,
            cert_path=tmp_path / "absent.crt",
            key_path=tmp_path / "absent.key",
            port=0,
        )
        with pytest.raises(FileNotFoundError, match="TLS certificates not found"):
            await p.start()


class TestLocalLogin:
    """Login is answered by the proxy, not the printer."""

    async def test_login_succeeds_without_opening_a_printer_session(
        self, proxy, printer
    ):
        client = await FTPTestClient.connect(proxy.port)
        reply = await client.login()

        assert reply.startswith("230")
        # The whole point: the client is logged in before the printer is
        # touched at all, so a busy printer can never surface as a failure.
        assert printer.sessions_opened == 0
        await client.close()

    async def test_wrong_access_code_is_rejected(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.command("USER bblp")
        reply = await client.command("PASS wrong-code")

        assert reply.startswith("530")
        assert printer.sessions_opened == 0
        await client.close()

    async def test_commands_before_login_are_refused(self, proxy):
        client = await FTPTestClient.connect(proxy.port)
        reply = await client.command("PASV")
        assert reply.startswith("530")
        await client.close()

    async def test_feat_works_before_login(self, proxy, printer):
        # lftp and others send FEAT straight after the implicit-TLS handshake;
        # refusing it loses them the PASV/EPSV advertisement (RFC 2389).
        client = await FTPTestClient.connect(proxy.port)
        reply = await client.command("FEAT")
        assert reply.startswith("211")
        assert "PASV" in reply
        assert printer.sessions_opened == 0
        await client.close()

    async def test_active_mode_is_refused_without_a_printer_session(
        self, proxy, printer
    ):
        # PORT would have the printer dial the client directly, bypassing the
        # proxy and the queue it exists for.
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("PORT 127,0,0,1,7,208")
        assert reply.startswith("502")
        assert printer.sessions_opened == 0
        await client.close()

    async def test_empty_command_costs_no_printer_session(self, proxy, printer):
        # A stray CRLF used to open a TLS connect plus login and hold the only
        # slot for 30s.
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        client.writer.write(b"\r\n")
        await client.writer.drain()
        assert (await client.read_reply()).startswith("500")
        assert printer.sessions_opened == 0
        await client.close()

    async def test_epsv_all_is_a_mode_declaration(self, proxy, printer):
        # EPSV ALL declares that only extended passive mode will be used; it
        # is not a request for a port, and echoing it upstream made every
        # later transfer fail with 425.
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("EPSV ALL")
        assert reply.startswith("200")
        assert proxy.data_ports.available == DATA_PORT_END - DATA_PORT_START + 1
        assert printer.sessions_opened == 0
        await client.close()

    async def test_feat_is_answered_locally(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("FEAT")
        assert reply.startswith("211")
        assert "PASV" in reply
        assert printer.sessions_opened == 0
        await client.close()


class TestPassiveTransfer:
    """PASV rewriting and data relay."""

    async def test_pasv_is_rewritten_to_the_proxy(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("PASV")

        endpoint = parse_pasv_reply(reply)
        assert endpoint is not None
        host, port = endpoint
        assert host == "127.0.0.1"
        # The advertised port must be one of ours, not the printer's.
        assert DATA_PORT_START <= port <= DATA_PORT_END
        assert port != printer.port
        await client.close()

    async def test_listing_flows_through_the_relay(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("PASV")
        _host, port = parse_pasv_reply(reply)

        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        preliminary = await client.command("LIST")
        assert preliminary.startswith("150")

        payload = await asyncio.wait_for(data_reader.read(), timeout=10)
        assert payload == printer.listing

        final = await client.read_reply()
        assert final.startswith("226")

        data_writer.close()
        await client.close()

    async def test_upload_reaches_the_printer(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        await client.command("TYPE I")
        reply = await client.command("PASV")
        _host, port = parse_pasv_reply(reply)

        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        preliminary = await client.command("STOR model.3mf")
        assert preliminary.startswith("150")

        data_writer.write(b"3MF-PAYLOAD" * 100)
        await data_writer.drain()
        data_writer.close()

        final = await client.read_reply()
        assert final.startswith("226")
        assert printer.uploads["model.3mf"] == b"3MF-PAYLOAD" * 100
        await client.close()

    async def test_cwd_is_decided_by_the_printer(self, proxy, printer):
        # Answering CWD locally would confirm a directory that may not exist,
        # and a later upload would silently land somewhere else.
        printer.missing_dirs.add("/nope")
        client = await FTPTestClient.connect(proxy.port)
        await client.login()

        assert (await client.command("CWD /nope")).startswith("550")
        assert (await client.command("CWD /cache")).startswith("250")
        assert "CWD /nope" in printer.commands
        await client.close()

    async def test_session_state_is_replayed_upstream(self, proxy, printer):
        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        # Set before any printer session exists: answered locally, recorded.
        assert (await client.command("TYPE I")).startswith("200")
        assert (await client.command("PROT P")).startswith("200")

        # PASV is answered locally too, so it must not reach the printer.
        reply = await client.command("PASV")
        assert reply.startswith("227")
        assert printer.sessions_opened == 0

        # The transfer command is what opens the session and replays state.
        _host, port = parse_pasv_reply(reply)
        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        assert (await client.command("LIST")).startswith("150")
        await asyncio.wait_for(data_reader.read(), timeout=10)
        assert (await client.read_reply()).startswith("226")

        assert "TYPE I" in printer.commands
        assert "PROT P" in printer.commands
        data_writer.close()
        await client.close()


class TestQueueing:
    """Only one session reaches the printer at a time."""

    async def test_second_client_waits_for_the_first(self, proxy, printer):
        printer.hold.clear()  # freeze the first transfer mid-flight

        first = await FTPTestClient.connect(proxy.port)
        await first.login()
        reply = await first.command("PASV")
        _host, port = parse_pasv_reply(reply)
        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        first.writer.write(b"LIST\r\n")
        await first.writer.drain()
        await asyncio.sleep(0.2)

        # A second client logs in and gets a passive port locally, but the
        # transfer itself must wait for the printer.
        second = await FTPTestClient.connect(proxy.port)
        await second.login()
        assert (await second.command("PASV")).startswith("227")
        second.writer.write(b"LIST\r\n")
        await second.writer.drain()

        with pytest.raises(TimeoutError):
            await asyncio.wait_for(second.read_reply(), timeout=0.5)
        assert proxy.queue.waiting == 1
        assert printer.max_concurrent_seen == 1

        # Let the first finish; the second is then served.
        printer.hold.set()
        await asyncio.wait_for(data_reader.read(), timeout=5)
        await first.command("QUIT")

        served = await asyncio.wait_for(second.read_reply(), timeout=10)
        assert served.startswith("150")
        assert printer.max_concurrent_seen == 1

        data_writer.close()
        await second.close()

    async def test_upload_claims_the_slot_at_upload_priority(self, proxy, printer):
        # Regression: the slot used to be taken by the PASV that necessarily
        # precedes STOR, so it was always acquired at PRIORITY_NORMAL and the
        # upload priority was unreachable for any real client.
        seen: list[int] = []
        original = proxy.queue.acquire

        async def record(priority=PRIORITY_NORMAL):
            seen.append(priority)
            await original(priority)

        proxy.queue.acquire = record

        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        await client.command("TYPE I")
        reply = await client.command("PASV")
        _host, port = parse_pasv_reply(reply)
        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        assert (await client.command("STOR model.3mf")).startswith("150")
        data_writer.write(b"payload")
        await data_writer.drain()
        data_writer.close()
        assert (await client.read_reply()).startswith("226")

        assert seen == [PRIORITY_UPLOAD], f"priorites utilisees: {seen}"
        assert printer.uploads["model.3mf"] == b"payload"
        del data_reader
        await client.close()

    async def test_listing_claims_the_slot_at_normal_priority(self, proxy, printer):
        seen: list[int] = []
        original = proxy.queue.acquire

        async def record(priority=PRIORITY_NORMAL):
            seen.append(priority)
            await original(priority)

        proxy.queue.acquire = record

        client = await FTPTestClient.connect(proxy.port)
        await client.login()
        reply = await client.command("PASV")
        _host, port = parse_pasv_reply(reply)
        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", port)
        await client.command("LIST")
        await asyncio.wait_for(data_reader.read(), timeout=10)
        await client.read_reply()

        assert seen == [PRIORITY_NORMAL]
        data_writer.close()
        await client.close()

    async def test_printer_stays_untouched_until_a_command_needs_it(
        self, proxy, printer
    ):
        clients = [await FTPTestClient.connect(proxy.port) for _ in range(3)]
        for client in clients:
            await client.login()
            await client.command("TYPE I")

        # Three logged-in clients, zero printer sessions.
        assert printer.sessions_opened == 0
        assert proxy.queue.active == 0

        for client in clients:
            await client.close()


class TestControlSessionUnits:
    """Behaviour that is easier to assert without a live connection."""

    async def test_local_ip_defaults_when_socket_info_is_absent(self, temp_certs):
        cert, key = temp_certs
        proxy = FTPProxy(
            printer_ip="127.0.0.1", access_code="x", cert_path=cert, key_path=key
        )

        class _Writer:
            def get_extra_info(self, name):
                return None

            def close(self):
                pass

        session = ControlSession(proxy, None, _Writer())
        assert session.local_ip == "127.0.0.1"
