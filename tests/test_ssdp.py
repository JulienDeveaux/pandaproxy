"""Tests for the SSDP announcements that make a slicer see the proxy."""

import asyncio

import pytest

from pandaproxy.ssdp import (
    BROADCAST,
    DEFAULT_INTERVAL,
    SSDP_PORT,
    SsdpAnnouncer,
    build_announcement,
)

IP = "192.168.1.66"
SERIAL = "01P00C541700323"


def headers(payload: bytes) -> dict[str, str]:
    """Parse the announcement into a header map."""
    text = payload.decode()
    out: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        out[name.strip()] = value.strip()
    return out


class TestAnnouncementShape:
    """The exact header set BambuStudio accepts."""

    def test_is_an_http_response_not_a_notify(self):
        # The printer sends a 200 response; Studio's parser expects that.
        assert build_announcement(IP, SERIAL).startswith(b"HTTP/1.1 200 OK\r\n")

    def test_ends_with_a_blank_line(self):
        assert build_announcement(IP, SERIAL).endswith(b"\r\n\r\n")

    def test_location_is_a_bare_address(self):
        # Not a URL: Studio dials this verbatim.
        assert headers(build_announcement(IP, SERIAL))["Location"] == IP

    def test_usn_is_the_serial(self):
        assert headers(build_announcement(IP, SERIAL))["USN"] == SERIAL

    def test_search_target_identifies_a_bambu_printer(self):
        found = headers(build_announcement(IP, SERIAL))["ST"]
        assert found == "urn:bambulab-com:device:3dprinter:1"

    def test_every_header_the_parser_knows_is_present(self):
        # libbambu_networking.dylib lists eight; examples that send five are
        # why the printer shows up and then refuses to connect.
        present = headers(build_announcement(IP, SERIAL))
        for name in (
            "DevModel",
            "DevName",
            "DevSignal",
            "DevConnect",
            "DevBind",
            "Devseclink",
            "DevInf",
            "DevVersion",
        ):
            assert f"{name}.bambu.com" in present, f"{name} missing"

    def test_devinf_is_empty(self):
        # Measured: an address here makes Studio reject the device instantly,
        # without opening a socket. This was the entire cause of "code -1".
        assert headers(build_announcement(IP, SERIAL))["DevInf.bambu.com"] == ""

    def test_model_defaults_to_the_p1s_code(self):
        assert headers(build_announcement(IP, SERIAL))["DevModel.bambu.com"] == "C12"

    def test_version_is_carried_through(self):
        payload = build_announcement(IP, SERIAL, dev_version="01.09.01.00")
        assert headers(payload)["DevVersion.bambu.com"] == "01.09.01.00"

    def test_name_is_carried_through(self):
        payload = build_announcement(IP, SERIAL, dev_name="Workshop Proxy")
        assert headers(payload)["DevName.bambu.com"] == "Workshop Proxy"


class TestAnnouncerDelivery:
    """Datagrams actually reach the configured targets."""

    async def test_sends_to_each_target(self):
        import socket

        listeners = []
        try:
            for _ in range(2):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("127.0.0.1", 0))
                s.settimeout(2)
                listeners.append(s)

            # Aim at the bound ports by patching the module's port constant.
            import pandaproxy.ssdp as module

            ports = [s.getsockname()[1] for s in listeners]
            original = module.SSDP_PORT
            try:
                # One announcer per port, since the port is module-level.
                for port, listener in zip(ports, listeners, strict=True):
                    module.SSDP_PORT = port
                    announcer = SsdpAnnouncer(IP, SERIAL, targets=["127.0.0.1"])
                    announcer.start()
                    assert announcer.announce_once() == 1
                    announcer.stop()
                    data, _ = listener.recvfrom(4096)
                    assert headers(data)["USN"] == SERIAL
            finally:
                module.SSDP_PORT = original
        finally:
            for s in listeners:
                s.close()

    def test_defaults_to_broadcast(self):
        assert SsdpAnnouncer(IP, SERIAL).targets == [BROADCAST]
        assert SSDP_PORT == 2021

    def test_counts_what_it_sent(self):
        announcer = SsdpAnnouncer(IP, SERIAL, targets=["127.0.0.1", "127.0.0.2"])
        announcer.start()
        try:
            assert announcer.announce_once() == 2
            assert announcer.sent == 2
        finally:
            announcer.stop()

    def test_sending_without_start_is_a_no_op(self):
        assert SsdpAnnouncer(IP, SERIAL).announce_once() == 0

    async def test_run_keeps_announcing_until_cancelled(self):
        announcer = SsdpAnnouncer(IP, SERIAL, targets=["127.0.0.1"], interval=0.05)
        announcer.start()
        task = asyncio.create_task(announcer.run())
        await asyncio.sleep(0.25)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        announcer.stop()
        # Studio drops a device whose announcements stop, so this has to be a
        # steady heartbeat rather than a single shot.
        assert announcer.sent >= 3

    def test_interval_default_outpaces_the_printer(self):
        assert DEFAULT_INTERVAL <= 5.0
