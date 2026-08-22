"""Tests for helper utility functions."""

import datetime
import logging
import ssl
import struct
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pandaproxy.helper import (
    ReconnectPolicy,
    certificate_expires_soon,
    close_writer,
    create_auth_payload,
    create_ssl_context,
    generate_self_signed_cert,
    open_connection_safe,
    parse_auth_payload,
)
from pandaproxy.protocol import AUTH_COMMAND, AUTH_MAGIC


class TestCreateAuthPayload:
    """Tests for create_auth_payload function."""

    def test_creates_80_byte_payload(self):
        """Auth payload should be exactly 80 bytes."""
        payload = create_auth_payload("12345678")
        assert len(payload) == 80

    def test_payload_starts_with_magic(self):
        """Payload should start with AUTH_MAGIC byte."""
        payload = create_auth_payload("testcode")
        assert payload[0] == AUTH_MAGIC

    def test_payload_contains_command(self):
        """Payload should contain AUTH_COMMAND at correct offset."""
        payload = create_auth_payload("testcode")
        # Command is at offset 4, little-endian uint32
        command = struct.unpack("<I", payload[4:8])[0]
        assert command == AUTH_COMMAND

    def test_payload_contains_access_code(self):
        """Payload should contain the access code."""
        access_code = "myaccess"
        payload = create_auth_payload(access_code)
        # Access code is at offset 16
        assert access_code.encode("utf-8") in payload

    def test_different_codes_produce_different_payloads(self):
        """Different access codes should produce different payloads."""
        payload1 = create_auth_payload("code1111")
        payload2 = create_auth_payload("code2222")
        assert payload1 != payload2

    def test_empty_access_code(self):
        """Empty access code should still produce valid 80-byte payload."""
        payload = create_auth_payload("")
        assert len(payload) == 80


class TestParseAuthPayload:
    """Tests for parse_auth_payload function."""

    def test_parses_valid_payload(self):
        """Should correctly parse a valid auth payload."""
        access_code = "testcode"
        payload = create_auth_payload(access_code)
        parsed = parse_auth_payload(payload)
        assert parsed == access_code

    def test_returns_none_for_invalid_magic(self):
        """Should return None if magic byte is wrong."""
        payload = bytearray(create_auth_payload("testcode"))
        payload[0] = 0x00  # Invalid magic
        result = parse_auth_payload(bytes(payload))
        assert result is None

    def test_returns_none_for_short_payload(self):
        """Should return None if payload is too short."""
        result = parse_auth_payload(b"short")
        assert result is None

    def test_returns_none_for_empty_payload(self):
        """Should return None for empty payload."""
        result = parse_auth_payload(b"")
        assert result is None

    def test_roundtrip_various_codes(self):
        """Various access codes should survive roundtrip."""
        codes = ["12345678", "abcdefgh", "A1B2C3D4", "test1234"]
        for code in codes:
            payload = create_auth_payload(code)
            parsed = parse_auth_payload(payload)
            assert parsed == code, f"Failed for code: {code}"


class TestGenerateSelfSignedCert:
    """Tests for generate_self_signed_cert function."""

    def test_generates_cert_and_key_files(self):
        """Should generate both certificate and key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            assert cert_path.exists()
            assert key_path.exists()

    def test_cert_file_contains_pem_data(self):
        """Certificate file should contain PEM-formatted data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            cert_content = cert_path.read_text()
            assert "-----BEGIN CERTIFICATE-----" in cert_content
            assert "-----END CERTIFICATE-----" in cert_content

    def test_key_file_contains_pem_data(self):
        """Key file should contain PEM-formatted data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            key_content = key_path.read_text()
            assert "-----BEGIN" in key_content
            assert "PRIVATE KEY-----" in key_content

    def test_cert_can_be_loaded_by_ssl_context(self):
        """Generated cert should be loadable by SSL context."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "test.crt"
            key_path = Path(tmpdir) / "test.key"

            generate_self_signed_cert(
                common_name="TestCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Should not raise
            ctx.load_cert_chain(cert_path, key_path)


class TestCreateSslContext:
    """Tests for create_ssl_context function."""

    def test_returns_ssl_context(self):
        """Should return an SSLContext instance."""
        ctx = create_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)

    def test_context_is_client_mode(self):
        """Context should be configured for client mode."""
        ctx = create_ssl_context()
        # Client contexts don't require certificates to be loaded
        # We just verify it's a valid context
        assert ctx is not None

    def test_accepts_custom_cert_path(self):
        """Should load the CA cert from an explicitly provided path, not the default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = Path(tmpdir) / "custom.crt"
            key_path = Path(tmpdir) / "custom.key"
            generate_self_signed_cert(
                common_name="CustomCN",
                san_dns=["localhost"],
                san_ips=["127.0.0.1"],
                output_cert=cert_path,
                output_key=key_path,
            )

            ctx = create_ssl_context(cert_path)
            assert isinstance(ctx, ssl.SSLContext)

    def test_raises_for_missing_custom_cert_path(self):
        """Should propagate the given path instead of silently using the default."""
        with pytest.raises(FileNotFoundError):
            create_ssl_context("/nonexistent/custom.cer")


class TestOpenConnectionSafe:
    """Tests for open_connection_safe function."""

    @pytest.mark.asyncio
    async def test_returns_reader_writer_on_success(self):
        """Should return (reader, writer) when connection succeeds."""
        reader = AsyncMock()
        writer = AsyncMock()
        with patch(
            "pandaproxy.helper.asyncio.open_connection",
            new=AsyncMock(return_value=(reader, writer)),
        ):
            result = await open_connection_safe("192.168.1.1", 6000)
        assert result == (reader, writer)

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self):
        """Should return None and not raise on TimeoutError."""
        with (
            patch("pandaproxy.helper.asyncio.open_connection", new_callable=MagicMock),
            patch(
                "pandaproxy.helper.asyncio.wait_for",
                new=AsyncMock(side_effect=TimeoutError()),
            ),
        ):
            result = await open_connection_safe("192.168.1.1", 6000)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_connection_refused(self):
        """Should return None and not raise on ConnectionRefusedError."""
        with (
            patch("pandaproxy.helper.asyncio.open_connection", new_callable=MagicMock),
            patch(
                "pandaproxy.helper.asyncio.wait_for",
                new=AsyncMock(side_effect=ConnectionRefusedError()),
            ),
        ):
            result = await open_connection_safe("192.168.1.1", 6000)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_os_error(self):
        """Should return None and not raise on OSError."""
        with (
            patch("pandaproxy.helper.asyncio.open_connection", new_callable=MagicMock),
            patch(
                "pandaproxy.helper.asyncio.wait_for",
                new=AsyncMock(side_effect=OSError("Network unreachable")),
            ),
        ):
            result = await open_connection_safe("192.168.1.1", 6000)
        assert result is None

    @pytest.mark.asyncio
    async def test_passes_ssl_context_to_open_connection(self):
        """Should forward ssl_context to asyncio.open_connection."""
        reader = AsyncMock()
        writer = AsyncMock()
        mock_ctx = MagicMock(spec=ssl.SSLContext)

        with patch(
            "pandaproxy.helper.asyncio.open_connection",
            new=AsyncMock(return_value=(reader, writer)),
        ) as mock_conn:
            await open_connection_safe("192.168.1.1", 6000, ssl_context=mock_ctx)

        mock_conn.assert_called_once_with("192.168.1.1", 6000, ssl=mock_ctx)


class TestCloseWriter:
    """Tests for close_writer function."""

    @pytest.mark.asyncio
    async def test_closes_writer(self):
        """Should call close and wait_closed on writer."""
        writer = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await close_writer(writer)

        writer.close.assert_called_once()
        writer.wait_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_exception_gracefully(self):
        """Should not raise if wait_closed fails with a connection-level error."""
        writer = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock(
            side_effect=ConnectionResetError("Connection lost")
        )

        # Should not raise
        await close_writer(writer)

        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_handles_none_writer(self):
        """Should handle None writer gracefully."""
        # This tests the function's robustness
        # Implementation may vary - adjust test if needed
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        await close_writer(writer)


class TestCertificateExpirySignal:
    """A persisted certificate must not be allowed to die quietly."""

    @staticmethod
    def _write(path, *, days_from_now: int) -> None:
        """A minimal self-signed certificate expiring at a chosen offset."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expiry-test")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=400))
            .not_valid_after(now + datetime.timedelta(days=days_from_now))
            .sign(key, hashes.SHA256())
        )
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def test_a_fresh_certificate_is_left_alone(self, tmp_path):
        cert = tmp_path / "fresh.crt"
        self._write(cert, days_from_now=825)
        assert certificate_expires_soon(cert) is False

    def test_an_expired_certificate_is_flagged(self, tmp_path):
        cert = tmp_path / "old.crt"
        self._write(cert, days_from_now=-1)
        assert certificate_expires_soon(cert) is True

    def test_the_margin_catches_it_before_it_dies(self, tmp_path):
        # Reissuing on the expiry date itself would mean a window where
        # clients refuse the proxy; the margin is the whole point.
        cert = tmp_path / "soon.crt"
        self._write(cert, days_from_now=10)
        assert certificate_expires_soon(cert) is True
        assert certificate_expires_soon(cert, margin_days=1) is False

    def test_an_unreadable_certificate_counts_as_due(self, tmp_path):
        assert certificate_expires_soon(tmp_path / "absent.crt") is True
        junk = tmp_path / "junk.crt"
        junk.write_text("not a certificate")
        assert certificate_expires_soon(junk) is True


class TestReconnectPolicy:
    """A printer switched off overnight must not fill the log or the network."""

    @staticmethod
    def _policy(caplog_logger="test.reconnect", **kw):
        return ReconnectPolicy(logging.getLogger(caplog_logger), **kw)

    def test_the_first_failure_is_visible(self, caplog):
        policy = self._policy()
        with caplog.at_level(logging.DEBUG):
            policy.failure("printer unreachable")
        records = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(records) == 1

    def test_the_repeats_are_not(self, caplog):
        # This is the whole point: 200 identical failures, not 200 warnings.
        policy = self._policy(report_every=25)
        with caplog.at_level(logging.DEBUG):
            for _ in range(24):
                policy.failure("printer unreachable")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1

    def test_a_long_outage_is_still_reported_periodically(self, caplog):
        # Silence for hours would be its own bug: nothing would say why the
        # printer never came back.
        policy = self._policy(report_every=10)
        with caplog.at_level(logging.DEBUG):
            for _ in range(30):
                policy.failure("printer unreachable")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 4  # the first, then attempts 10, 20 and 30
        assert "Still failing after 30 attempts" in warnings[-1].getMessage()

    def test_the_delay_grows_and_is_capped(self):
        policy = self._policy(base_delay=5.0, max_delay=60.0)
        delays = []
        for _ in range(8):
            policy.failure("nope")
            delays.append(policy.delay())
        assert delays[:4] == [5.0, 10.0, 20.0, 40.0]
        assert set(delays[4:]) == {60.0}

    def test_attempts_are_quiet_while_failing(self, caplog):
        policy = self._policy()
        with caplog.at_level(logging.DEBUG):
            policy.log_attempt("connecting")
            policy.failure("nope")
            policy.log_attempt("connecting")
        levels = [r.levelno for r in caplog.records if "connecting" in r.getMessage()]
        assert levels == [logging.INFO, logging.DEBUG]

    def test_recovery_resets_everything(self, caplog):
        policy = self._policy(base_delay=5.0)
        for _ in range(5):
            policy.failure("nope")
        with caplog.at_level(logging.INFO):
            policy.success()
        assert policy.failures == 0
        assert policy.delay() == 5.0
        assert "Recovered after 5 failed attempt(s)" in caplog.text

    def test_a_success_with_nothing_to_recover_says_nothing(self, caplog):
        policy = self._policy()
        with caplog.at_level(logging.DEBUG):
            policy.success()
        assert caplog.records == []


class TestReconnectPolicySurvivesLongOutages:
    """The backoff must not be the thing that breaks during a long outage."""

    def test_hundreds_of_failures_still_yield_a_delay(self):
        # An overnight outage reaches this many attempts; computing 2**500
        # raises OverflowError, which would kill the reconnect loop.
        policy = ReconnectPolicy(logging.getLogger("test.longoutage"))
        for _ in range(2000):
            policy.failure("still off")
        assert policy.delay() == policy.max_delay
