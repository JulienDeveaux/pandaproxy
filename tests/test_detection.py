"""Tests for camera type detection."""

import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pandaproxy.detection import (
    _probe_chamber_port,
    _probe_rtsp_port,
    detect_camera_type,
)
from pandaproxy.protocol import MAX_PAYLOAD_SIZE


class TestDetectCameraType:
    """Tests for detect_camera_type function."""

    @pytest.mark.asyncio
    async def test_detects_chamber_type(self):
        """Should return 'chamber' when chamber port responds."""
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            mock_chamber.return_value = True
            mock_rtsp.return_value = False

            result = await detect_camera_type("192.168.1.100", "testcode")

            assert result == "chamber"

    @pytest.mark.asyncio
    async def test_detects_rtsp_type(self):
        """Should return 'rtsp' when RTSP port responds."""
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            mock_chamber.return_value = False
            mock_rtsp.return_value = True

            result = await detect_camera_type("192.168.1.100", "testcode")

            assert result == "rtsp"

    @pytest.mark.asyncio
    async def test_prefers_chamber_when_both_respond(self):
        """Should prefer 'chamber' if both probes succeed."""
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            mock_chamber.return_value = True
            mock_rtsp.return_value = True

            result = await detect_camera_type("192.168.1.100", "testcode")

            assert result == "chamber"

    @pytest.mark.asyncio
    async def test_raises_when_neither_responds(self):
        """Should raise RuntimeError when no camera detected."""
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            mock_chamber.return_value = False
            mock_rtsp.return_value = False

            with pytest.raises(RuntimeError) as exc_info:
                await detect_camera_type("192.168.1.100", "testcode")

            assert "Could not detect camera type" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_handles_probe_timeout(self):
        """Should handle probe timeouts gracefully (returns False)."""
        # When a probe times out internally, it returns False (not raises)
        # The actual probe functions catch TimeoutError and return False
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            # Simulate chamber timing out (returns False), RTSP succeeds
            mock_chamber.return_value = False
            mock_rtsp.return_value = True

            result = await detect_camera_type("192.168.1.100", "testcode")

            assert result == "rtsp"

    @pytest.mark.asyncio
    async def test_handles_probe_exception(self):
        """Should handle probe exceptions gracefully (returns False)."""
        # The actual probe functions catch exceptions and return False
        # They don't let exceptions propagate to the caller
        with (
            patch("pandaproxy.detection._probe_chamber_port") as mock_chamber,
            patch("pandaproxy.detection._probe_rtsp_port") as mock_rtsp,
        ):
            # Simulate chamber connection refused (returns False), RTSP succeeds
            mock_chamber.return_value = False
            mock_rtsp.return_value = True

            result = await detect_camera_type("192.168.1.100", "testcode")

            assert result == "rtsp"


class TestProbeIntegration:
    """Tests for probe functions with mocked network connections."""

    def _make_rw(self):
        """Create a mock (reader, writer) pair."""
        reader = AsyncMock()
        writer = AsyncMock()
        writer.write = MagicMock()  # write() is synchronous in asyncio.StreamWriter
        writer.close = MagicMock()  # close() is synchronous in asyncio.StreamWriter
        return reader, writer

    # --- Chamber port probe ---

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_true_on_valid_response(self):
        """Chamber probe returns True when printer replies with a valid payload size."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        # 16-byte header: first 4 bytes are payload_size (little-endian uint32)
        header = struct.pack("<I", 5000) + b"\x00" * 12
        reader.read = AsyncMock(return_value=header)

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is True

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_false_on_zero_payload_size(self):
        """Chamber probe returns False when payload_size is 0."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        header = struct.pack("<I", 0) + b"\x00" * 12
        reader.read = AsyncMock(return_value=header)

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_false_on_oversized_payload(self):
        """Chamber probe returns False when payload_size exceeds MAX_PAYLOAD_SIZE."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        header = struct.pack("<I", MAX_PAYLOAD_SIZE + 1) + b"\x00" * 12
        reader.read = AsyncMock(return_value=header)

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_false_on_empty_response(self):
        """Chamber probe returns False when no data is returned."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(return_value=b"")

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_false_on_connection_failure(self):
        """Chamber probe returns False when connection cannot be established."""
        ssl_ctx = MagicMock()

        with patch("pandaproxy.detection.open_connection_safe", return_value=None):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is False

    # --- RTSP port probe ---

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_true_on_rtsp_banner(self):
        """RTSP probe returns True when printer responds with RTSP/1.0 banner."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(return_value=b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is True

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_true_on_rtsp2_banner(self):
        """RTSP probe returns True when printer responds with RTSP/2.0 banner."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(return_value=b"RTSP/2.0 200 OK\r\n")

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is True

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_true_on_unexpected_response(self):
        """RTSP probe returns True for any non-empty response (port is open with TLS)."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(return_value=b"some unexpected data")

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is True

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_false_on_empty_response(self):
        """RTSP probe returns False when no data is returned."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(return_value=b"")

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_false_on_connection_failure(self):
        """RTSP probe returns False when connection cannot be established."""
        ssl_ctx = MagicMock()

        with patch("pandaproxy.detection.open_connection_safe", return_value=None):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_chamber_returns_false_on_read_timeout(self):
        """Chamber probe returns False when connection succeeds but read times out."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(side_effect=TimeoutError())

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_chamber_port("192.168.1.1", "testcode", ssl_ctx)

        assert result is False

    @pytest.mark.asyncio
    async def test_probe_rtsp_returns_false_on_read_timeout(self):
        """RTSP probe returns False when connection succeeds but read times out."""
        ssl_ctx = MagicMock()
        reader, writer = self._make_rw()
        reader.read = AsyncMock(side_effect=TimeoutError())

        with patch(
            "pandaproxy.detection.open_connection_safe", return_value=(reader, writer)
        ):
            result = await _probe_rtsp_port("192.168.1.1", ssl_ctx)

        assert result is False
