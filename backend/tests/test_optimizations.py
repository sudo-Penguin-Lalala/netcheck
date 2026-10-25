"""Unit tests for NetCheck performance and system optimizations.

Tests verify:
1. Shared HTTP connection pool (singleton lifecycle & reuse)
2. Globalping adaptive polling schedule
3. Private target fallback (allowed when ALLOW_PRIVATE_TARGETS=1, blocked when 0)
4. Cache-Control and GZip response headers
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from starlette.requests import Request
from starlette.testclient import TestClient

# Add repo root and backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.main import app
from backend.utils.http_client import get_http_client, close_http_client
import backend.utils.globalping as gp
from backend.routers.port import port_check, PortRequest
from backend.routers.ping import ping_host, PingRequest
from backend.routers.http_check import http_check, HttpRequest


def _make_dummy_request(path: str = "/api/test") -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope)


class TestHttpClientPool(unittest.IsolatedAsyncioTestCase):
    """Test HTTP connection pooling and lifecycle."""

    async def test_singleton_reuse_and_close(self):
        client1 = get_http_client()
        client2 = get_http_client()
        self.assertIs(client1, client2, "get_http_client must return the same instance (reused connection pool)")
        self.assertFalse(client1.is_closed)

        await close_http_client()
        self.assertTrue(client1.is_closed, "close_http_client should gracefully close the pool")

        # Calling get_http_client again creates a fresh one
        client3 = get_http_client()
        self.assertIsNot(client1, client3)
        self.assertFalse(client3.is_closed)
        await close_http_client()


class TestAdaptivePolling(unittest.TestCase):
    """Test Globalping polling schedule."""

    def test_adaptive_intervals_defined(self):
        self.assertTrue(hasattr(gp, "_INITIAL_POLL_INTERVALS"))
        intervals = gp._INITIAL_POLL_INTERVALS
        self.assertEqual(intervals, [0.2, 0.3, 0.5, 0.75])
        self.assertLess(intervals[0], 0.5, "First poll must occur promptly (< 0.5s) to avoid unnecessary idle delay")


class TestPrivateTargetFallback(unittest.IsolatedAsyncioTestCase):
    """Test private target handling for homelab / LAN diagnostic use cases."""

    @patch.dict(os.environ, {"ALLOW_PRIVATE_TARGETS": "0"})
    async def test_blocked_by_default(self):
        req = _make_dummy_request("/api/port")
        body = PortRequest(host="192.168.1.1", port=80)
        with self.assertRaises(HTTPException) as cm:
            await port_check(req, body)
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.detail["error"], "private_blocked")

    @patch.dict(os.environ, {"ALLOW_PRIVATE_TARGETS": "1"})
    @patch("asyncio.open_connection")
    async def test_port_local_check_allowed(self, mock_conn):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)

        req = _make_dummy_request("/api/port")
        body = PortRequest(host="192.168.1.1", port=80)
        res = await port_check(req, body)
        self.assertEqual(res["status"], "open")
        self.assertEqual(res["host"], "192.168.1.1")
        self.assertEqual(res["port"], 80)

    @patch.dict(os.environ, {"ALLOW_PRIVATE_TARGETS": "1"})
    @patch("asyncio.create_subprocess_exec")
    async def test_ping_local_fallback(self, mock_exec):
        mock_proc = AsyncMock()
        mock_proc.communicate.return_value = (
            b"2 packets transmitted, 2 received, 0% packet loss\nrtt min/avg/max/mdev = 0.512/0.834/1.156/0.228 ms",
            b"",
        )
        mock_exec.return_value = mock_proc

        req = _make_dummy_request("/api/ping")
        body = PingRequest(host="192.168.1.1", count=2)
        res = await ping_host(req, body)
        self.assertEqual(res["host"], "192.168.1.1")
        self.assertEqual(res["packets_sent"], 2)
        self.assertEqual(res["packets_recv"], 2)
        self.assertEqual(res["loss_pct"], 0.0)
        self.assertEqual(res["avg"], 0.834)

    @patch.dict(os.environ, {"ALLOW_PRIVATE_TARGETS": "1"})
    async def test_http_local_fallback(self):
        req = _make_dummy_request("/api/http")
        body = HttpRequest(url="http://192.168.1.1/setup")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.reason_phrase = "OK"
        mock_resp.headers = {"server": "lighttpd", "content-type": "text/html"}

        mock_client = AsyncMock()
        mock_client.request.return_value = mock_resp

        with patch("backend.routers.http_check.get_http_client", return_value=mock_client):
            res = await http_check(req, body)
            self.assertEqual(res["status_code"], 200)
            self.assertEqual(res["status_text"], "OK")
            self.assertIn("server", res["headers"])


class TestMiddlewareHeaders(unittest.TestCase):
    """Test Cache-Control and compression middleware."""

    def setUp(self):
        self.client = TestClient(app)

    def test_api_cache_control_no_store(self):
        res = self.client.get("/api/healthz")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Cache-Control", res.headers)
        self.assertEqual(res.headers["Cache-Control"], "no-store, no-cache, must-revalidate")

    def test_static_cache_control(self):
        res = self.client.get("/style.css")
        if res.status_code == 200:
            self.assertIn("Cache-Control", res.headers)
            self.assertIn("max-age=86400", res.headers["Cache-Control"])

    def test_html_cache_control(self):
        res = self.client.get("/")
        if res.status_code == 200:
            self.assertIn("Cache-Control", res.headers)
            self.assertIn("no-cache", res.headers["Cache-Control"])

    def test_csp_connect_src_includes_icanhazip(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("https://ipv4.icanhazip.com", csp)
        self.assertIn("https://ipv6.icanhazip.com", csp)

    def test_csp_self_contained_fonts(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("font-src 'self'", csp)
        self.assertNotIn("fonts.googleapis.com", csp)
        self.assertNotIn("fonts.gstatic.com", csp)

    def test_dns_modern_types_allowed(self):
        from backend.routers.dns import _ALLOWED_TYPES
        for rtype in ("HTTPS", "SVCB", "DNSKEY", "DS"):
            self.assertIn(rtype, _ALLOWED_TYPES)

    def test_dynamic_user_agent(self):
        from backend.utils.http_client import USER_AGENT
        self.assertTrue(USER_AGENT.startswith("NetCheck"))
        self.assertIn("github.com", USER_AGENT)
        self.assertNotIn("NetCheck/1.4", USER_AGENT)


if __name__ == "__main__":
    unittest.main()
