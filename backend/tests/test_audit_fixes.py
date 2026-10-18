"""Unit tests for 2026 comprehensive audit fixes and enhancements.

Tests verify fixes for:
1. Constant-time auth verification (mitigating timing attacks)
2. IP spoofing rejection in client IP resolution
3. Non-Docker cache directory resolution and lock leak prevention
4. Split-DNS and private target resolution in DNS and rDNS routers
"""
import asyncio
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException
from starlette.requests import Request

# Add repo root and backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.validators import require_auth
from utils.cache import _resolve_cache_dir, get_or_fetch, _locks
from routers.ip import _client_ip
from backend.routers.dns import dns_lookup, DnsRequest
from backend.routers.rdns import reverse_dns, RdnsRequest


def _make_dummy_request(path: str = "/api/test", headers: list[tuple[bytes, bytes]] | None = None, client: tuple[str, int] = ("127.0.0.1", 12345)) -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers or [],
        "client": client,
    }
    return Request(scope)


class TestRequireAuth(unittest.TestCase):
    """Test timing-safe require_auth with secrets.compare_digest."""

    @patch.dict(os.environ, {"AUTH_TOKEN": "supersecrettoken1234567890"})
    def test_valid_token_allowed(self):
        req = _make_dummy_request(headers=[(b"authorization", b"Bearer supersecrettoken1234567890")])
        try:
            asyncio.run(require_auth(req))
        except HTTPException:
            self.fail("require_auth raised HTTPException unexpectedly with valid token")

    @patch.dict(os.environ, {"AUTH_TOKEN": "supersecrettoken1234567890"})
    def test_invalid_token_rejected(self):
        req = _make_dummy_request(headers=[(b"authorization", b"Bearer wrongtoken")])
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(require_auth(req))
        self.assertEqual(cm.exception.status_code, 401)
        self.assertEqual(cm.exception.detail["message"], "Invalid token")

    @patch.dict(os.environ, {"AUTH_TOKEN": "supersecrettoken1234567890"})
    def test_missing_header_rejected(self):
        req = _make_dummy_request(headers=[])
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(require_auth(req))
        self.assertEqual(cm.exception.status_code, 401)
        self.assertEqual(cm.exception.detail["message"], "Missing or invalid Authorization header")

    @patch.dict(os.environ, {}, clear=True)
    def test_no_auth_configured_allows_all(self):
        if "AUTH_TOKEN" in os.environ:
            del os.environ["AUTH_TOKEN"]
        req = _make_dummy_request(headers=[])
        try:
            asyncio.run(require_auth(req))
        except HTTPException:
            self.fail("require_auth should not raise when AUTH_TOKEN is not configured")

    @patch("utils.validators.secrets.compare_digest")
    @patch.dict(os.environ, {"AUTH_TOKEN": "testtoken"})
    def test_timing_safe_digest_called(self, mock_compare):
        mock_compare.return_value = True
        req = _make_dummy_request(headers=[(b"authorization", b"Bearer testtoken")])
        asyncio.run(require_auth(req))
        self.assertTrue(mock_compare.called, "secrets.compare_digest must be used for constant-time comparison")


class TestClientIPResolution(unittest.TestCase):
    """Test client IP resolution ignores raw spoofed headers."""

    def test_client_ip_uses_client_host(self):
        # Even if attacker sends X-Forwarded-For header, _client_ip must rely on request.client.host
        req = _make_dummy_request(
            headers=[(b"x-forwarded-for", b"9.9.9.9")],
            client=("203.0.113.195", 54321),
        )
        ip = _client_ip(req)
        self.assertEqual(ip, "203.0.113.195", "Should use request.client.host instead of trusting spoofed headers")

    def test_client_ip_handles_missing_client(self):
        req = _make_dummy_request()
        # Simulate scope without client
        req.scope["client"] = None
        ip = _client_ip(req)
        self.assertEqual(ip, "")


class TestCacheResilience(unittest.TestCase):
    """Test cache directory fallback and lock cleanup."""

    def test_resolve_cache_dir_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_path = os.path.join(tmpdir, "testcache")
            with patch.dict(os.environ, {"CACHE_DIR": target_path}):
                path = _resolve_cache_dir()
                self.assertEqual(path, target_path)
                self.assertTrue(os.path.isdir(path))
                self.assertTrue(os.access(path, os.W_OK))

    def test_resolve_cache_dir_permission_fallback(self):
        # Force a non-writable path as CACHE_DIR (under /proc/which fails even for root)
        with patch.dict(os.environ, {"CACHE_DIR": "/proc/nonexistent_cache_dir_test"}):
            path = _resolve_cache_dir()
            self.assertTrue(os.path.isdir(path))
            self.assertTrue(os.access(path, os.W_OK))
            self.assertNotEqual(path, "/proc/nonexistent_cache_dir_test")

    def test_locks_dict_cleaned_up(self):
        test_key = "test_cleanup_key"

        async def dummy_fetch():
            return {"data": "ok"}

        async def run_cache():
            res = await get_or_fetch(test_key, 60, dummy_fetch)
            return res

        asyncio.run(run_cache())
        self.assertNotIn(test_key, _locks, "Lock key should be popped from _locks dictionary to prevent memory leak")


class TestDnsSplitAndPrivateHandling(unittest.TestCase):
    """Test DNS and rDNS routers allow private and split-DNS targets."""

    @patch("backend.routers.dns._resolver.resolve")
    def test_dns_lookup_allows_internal_domain(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.__iter__.return_value = ["192.168.1.100"]
        mock_answer.rrset.ttl = 300
        mock_resolve.return_value = mock_answer

        req = _make_dummy_request(path="/api/dns")
        body = DnsRequest(host="router.lan", type="A")

        res = asyncio.run(dns_lookup(req, body))
        self.assertIn("records", res)
        self.assertEqual(res["records"], ["192.168.1.100"])

    @patch("backend.routers.rdns._resolver.resolve")
    def test_rdns_lookup_allows_private_ip(self, mock_resolve):
        mock_answer = MagicMock()
        mock_answer.__getitem__.return_value = "gateway.lan."
        mock_resolve.return_value = mock_answer

        req = _make_dummy_request(path="/api/rdns")
        body = RdnsRequest(ip="192.168.1.1")

        res = asyncio.run(reverse_dns(req, body))
        self.assertIn("hostname", res)
        self.assertEqual(res["hostname"], "gateway.lan")


if __name__ == "__main__":
    unittest.main()
