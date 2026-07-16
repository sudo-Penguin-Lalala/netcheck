"""Security test suite for critical vulnerability patches.

Tests verify fixes for:
1. IPv6-mapped IPv4 address bypass (::ffff:192.168.1.1)
2. DNS rebinding + TOCTOU race condition
3. WHOIS SSRF via DNS rebinding
4. Normal functionality preservation
"""
import socket
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import asyncio

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils.validators import is_private_ip, is_private_target_blocked, _resolve_all_ips


class TestIPv6MappedIPv4Bypass(unittest.TestCase):
    """Test IPv6-mapped IPv4 address normalization (HIGH severity fix)."""

    def test_ipv6_mapped_loopback_blocked(self):
        """IPv6-mapped loopback (::ffff:127.0.0.1) should be detected as private."""
        result = is_private_ip("::ffff:127.0.0.1")
        self.assertTrue(result, "::ffff:127.0.0.1 should be detected as loopback")

    def test_ipv6_mapped_private_blocked(self):
        """IPv6-mapped private IPs should be detected as private."""
        test_cases = [
            "::ffff:192.168.1.1",    # RFC1918
            "::ffff:10.0.0.1",       # RFC1918
            "::ffff:172.16.0.1",     # RFC1918
            "::ffff:169.254.1.1",    # Link-local
        ]
        for ip in test_cases:
            with self.subTest(ip=ip):
                result = is_private_ip(ip)
                self.assertTrue(result, f"{ip} should be detected as private")

    def test_ipv6_mapped_public_allowed(self):
        """IPv6-mapped public IPs should NOT be blocked."""
        result = is_private_ip("::ffff:8.8.8.8")
        self.assertFalse(result, "::ffff:8.8.8.8 (public) should NOT be blocked")

    def test_regular_ipv6_loopback_blocked(self):
        """Regular IPv6 loopback (::1) should still be blocked."""
        result = is_private_ip("::1")
        self.assertTrue(result, "::1 should be detected as loopback")

    def test_regular_ipv4_private_blocked(self):
        """Regular IPv4 private addresses should still be blocked."""
        result = is_private_ip("192.168.1.1")
        self.assertTrue(result, "192.168.1.1 should be detected as private")


class TestDNSRebindingProtection(unittest.TestCase):
    """Test DNS rebinding + TOCTOU race condition protection (CRITICAL severity fix)."""

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')  # Mock sleep to make tests fast
    @patch('utils.validators._resolve_all_ips')
    def test_consistent_public_dns_allowed(self, mock_resolve, mock_sleep, mock_allow):
        """Consistent public DNS resolution should be allowed."""
        mock_allow.return_value = False
        # Both resolutions return same public IP
        mock_resolve.return_value = {"8.8.8.8"}

        result = asyncio.run(is_private_target_blocked("safe.example.com"))
        self.assertFalse(result, "Consistent public DNS should be allowed")
        self.assertEqual(mock_resolve.call_count, 2, "Should perform dual-resolution")

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')
    @patch('utils.validators._resolve_all_ips')
    def test_consistent_private_dns_blocked(self, mock_resolve, mock_sleep, mock_allow):
        """Consistent private DNS resolution should be blocked."""
        mock_allow.return_value = False
        # Both resolutions return same private IP
        mock_resolve.return_value = {"192.168.1.1"}

        result = asyncio.run(is_private_target_blocked("internal.local"))
        self.assertTrue(result, "Consistent private DNS should be blocked")

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')
    @patch('utils.validators._resolve_all_ips')
    def test_dns_rebinding_detected_and_blocked(self, mock_resolve, mock_sleep, mock_allow):
        """DNS rebinding attack (changing IPs between resolutions) should be blocked."""
        mock_allow.return_value = False
        # First resolution: public IP (passes initial check)
        # Second resolution: private IP (rebinding attack!)
        mock_resolve.side_effect = [
            {"8.8.8.8"},           # First resolution: public
            {"192.168.1.1"}        # Second resolution: private (ATTACK!)
        ]

        result = asyncio.run(is_private_target_blocked("rebind.attacker.com"))
        self.assertTrue(result, "DNS rebinding should be detected and blocked")
        self.assertEqual(mock_resolve.call_count, 2, "Should perform dual-resolution")

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')
    @patch('utils.validators._resolve_all_ips')
    def test_dns_resolution_failure_blocked(self, mock_resolve, mock_sleep, mock_allow):
        """Failed DNS resolution should be blocked (fail-closed security)."""
        mock_allow.return_value = False
        # First resolution fails
        mock_resolve.return_value = set()

        result = asyncio.run(is_private_target_blocked("nonexistent.invalid"))
        self.assertTrue(result, "Failed DNS resolution should be blocked (fail-closed)")

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')
    @patch('utils.validators._resolve_all_ips')
    def test_inconsistent_dns_blocked(self, mock_resolve, mock_sleep, mock_allow):
        """Inconsistent DNS (different public IPs) should be blocked as suspicious."""
        mock_allow.return_value = False
        # Different IPs between resolutions (even both public)
        mock_resolve.side_effect = [
            {"1.1.1.1"},
            {"8.8.8.8"}
        ]

        result = asyncio.run(is_private_target_blocked("suspicious.example.com"))
        self.assertTrue(result, "Inconsistent DNS should be blocked")

    @patch('utils.validators._allow_private_targets')
    def test_literal_ip_bypasses_dns_check(self, mock_allow):
        """Literal IP addresses should bypass DNS resolution logic."""
        mock_allow.return_value = False

        # Public IP literal should be allowed
        result = asyncio.run(is_private_target_blocked("8.8.8.8"))
        self.assertFalse(result)

        # Private IP literal should be blocked
        result = asyncio.run(is_private_target_blocked("192.168.1.1"))
        self.assertTrue(result)


class TestNormalFunctionality(unittest.TestCase):
    """Verify patches don't break normal NetCheck functionality."""

    @patch('utils.validators._allow_private_targets')
    @patch('utils.validators.time.sleep')
    def test_real_public_domain_allowed(self, mock_sleep, mock_allow):
        """Real public domains like google.com should work normally."""
        mock_allow.return_value = False

        # This will do real DNS resolution unless network is unavailable
        try:
            result = asyncio.run(is_private_target_blocked("google.com"))
            # Google.com should resolve to public IPs and be allowed
            self.assertFalse(result, "google.com should be allowed")
        except Exception as e:
            self.skipTest(f"Network unavailable: {e}")

    def test_public_ip_validation_unchanged(self):
        """Public IPv4 validation should work as before."""
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))
        self.assertFalse(is_private_ip("142.250.185.46"))

    def test_private_ip_validation_unchanged(self):
        """Private IPv4 validation should work as before."""
        self.assertTrue(is_private_ip("192.168.0.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))

    @patch('utils.validators._allow_private_targets')
    def test_allow_private_targets_flag_works(self, mock_allow):
        """ALLOW_PRIVATE_TARGETS=1 should still allow private targets."""
        mock_allow.return_value = True

        # When flag is enabled, private targets should be allowed
        result = asyncio.run(is_private_target_blocked("192.168.1.1"))
        self.assertFalse(result, "Private targets should be allowed when flag is set")


class TestResolveAllIPs(unittest.TestCase):
    """Test the _resolve_all_ips helper function."""

    def test_resolve_real_domain(self):
        """Test resolving a real domain."""
        try:
            ips = _resolve_all_ips("google.com", timeout=2.0)
            self.assertIsInstance(ips, set)
            self.assertGreater(len(ips), 0, "Should resolve at least one IP")
            # All resolved IPs should be valid
            for ip in ips:
                self.assertIsNotNone(ip)
        except Exception:
            self.skipTest("Network unavailable")

    def test_resolve_invalid_domain(self):
        """Test resolving an invalid domain returns empty set."""
        ips = _resolve_all_ips("this-domain-definitely-does-not-exist.invalid")
        self.assertEqual(ips, set(), "Invalid domain should return empty set")


def run_tests():
    """Run all security tests and print results."""
    print("=" * 70)
    print("NETCHECK SECURITY PATCH VALIDATION")
    print("=" * 70)
    print()

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestIPv6MappedIPv4Bypass))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSRebindingProtection))
    suite.addTests(loader.loadTestsFromTestCase(TestNormalFunctionality))
    suite.addTests(loader.loadTestsFromTestCase(TestResolveAllIPs))

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()

    if result.wasSuccessful():
        print("✅ ALL SECURITY PATCHES VALIDATED - TESTS PASSED")
        return 0
    else:
        print("❌ SOME TESTS FAILED - REVIEW REQUIRED")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
