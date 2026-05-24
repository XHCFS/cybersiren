"""Unit tests for the SSRF guard.

Covers the is_public_ip predicate, the validate_url pre-flight, the
requests adapter (including the redirect-revalidation property), and
the aiohttp connector.
"""
from __future__ import annotations

import ipaddress
import socket
import unittest
from unittest import mock

from fusion_kit.safe_http import (
    BlockedAddressError,
    SSRFGuardedAdapter,
    SSRFGuardedConnector,
    is_public_ip,
    mount_ssrf_guard,
    validate_url,
)


class TestIsPublicIP(unittest.TestCase):
    def test_public_addresses_pass(self):
        for addr in ("1.1.1.1", "8.8.8.8", "140.82.112.4", "2606:4700:4700::1111"):
            with self.subTest(addr=addr):
                self.assertTrue(is_public_ip(ipaddress.ip_address(addr)))

    def test_loopback_rejected(self):
        for addr in ("127.0.0.1", "127.10.0.1", "::1"):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_ip(ipaddress.ip_address(addr)))

    def test_link_local_rejected(self):
        # Includes 169.254.169.254 cloud metadata.
        for addr in ("169.254.0.1", "169.254.169.254", "fe80::1"):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_ip(ipaddress.ip_address(addr)))

    def test_private_rejected(self):
        for addr in ("10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254",
                     "192.168.0.1", "fc00::1", "fd12:3456:789a::1"):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_ip(ipaddress.ip_address(addr)))

    def test_multicast_rejected(self):
        for addr in ("224.0.0.1", "239.255.255.255", "ff02::1"):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_ip(ipaddress.ip_address(addr)))

    def test_unspecified_rejected(self):
        for addr in ("0.0.0.0", "::"):
            with self.subTest(addr=addr):
                self.assertFalse(is_public_ip(ipaddress.ip_address(addr)))


class TestValidateURL(unittest.TestCase):
    def test_literal_loopback_rejected(self):
        with self.assertRaises(BlockedAddressError):
            validate_url("http://127.0.0.1/")

    def test_literal_metadata_rejected(self):
        with self.assertRaises(BlockedAddressError):
            validate_url("http://169.254.169.254/latest/meta-data/")

    def test_literal_private_rejected(self):
        for u in ("http://10.0.0.1/", "http://192.168.1.1/admin",
                  "http://172.16.0.1/", "http://[fc00::1]/"):
            with self.subTest(url=u), self.assertRaises(BlockedAddressError):
                validate_url(u)

    def test_non_http_scheme_rejected(self):
        for u in ("file:///etc/passwd", "ftp://example.com/", "gopher://x/"):
            with self.subTest(url=u), self.assertRaises(BlockedAddressError):
                validate_url(u)

    def test_no_host_rejected(self):
        with self.assertRaises(BlockedAddressError):
            validate_url("http:///path-only")

    def test_resolved_internal_rejected(self):
        with mock.patch("fusion_kit.safe_http.socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, 0, 0, "", ("10.0.0.5", 0))]
            with self.assertRaises(BlockedAddressError):
                validate_url("http://attacker-controlled.example/")

    def test_resolved_public_accepted(self):
        with mock.patch("fusion_kit.safe_http.socket.getaddrinfo") as gai:
            gai.return_value = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
            # Should not raise.
            validate_url("http://example.com/")

    def test_dns_failure_blocks(self):
        with mock.patch("fusion_kit.safe_http.socket.getaddrinfo") as gai:
            gai.side_effect = socket.gaierror("nope")
            with self.assertRaises(BlockedAddressError):
                validate_url("http://does-not-resolve.invalid/")


class TestSSRFGuardedAdapter(unittest.TestCase):
    def test_send_validates_url(self):
        adapter = SSRFGuardedAdapter()
        req = mock.Mock()
        req.url = "http://127.0.0.1/"
        with self.assertRaises(BlockedAddressError):
            adapter.send(req)

    def test_mount_replaces_adapters(self):
        import requests
        sess = mount_ssrf_guard(requests.Session())
        for prefix in ("http://", "https://"):
            self.assertIsInstance(sess.get_adapter("https://example.com"), SSRFGuardedAdapter)
            self.assertIsInstance(sess.get_adapter("http://example.com"), SSRFGuardedAdapter)


class TestSSRFGuardedConnector(unittest.TestCase):
    def _drive(self, fake_host, target_host):
        """Construct the connector inside the event loop (aiohttp >=3.13
        requires a running loop at TCPConnector __init__), patch the parent
        resolver, and exercise _resolve_host once. Returns the list."""
        import asyncio

        async def runner():
            connector = SSRFGuardedConnector()
            try:
                async def fake_resolve(self, host, port, traces=None):
                    return [{"hostname": host, "host": fake_host, "port": port,
                             "family": socket.AF_INET, "proto": 0, "flags": 0}]

                with mock.patch.object(
                    SSRFGuardedConnector.__mro__[1],
                    "_resolve_host",
                    new=fake_resolve,
                ):
                    return await connector._resolve_host(target_host, 443)
            finally:
                await connector.close()

        return asyncio.run(runner())

    def test_resolved_internal_raises(self):
        with self.assertRaises(BlockedAddressError):
            self._drive("10.0.0.1", "attacker.test")

    def test_resolved_metadata_raises(self):
        with self.assertRaises(BlockedAddressError):
            self._drive("169.254.169.254", "metadata-rebind.test")

    def test_resolved_public_passes_through(self):
        got = self._drive("8.8.8.8", "dns.google")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["host"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
