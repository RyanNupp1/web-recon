import unittest
from unittest.mock import patch
import socket

from recon import (
    normalize_url,
    resolve_public_addresses,
    validate_public_target,
)

class TestNormalizeUrl(unittest.TestCase):
    def test_hostname_gets_https(self):
        self.assertEqual(
            normalize_url("example.com"),
            "https://example.com",
        )

    def test_existing_https_url_is_preserved(self):
        self.assertEqual(
            normalize_url("https://example.com/path"),
            "https://example.com/path",
        )

    def test_http_is_supported(self):
        self.assertEqual(
            normalize_url("http://example.com"),
            "http://example.com",
        )

    def test_ftp_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("ftp://example.com")

    def test_empty_input_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("   ")

    def test_missing_hostname_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("https://")

    def test_invalid_port_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("https://example.com:abc")

    def test_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:password@example.com")


class TestValidatePublicTarget(unittest.TestCase):
    @patch("recon.socket.getaddrinfo")
    def test_loopback_address_is_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("127.0.0.1", 443))
        ]

        with self.assertRaisesRegex(ValueError, "non-public"):
            validate_public_target("https://example.com")

    @patch("recon.socket.getaddrinfo")
    def test_private_address_is_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("192.168.1.1", 443))
        ]

        with self.assertRaisesRegex(ValueError, "non-public"):
            validate_public_target("https://example.com")

    @patch("recon.socket.getaddrinfo")
    def test_public_address_is_accepted(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "",
             ("93.184.216.34", 443))
        ]

        self.assertEqual(
            validate_public_target("https://example.com"),
            "https://example.com",
        )

    @patch("recon.socket.getaddrinfo")
    def test_dns_failure_is_rejected(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror(
            "Name resolution failed"
        )

        with self.assertRaisesRegex(ValueError, "Unable to resolve"):
            validate_public_target("https://example.com")
if __name__ == "__main__":
    unittest.main()


class TestResolvePublicAddresses(unittest.TestCase):
    @patch("recon.socket.getaddrinfo")
    def test_returns_unique_public_addresses(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
        ]

        result = resolve_public_addresses("https://example.com")

        self.assertEqual(result, ["93.184.216.34"])

    @patch("recon.socket.getaddrinfo")
    def test_rejects_mixed_public_and_private_addresses(
        self, mock_getaddrinfo
    ):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("192.168.1.10", 443),
            ),
        ]

        with self.assertRaisesRegex(ValueError, "non-public"):
            resolve_public_addresses("https://example.com")
