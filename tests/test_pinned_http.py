import socket
from unittest.mock import call
from pinned_http import _connect_to_ip, PinnedHTTPSConnection
import unittest
from unittest.mock import MagicMock, patch

from pinned_http import pinned_get, _format_host_header


class TestPinnedGet(unittest.TestCase):
    @patch("pinned_http.PinnedHTTPConnection")
    def test_http_uses_pinned_ip_and_preserves_host(self, mock_connection):
        connection = mock_connection.return_value
        response = MagicMock()

        response.status = 200
        response.read.return_value = b"test body"
        response.getheader.side_effect = lambda name: {
            "Content-Type": "text/html",
            "Server": "test-server",
            "Location": None,
        }.get(name)

        connection.getresponse.return_value = response

        result = pinned_get(
            "http://example.com/test?mode=check",
            "93.184.216.34",
        )

        mock_connection.assert_called_once_with(
            "example.com",
            80,
            "93.184.216.34",
            8,
        )

        connection.request.assert_called_once_with(
            "GET",
            "/test?mode=check",
            headers={
                "Host": "example.com",
                "User-Agent": "WebReconToolkit/0.1",
                "Connection": "close",
            },
        )

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["response_bytes_sampled"], 9)
        connection.close.assert_called_once()

    def test_private_ip_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "globally routable"):
            pinned_get("http://example.com/", "192.168.1.10")

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            pinned_get("http://example.com/", "not-an-ip")

    def test_unsupported_scheme_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Only HTTP and HTTPS"):
            pinned_get("ftp://example.com/", "93.184.216.34")



class TestHostHeaderFormatting(unittest.TestCase):
    def test_http_default_port_is_omitted(self):
        self.assertEqual(
            _format_host_header("example.com", "http", 80),
            "example.com",
        )

    def test_non_default_port_is_preserved(self):
        self.assertEqual(
            _format_host_header("example.com", "http", 443),
            "example.com:443",
        )
        self.assertEqual(
            _format_host_header("example.com", "https", 80),
            "example.com:80",
        )

    def test_ipv6_hostname_uses_brackets(self):
        self.assertEqual(
            _format_host_header("2606:4700::1111", "http", 80),
            "[2606:4700::1111]",
        )
        self.assertEqual(
            _format_host_header("2606:4700::1111", "https", 8443),
            "[2606:4700::1111]:8443",
        )


class TestPinnedSocket(unittest.TestCase):
    @patch("pinned_http.socket.socket")
    def test_connects_directly_to_ipv4_address(self, mock_socket):
        sock = mock_socket.return_value

        result = _connect_to_ip("93.184.216.34", 443, 8)

        mock_socket.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        sock.settimeout.assert_called_once_with(8)
        sock.connect.assert_called_once_with(("93.184.216.34", 443))
        self.assertIs(result, sock)

    @patch("pinned_http.socket.socket")
    def test_connects_directly_to_ipv6_address(self, mock_socket):
        sock = mock_socket.return_value

        result = _connect_to_ip("2606:4700:4700::1111", 443, 8)

        mock_socket.assert_called_once_with(
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )
        sock.connect.assert_called_once_with(
            ("2606:4700:4700::1111", 443, 0, 0)
        )
        self.assertIs(result, sock)

    @patch("pinned_http._connect_to_ip")
    def test_https_uses_original_hostname_for_tls(self, mock_connect):
        raw_socket = MagicMock()
        mock_connect.return_value = raw_socket

        connection = PinnedHTTPSConnection(
            "example.com",
            443,
            "93.184.216.34",
            8,
        )

        with patch.object(
            connection._context,
            "wrap_socket",
            return_value=MagicMock(),
        ) as mock_wrap:
            connection.connect()

        mock_connect.assert_called_once_with(
            "93.184.216.34",
            443,
            8,
        )
        mock_wrap.assert_called_once()
        self.assertEqual(
            mock_wrap.call_args.kwargs["server_hostname"],
            "example.com",
        )
if __name__ == "__main__":
    unittest.main()
