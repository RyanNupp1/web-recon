import unittest
from unittest.mock import patch

from recon import inspect_http


SAMPLE_RESULT = {
    "url": "https://example.com",
    "status_code": 200,
    "final_url": "https://example.com",
    "content_type": "text/html; charset=utf-8",
    "server_header": "test-server",
    "location_header": None,
    "response_bytes_sampled": 18,
    "security_headers": {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": None,
        "X-Content-Type-Options": None,
        "X-Frame-Options": None,
        "Referrer-Policy": None,
        "Permissions-Policy": None,
    },
}


class TestInspectHttp(unittest.TestCase):
    @patch("recon.pinned_get", return_value=SAMPLE_RESULT)
    @patch("recon.resolve_public_addresses", return_value=["93.184.216.34"])
    def test_successful_response(self, mock_resolve, mock_pinned_get):
        result = inspect_http("https://example.com")

        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["content_type"], "text/html; charset=utf-8")
        self.assertEqual(
            result["security_headers"]["Strict-Transport-Security"],
            "max-age=31536000",
        )
        mock_resolve.assert_called_once_with("https://example.com")
        mock_pinned_get.assert_called_once_with(
            "https://example.com",
            "93.184.216.34",
            timeout=8,
        )

    @patch("recon.pinned_get", side_effect=OSError("simulated connection failure"))
    @patch("recon.resolve_public_addresses", return_value=["93.184.216.34"])
    def test_connection_error(self, mock_resolve, mock_pinned_get):
        result = inspect_http("https://example.com")

        self.assertIn("error", result)
        self.assertIn("simulated connection failure", result["error"])
        self.assertEqual(result["url"], "https://example.com")

    @patch("recon.pinned_get")
    @patch(
        "recon.resolve_public_addresses",
        side_effect=ValueError("Unable to resolve target hostname: example.com"),
    )
    def test_dns_validation_error_is_returned(
        self, mock_resolve, mock_pinned_get
    ):
        result = inspect_http("https://example.com")

        self.assertIn("error", result)
        self.assertIn("Unable to resolve", result["error"])
        mock_pinned_get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
