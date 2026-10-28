import ipaddress
import socket
import json
from pinned_http import pinned_get
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


MAX_RESPONSE_BYTES = 65536
TIMEOUT_SECONDS = 8

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def normalize_url(value):
    """Validate and normalize an HTTP or HTTPS URL."""
    value = value.strip()

    if not value:
        raise ValueError("URL cannot be empty")

    if "://" not in value:
        value = "https://" + value

    parsed = urlsplit(value)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    return parsed.geturl()


class NoRedirectHandler(HTTPRedirectHandler):
    """Return redirect responses instead of automatically following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def resolve_public_addresses(url):
    """Resolve a target and return its validated public IP addresses."""
    parsed = urlsplit(normalize_url(url))
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve target hostname: {hostname}"
        ) from exc

    if not addresses:
        raise ValueError(f"No IP addresses found for: {hostname}")

    validated_ips = []

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])

        if not ip.is_global:
            raise ValueError(
                f"Target resolves to a non-public IP address: {ip}"
            )

        if str(ip) not in validated_ips:
            validated_ips.append(str(ip))

    return validated_ips


def validate_public_target(url):
    """Reject targets that resolve to non-public IP addresses."""
    resolve_public_addresses(url)
    return url

def inspect_http(target):
    """Collect basic HTTP metadata from an authorized web target."""
    try:
        url = normalize_url(target)
        addresses = resolve_public_addresses(url)
        if not addresses:
            raise ValueError("Target did not resolve to a public IP address")

    except ValueError as exc:
        return {
            "url": target,
            "error": str(exc),
        }

    try:
        # Connect to an already-validated IP to avoid resolving the hostname again.
        return pinned_get(url, addresses[0], timeout=TIMEOUT_SECONDS)
    except (OSError, TimeoutError, ValueError, socket.timeout) as exc:
        return {
            "url": url,
            "error": str(exc),
        }


def generate_markdown_report(result):
    """Convert reconnaissance results into a readable Markdown report."""
    lines = [
        "# Web Reconnaissance Report",
        "",
        f"- **Target:** {result.get('url', 'Unknown')}",
        f"- **HTTP Status:** {result.get('status_code', 'N/A')}",
        f"- **Final URL:** {result.get('final_url', 'N/A')}",
        f"- **Content Type:** {result.get('content_type', 'N/A')}",
        f"- **Server Header:** {result.get('server_header', 'N/A')}",
        f"- **Redirect Location:** {result.get('location_header', 'N/A')}",
        f"- **Response Bytes Sampled:** {result.get('response_bytes_sampled', 'N/A')}",
        "",
        "## Security Headers",
        "",
        "| Header | Observed Value |",
        "|---|---|",
    ]

    headers = result.get("security_headers", {})

    for name, value in headers.items():
        observed = value if value is not None else "Not observed"
        lines.append(f"| {name} | {observed} |")

    if result.get("error"):
        lines.extend([
            "",
            "## Error",
            "",
            result["error"],
        ])

    lines.extend([
        "",
        "## Interpretation",
        "",
        "Missing security headers are observations, not automatic proof of a vulnerability.",
        "Review the target's configuration and application requirements before drawing conclusions.",
        "",
    ])

    return "\n".join(lines)
if __name__ == "__main__":
    target = input("Enter an authorized HTTP/HTTPS target: ")

    try:
        result = inspect_http(target)

        for key, value in result.items():
            print(f"{key}: {value}")

        output_path = "output/recon-report.json"

        with open(output_path, "w", encoding="utf-8") as report_file:
            json.dump(result, report_file, indent=4)

        print(f"\nJSON report saved to: {output_path}")

        markdown_path = "output/recon-report.md"

        with open(markdown_path, "w", encoding="utf-8") as report_file:
            report_file.write(generate_markdown_report(result))

        print(f"Markdown report saved to: {markdown_path}")

    except ValueError as exc:
        print(f"Invalid input: {exc}")
