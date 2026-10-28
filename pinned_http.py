import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


def _connect_to_ip(ip_address, port, timeout):
    """Open a TCP connection directly to a validated IP address."""
    ip = ipaddress.ip_address(ip_address)

    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        if ip.version == 6:
            sock.connect((str(ip), port, 0, 0))
        else:
            sock.connect((str(ip), port))

        return sock
    except Exception:
        sock.close()
        raise


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that connects directly to a specified IP."""

    def __init__(self, hostname, port, ip_address, timeout):
        super().__init__(hostname, port, timeout=timeout)
        self.ip_address = ip_address

    def connect(self):
        self.sock = _connect_to_ip(
            self.ip_address,
            self.port,
            self.timeout,
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP with normal TLS verification."""

    def __init__(self, hostname, port, ip_address, timeout):
        super().__init__(
            hostname,
            port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self.ip_address = ip_address

    def connect(self):
        raw_socket = _connect_to_ip(
            self.ip_address,
            self.port,
            self.timeout,
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
            )
        except Exception:
            raw_socket.close()
            raise


def _format_host_header(hostname, scheme, port):
    """Format the HTTP Host header with the correct port and IPv6 brackets."""
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80

    if port != default_port:
        return f"{host}:{port}"

    return host


def pinned_get(url, ip_address, timeout=8):
    """Issue one GET request to a validated IP while retaining the hostname."""
    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    if not parsed.hostname:
        raise ValueError("URL must contain a hostname")

    ip = ipaddress.ip_address(ip_address)

    if not ip.is_global:
        raise ValueError("Connection IP must be globally routable")

    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme == "https":
        connection = PinnedHTTPSConnection(
            hostname,
            port,
            str(ip),
            timeout,
        )
    else:
        connection = PinnedHTTPConnection(
            hostname,
            port,
            str(ip),
            timeout,
        )

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": _format_host_header(hostname, parsed.scheme, port),
                "User-Agent": "WebReconToolkit/0.1",
                "Connection": "close",
            },
        )

        response = connection.getresponse()
        body_sample = response.read(65536)

        return {
            "url": url,
            "status_code": response.status,
            "final_url": url,
            "content_type": response.getheader("Content-Type"),
            "server_header": response.getheader("Server"),
            "location_header": response.getheader("Location"),
            "response_bytes_sampled": len(body_sample),
            "security_headers": {
                name: response.getheader(name)
                for name in (
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy",
                )
            },
        }
    finally:
        connection.close()
