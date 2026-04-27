import dataclasses
import socket
import ssl
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import http_parser
import tls

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# Security config
ALLOWED_CONNECT_PORTS = {443, 8443, 8080, 8888}

# RFC-1918 + loopback + link-local
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Maximum concurrent client threads
MAX_WORKERS = 100

# Relay/read timeout
RELAY_TIMEOUT = 10

# Maximum size of HTTP request headers
MAX_HEADER_SIZE = 65536

# Set False only for upstream servers with self-signed certs. Just for testing.
VERIFY_UPSTREAM_CERT = True


# CA
_ca_cert = None
_ca_key = None


def _load_ca() -> None:
    global _ca_cert, _ca_key
    _ca_cert, _ca_key = tls.load_or_create_ca()


# SSRF guard
def resolve_and_check(host: str) -> str | None:
    """
    Resolve host to an IP, verify it is not in a blocked range, and return
    the IP string so the caller can connect directly (avoiding a second DNS
    lookup that a rebinding attack could swap).

    Returns None if the host is unsafe or resolution fails.
    """
    try:
        ip_str = socket.gethostbyname(host)
        resolved = ipaddress.ip_address(ip_str)
        for net in BLOCKED_NETWORKS:
            if resolved in net:
                log.warning("SSRF block: %s resolved to %s", host, ip_str)
                return None
        return ip_str
    except Exception as exc:
        log.warning("Host resolution failed for %s: %s", host, exc)
        return None


def send_error(sock: socket.socket, status_code: int, reason: str) -> None:
    """Send a minimal HTTP error response."""
    response = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(response.encode("utf-8"))
    except Exception:
        pass


# HTTP target helpers
def _http_target(req: http_parser.HTTPRequest) -> tuple[str, int]:
    """Extract (host, port) from a plain-HTTP proxy request."""
    if req.path.startswith(("http://", "https://")):
        parsed = urlparse(req.path)
        host = parsed.hostname or ""
        port = parsed.port or (443 if req.path.startswith("https") else 80)
        return host, port
    host_hdr = (req.header("host") or "").strip()
    if ":" in host_hdr:
        h, _, p = host_hdr.rpartition(":")
        return h, int(p)
    return host_hdr, 80


def _to_relative(req: http_parser.HTTPRequest) -> http_parser.HTTPRequest:
    """Return a copy of *req* with an absolute-URL path stripped to relative."""
    if not req.path.startswith(("http://", "https://")):
        return req
    parsed = urlparse(req.path)
    rel = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
    return dataclasses.replace(req, path=rel)


# CONNECT tunnel handler
def handle_connect(client_socket: socket.socket, url: str) -> None:
    """
    TLS MITM handler for HTTPS CONNECT requests.

    Flow:
      1. Parse host:port from the CONNECT target.
      2. Connect to the real upstream server with TLS (verifying its cert).
      3. Tell the client the tunnel is ready (200 Connection Established).
      4. Wrap the client socket with TLS using a dynamically signed leaf cert.
      5. Parse HTTP request/response pairs through the tunnel until either side
         closes the connection or signals Connection: close.
    """
    try:
        host, port_str = url.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        send_error(client_socket, 400, "Bad Request")
        return

    if port not in ALLOWED_CONNECT_PORTS:
        log.warning("CONNECT to disallowed port %d blocked", port)
        send_error(client_socket, 403, "Forbidden")
        return

    # Resolve once — reuse IP to prevent DNS rebinding
    ip = resolve_and_check(host)
    if not ip:
        send_error(client_socket, 403, "Forbidden")
        return

    # Connect to upstream with TLS and verify cert
    try:
        raw_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_server_sock.settimeout(RELAY_TIMEOUT)
        raw_server_sock.connect((ip, port))
        upstream_ctx = tls.make_upstream_context(verify=VERIFY_UPSTREAM_CERT)
        server_sock = upstream_ctx.wrap_socket(raw_server_sock, server_hostname=host)
    except ssl.SSLCertVerificationError as exc:
        log.warning("Upstream cert verification failed for %s: %s", host, exc)
        send_error(client_socket, 502, "Bad Gateway")
        return
    except Exception as exc:
        log.error("CONNECT upstream TLS failed for %s:%d — %s", host, port, exc)
        send_error(client_socket, 502, "Bad Gateway")
        return

    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    try:
        client_ctx = tls.get_host_ssl_context(host, _ca_cert, _ca_key)
        client_tls = client_ctx.wrap_socket(client_socket, server_side=True)
    except Exception as exc:
        log.error("Client TLS handshake failed for %s — %s", host, exc)
        server_sock.close()
        return

    log.info("TLS MITM established: %s:%d", host, port)

    # Parse and relay HTTP request/response pairs through the decrypted tunnel
    while True:
        try:
            req = http_parser.HTTPRequest.from_socket(client_tls)
        except (ConnectionResetError, OSError):
            break
        except ValueError as exc:
            log.warning("Bad HTTPS request from %s — %s", host, exc)
            send_error(client_tls, 400, "Bad Request")
            break

        log.info("HTTPS %s %s %s", req.method, req.path, host)

        try:
            server_sock.sendall(req.to_bytes())
            resp = http_parser.HTTPResponse.from_socket(server_sock, req.method)
            client_tls.sendall(resp.to_bytes())
        except Exception as exc:
            log.error("HTTPS relay error for %s: %s", host, exc)
            break

        if not req.is_keep_alive() or not resp.is_keep_alive():
            break

    log.info("TLS MITM closed: %s:%d", host, port)
    for sock in (server_sock, client_tls):
        try:
            sock.close()
        except Exception:
            pass


# Plain HTTP handler
def handle_http(
    client_socket: socket.socket,
    req: http_parser.HTTPRequest,
) -> None:
    """Forward plain HTTP request/response pairs. Reuses the upstream connection
    across keep-alive requests to the same host."""
    server_socket: socket.socket | None = None
    current_host: str | None = None
    current_port: int | None = None

    while True:
        host, port = _http_target(req)
        if not host:
            send_error(client_socket, 400, "Bad Request")
            break

        ip = resolve_and_check(host)
        if not ip:
            send_error(client_socket, 403, "Forbidden")
            break

        # Open a new upstream connection only when target changes
        if server_socket is None or host != current_host or port != current_port:
            if server_socket:
                try:
                    server_socket.close()
                except Exception:
                    pass
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(RELAY_TIMEOUT)
                server_socket.connect((ip, port))
                current_host, current_port = host, port
            except Exception as exc:
                log.error("HTTP connect failed %s:%d — %s", host, port, exc)
                send_error(client_socket, 502, "Bad Gateway")
                break

        log.info("HTTP %s %s -> %s:%d", req.method, req.path, host, port)

        try:
            server_socket.sendall(_to_relative(req).to_bytes())
            resp = http_parser.HTTPResponse.from_socket(server_socket, req.method)
            client_socket.sendall(resp.to_bytes())
        except Exception as exc:
            log.error("HTTP relay error for %s: %s", host, exc)
            break

        if not req.is_keep_alive() or not resp.is_keep_alive():
            break

        try:
            req = http_parser.HTTPRequest.from_socket(client_socket)
        except (ConnectionResetError, ValueError, OSError):
            break

    if server_socket:
        try:
            server_socket.close()
        except Exception:
            pass


# Per-client dispatcher
def handle_client(client_socket: socket.socket, address: tuple) -> None:
    """Parse the incoming request and dispatch to the correct handler."""
    try:
        req = http_parser.HTTPRequest.from_socket(client_socket)
    except (ValueError, ConnectionResetError) as exc:
        log.warning("Bad request from %s: %s", address, exc)
        send_error(client_socket, 400, "Bad Request")
        try:
            client_socket.close()
        except Exception:
            pass
        return

    try:
        if req.method == "CONNECT":
            handle_connect(client_socket, req.path)
        else:
            handle_http(client_socket, req)
    except Exception as exc:
        log.exception("Unexpected error handling %s: %s", address, exc)
        send_error(client_socket, 500, "Internal Server Error")
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


# Server entry point
def start_proxy(host: str = "127.0.0.1", port: int = 8888) -> None:
    """Bind and serve the proxy, dispatching clients to a thread pool."""
    _load_ca()
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((host, port))
    proxy_socket.listen(socket.SOMAXCONN)
    log.info("Proxy listening on %s:%d  (max workers: %d)", host, port, MAX_WORKERS)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        try:
            while True:
                client_socket, address = proxy_socket.accept()
                log.debug("Connection from %s", address)
                pool.submit(handle_client, client_socket, address)
        except KeyboardInterrupt:
            log.info("Shutting down proxy...")
        finally:
            proxy_socket.close()


if __name__ == "__main__":
    start_proxy()
