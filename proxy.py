import socket
import ssl
import threading
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor

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


# Socket relay helpers
def forward(src: socket.socket, dst: socket.socket) -> None:
    """Relay data from src -> dst until the connection closes."""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.close()
            except Exception:
                pass


def send_error(client_socket: socket.socket, status_code: int, reason: str) -> None:
    """Send a minimal HTTP error response."""
    response = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n\r\n"
    )
    try:
        client_socket.sendall(response.encode("utf-8"))
    except Exception:
        pass


# Request parsing
def read_request_headers(client_socket: socket.socket):
    """
    Read bytes from client until the end of HTTP headers (\\r\\n\\r\\n).

    Raises ValueError on:
      - client disconnect before headers complete
      - headers exceeding MAX_HEADER_SIZE (slow-header / header-flood DoS)
      - malformed request line

    Returns (raw_request_bytes, header_text, lines, method, url).
    """
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = client_socket.recv(4096)
        if not chunk:
            raise ValueError("Client closed connection before sending headers")
        raw += chunk
        if len(raw) > MAX_HEADER_SIZE:
            raise ValueError(f"Headers exceeded {MAX_HEADER_SIZE} bytes — possible DoS")

    header_part, _, _ = raw.partition(b"\r\n\r\n")
    header_text = header_part.decode("utf-8", errors="ignore")
    lines = header_text.split("\r\n")

    first_line = lines[0].split()
    if len(first_line) < 2:
        raise ValueError(f"Malformed request line: {lines[0]!r}")

    method, url = first_line[0], first_line[1]
    return raw, header_text, lines, method, url



# CONNECT tunnel handler
def handle_connect(client_socket: socket.socket, url: str) -> None:
    """
    TLS MITM handler for HTTPS CONNECT requests.

    Flow:
      1. Parse host:port from the CONNECT target.
      2. Connect to the real upstream server with TLS (verifying its cert).
      3. Tell the client the tunnel is ready (200 Connection Established).
      4. Wrap the client socket with TLS using a dynamically signed leaf cert.
      5. Relay decrypted plaintext bidirectionally.
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
    t1 = threading.Thread(target=forward, args=(client_tls, server_sock), daemon=True)
    t2 = threading.Thread(target=forward, args=(server_sock, client_tls), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    log.info("TLS MITM closed: %s:%d", host, port)

# Plain HTTP handler
def handle_http(
    client_socket: socket.socket,
    raw_request: bytes,
    lines: list[str],
    url: str,
) -> None:
    """Forward a plain HTTP request and stream the response back."""
    host = None
    port = 80

    if url.startswith("http"):
        try:
            host_part = url.split("/", 3)[2]
            if ":" in host_part:
                host, port_str = host_part.rsplit(":", 1)
                port = int(port_str)
            else:
                host = host_part
        except (IndexError, ValueError):
            send_error(client_socket, 400, "Bad Request")
            return
    else:
        # Relative URL
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host_header = line.split(":", 1)[1].strip()
                if ":" in host_header:
                    host, port_str = host_header.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        send_error(client_socket, 400, "Bad Request")
                        return
                else:
                    host = host_header
                break

    if not host:
        send_error(client_socket, 400, "Bad Request")
        return

    # Resolve once
    ip = resolve_and_check(host)
    if not ip:
        send_error(client_socket, 403, "Forbidden")
        return

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(RELAY_TIMEOUT)
        server_socket.connect((ip, port))
    except Exception as exc:
        log.error("HTTP connection failed to %s:%d - %s", host, port, exc)
        send_error(client_socket, 502, "Bad Gateway")
        return

    log.info("HTTP %s -> %s:%d", lines[0] if lines else "?", host, port)

    try:
        server_socket.sendall(raw_request)
        server_socket.settimeout(RELAY_TIMEOUT)
        while True:
            chunk = server_socket.recv(4096)
            if not chunk:
                break
            client_socket.sendall(chunk)
    except socket.timeout:
        pass  # Server finished sending
    except Exception as exc:
        log.error("Error relaying HTTP response: %s", exc)
    finally:
        server_socket.close()

# Per-client dispatcher
def handle_client(client_socket: socket.socket, address: tuple) -> None:
    """Parse the incoming request and dispatch to the correct handler."""
    try:
        raw_request, header_text, lines, method, url = read_request_headers(client_socket)
    except ValueError as exc:
        log.warning("Bad request from %s: %s", address, exc)
        send_error(client_socket, 400, "Bad Request")
        try:
            client_socket.close()
        except Exception:
            pass
        return

    try:
        if method == "CONNECT":
            handle_connect(client_socket, url)
        else:
            handle_http(client_socket, raw_request, lines, url)
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