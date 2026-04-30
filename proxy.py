import os
import dataclasses
import socket
import ssl
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import http_parser
import intercept
import tls
import history

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Maximum concurrent client threads
MAX_WORKERS = 100

# Relay/read timeout
RELAY_TIMEOUT = 300

# Maximum size of HTTP request headers
MAX_HEADER_SIZE = 65536

# Disabled upstream verification to allow self-signed certs (e.g., IoT, local dev, CTF targets)
VERIFY_UPSTREAM_CERT = False

# CA
_ca_cert = None
_ca_key = None

def _load_ca() -> None:
    global _ca_cert, _ca_key
    _ca_cert, _ca_key = tls.load_or_create_ca()

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
    """
    try:
        host, port_str = url.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        send_error(client_socket, 400, "Bad Request")
        return

    # Connect to upstream with TLS
    try:
        raw_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_server_sock.settimeout(RELAY_TIMEOUT)
        # Directly connecting to host/port (SSRF protections removed)
        raw_server_sock.connect((host, port))
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

        req = intercept.engine.intercept_request(req)
        if req is None:
            log.info("HTTPS request to %s dropped by intercept engine", host)
            send_error(client_tls, 502, "Bad Gateway")
            break

        try:
            server_sock.sendall(req.to_bytes())
            resp = http_parser.HTTPResponse.from_socket(server_sock, req.method)
        except Exception as exc:
            log.error("HTTPS relay error for %s: %s", host, exc)
            break

        resp = intercept.engine.intercept_response(resp)
        if resp is None:
            log.info("HTTPS response from %s dropped by intercept engine", host)
            break
        try: 
            client_tls.sendall(resp.to_bytes())
        except Exception as exc:
            log.error("HTTPS client send error for %s: %s", host, exc)
            break
        try:
            history.log_flow(
                host=host,
                port=port,
                protocol="https",
                original_request=req,
                original_response=resp,
            )
        except Exception as exc:
            log.warning("History log failed for %s: %s", host, exc)
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
                # Directly connecting to host/port (SSRF protections removed)
                server_socket.connect((host, port))
                current_host, current_port = host, port
            except Exception as exc:
                log.error("HTTP connect failed %s:%d — %s", host, port, exc)
                send_error(client_socket, 502, "Bad Gateway")
                break

        log.info("HTTP %s %s -> %s:%d", req.method, req.path, host, port)

        intercepted_req = intercept.engine.intercept_request(req)
        
        # Check the new variable for the drop signal
        if intercepted_req is None:
            log.info("HTTPS request to %s dropped by intercept engine", host)
            send_error(client_socket, 502, "Bad Gateway") 
            break
        req = intercepted_req


        try:
            server_socket.sendall(_to_relative(req).to_bytes())
            resp = http_parser.HTTPResponse.from_socket(server_socket, req.method)
        except Exception as exc:
            log.error("HTTP relay error for %s: %s", host, exc)
            break

        intercepted_resp = intercept.engine.intercept_response(resp)
        
        if intercepted_resp is None:
            log.info("HTTPS response from %s dropped by intercept engine", host)
            break
            
        resp = intercepted_resp

        try:
            client_socket.sendall(resp.to_bytes())
        except Exception as exc:
            log.error("HTTP client send error for %s: %s", host, exc)
            break
        try:
            history.log_flow(
                host=host,
                port=port,
                protocol="http",
                original_request=req,
                original_response=resp,
            )
        except Exception as exc:
            log.warning("History log failed for %s: %s", host, exc)
        
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
    history.makeDB()
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((host, port))
    proxy_socket.listen(socket.SOMAXCONN)
    
    # Allows Ctrl+C to interrupt the loop by unblocking the accept() call every second
    proxy_socket.settimeout(1.0)
    
    log.info("Proxy listening on %s:%d  (max workers: %d)", host, port, MAX_WORKERS)

    # Removed the 'with' block to prevent it from hanging on shutdown
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        while True:
            try:
                client_socket, address = proxy_socket.accept()
                # Use RELAY_TIMEOUT instead of None so keep-alive connections eventually die
                client_socket.settimeout(RELAY_TIMEOUT) 
                log.debug("Connection from %s", address)
                pool.submit(handle_client, client_socket, address)
            except socket.timeout:
                # Normal behavior from the 1.0s timeout; just loop again
                continue
    except KeyboardInterrupt:
        log.info("Shutting down proxy...")
    finally:
        proxy_socket.close()
        pool.shutdown(wait=False)
        os._exit(0)  # Instantly returns control to the terminal

if __name__ == "__main__":
    start_proxy()