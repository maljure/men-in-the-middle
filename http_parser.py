"""Phase 2 — HTTP/1.x parser.

Parse raw bytes or socket streams into HTTPRequest / HTTPResponse objects,
then re-serialise after inspection or modification.

Supports:
  - Chunked transfer-encoding (decoded on parse, removed on serialise)
  - gzip / deflate / br decompression (re-compressed if recompress=True)
  - Keep-alive / connection-reuse detection
  - Header order and original capitalisation preserved on re-serialisation
"""

from __future__ import annotations

import gzip
import io
import socket
import zlib
from dataclasses import dataclass

MAX_HEADER_BYTES = 65_536       # 64 KB
MAX_BODY_BYTES   = 52_428_800   # 50 MB


# ── socket helpers ────────────────────────────────────────────────────────────

def _recv_until_crlf2(sock: socket.socket) -> bytes:
    """Read from *sock* until \\r\\n\\r\\n, enforcing MAX_HEADER_BYTES."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionResetError("Connection closed before headers were complete")
        buf += chunk
        if len(buf) > MAX_HEADER_BYTES:
            raise ValueError(f"Header section exceeds {MAX_HEADER_BYTES} bytes")
    return buf


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(4096, n - len(buf)))
        if not chunk:
            raise ConnectionResetError(
                f"Connection closed after {len(buf)}/{n} body bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def _recv_until_close(sock: socket.socket, seed: bytes = b"") -> bytes:
    """Read until EOF — used for connection-close response bodies."""
    buf = bytearray(seed)
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > MAX_BODY_BYTES:
            raise ValueError("Response body exceeds MAX_BODY_BYTES")
    return bytes(buf)


# ── chunked transfer-encoding ─────────────────────────────────────────────────

class _SockBuf:
    """Drain *seed* bytes first, then pull from *sock* on demand."""

    __slots__ = ("_buf", "_sock")

    def __init__(self, seed: bytes, sock: socket.socket) -> None:
        self._buf = bytearray(seed)
        self._sock = sock

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("Connection closed inside chunked body")
            self._buf.extend(chunk)
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def readline(self) -> bytes:
        while b"\r\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("Connection closed inside chunked body")
            self._buf.extend(chunk)
        idx = self._buf.index(b"\n")
        line = bytes(self._buf[: idx + 1])
        del self._buf[: idx + 1]
        return line


def _decode_chunked_stream(seed: bytes, sock: socket.socket) -> bytes:
    r = _SockBuf(seed, sock)
    out = io.BytesIO()
    while True:
        size_line = r.readline().strip()
        chunk_size = int(size_line.split(b";")[0], 16)
        if chunk_size == 0:
            r.read(2)  # terminal CRLF
            break
        out.write(r.read(chunk_size))
        r.read(2)  # per-chunk trailing CRLF
        if out.tell() > MAX_BODY_BYTES:
            raise ValueError("Chunked body exceeds MAX_BODY_BYTES")
    return out.getvalue()


def _decode_chunked_bytes(data: bytes) -> bytes:
    """Decode a chunked body that is already fully buffered."""
    out = io.BytesIO()
    pos = 0
    while pos < len(data):
        end = data.find(b"\r\n", pos)
        if end == -1:
            break
        chunk_size = int(data[pos:end].split(b";")[0], 16)
        if chunk_size == 0:
            break
        start = end + 2
        out.write(data[start : start + chunk_size])
        pos = start + chunk_size + 2
    return out.getvalue()


# ── compression ───────────────────────────────────────────────────────────────

def _decompress(data: bytes, encoding: str) -> bytes:
    enc = encoding.lower().strip()
    if not enc or enc == "identity":
        return data
    if enc in ("gzip", "x-gzip"):
        return gzip.decompress(data)
    if enc == "deflate":
        try:
            return zlib.decompress(data)
        except zlib.error:
            return zlib.decompress(data, -15)  # raw deflate (no zlib header)
    if enc == "br":
        try:
            import brotli  # type: ignore[import]
            return brotli.decompress(data)
        except ImportError as exc:
            raise ImportError("Install 'brotli' to decompress br-encoded bodies") from exc
    return data  # unknown encoding — pass through unchanged


def _compress(data: bytes, encoding: str) -> bytes:
    enc = encoding.lower().strip()
    if not enc or enc == "identity":
        return data
    if enc in ("gzip", "x-gzip"):
        return gzip.compress(data)
    if enc == "deflate":
        return zlib.compress(data)
    if enc == "br":
        try:
            import brotli  # type: ignore[import]
            return brotli.compress(data)
        except ImportError as exc:
            raise ImportError("Install 'brotli' to compress br-encoded bodies") from exc
    return data


# ── header parsing ────────────────────────────────────────────────────────────

def _parse_headers(
    lines: list[str],
) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """
    Return (headers_lower, raw_headers).

    headers_lower — dict with lower-cased keys; duplicate values joined by ', '
    raw_headers   — ordered list of (original-case name, value)
    """
    headers: dict[str, str] = {}
    raw: list[tuple[str, str]] = []
    for line in lines:
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        raw.append((name, value))
        key = name.lower()
        headers[key] = (headers[key] + ", " + value) if key in headers else value
    return headers, raw


# ── body reader ───────────────────────────────────────────────────────────────

def _read_body(
    sock: socket.socket,
    headers: dict[str, str],
    leftover: bytes,
    *,
    is_response: bool = False,
    no_body: bool = False,
) -> bytes:
    """
    Read the message body using already-parsed headers and any *leftover* bytes
    captured while reading headers.

    Responses with neither Content-Length nor Transfer-Encoding are read until
    the server closes the connection (connection-close semantics).
    """
    if no_body:
        return b""

    te = headers.get("transfer-encoding", "")
    if "chunked" in te.lower():
        body = _decode_chunked_stream(leftover, sock)
    else:
        cl_raw = headers.get("content-length", "").strip()
        if cl_raw:
            cl = int(cl_raw)
            if cl == 0:
                return b""
            needed = cl - len(leftover)
            body = leftover + _recv_exactly(sock, needed) if needed > 0 else leftover[:cl]
        elif is_response:
            # No framing info → read until the server closes the connection
            body = _recv_until_close(sock, leftover)
        else:
            body = b""  # request with no declared body

    ce = headers.get("content-encoding", "")
    if ce:
        body = _decompress(body, ce)

    return body


# ── serialisation helper ──────────────────────────────────────────────────────

def _build_headers_for_wire(
    body: bytes,
    raw_headers: list[tuple[str, str]],
    headers: dict[str, str],
    *,
    recompress: bool,
) -> tuple[bytes, list[tuple[str, str]]]:
    """
    Strip framing/encoding headers, optionally recompress, then set Content-Length.

    Always removes Transfer-Encoding (we flatten to Content-Length).
    Removes Content-Encoding unless recompress=True.
    """
    skip = {"transfer-encoding", "content-length", "content-encoding"}
    out: list[tuple[str, str]] = [
        (k, v) for k, v in raw_headers if k.lower() not in skip
    ]

    ce = headers.get("content-encoding", "")
    if recompress and ce and body:
        body = _compress(body, ce)
        out.append(("Content-Encoding", ce))

    if body:
        out.append(("Content-Length", str(len(body))))

    return body, out


# ── public dataclasses ────────────────────────────────────────────────────────

@dataclass
class HTTPRequest:
    method: str
    path: str                           # includes query string
    version: str                        # e.g. "HTTP/1.1"
    headers: dict[str, str]             # lower-cased keys for lookup
    raw_headers: list[tuple[str, str]]  # original capitalisation, order preserved
    body: bytes                         # decoded: unchunked + decompressed

    # ── convenience ──────────────────────────────────────────────────────────

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())

    def is_keep_alive(self) -> bool:
        conn = (self.header("connection") or "").lower()
        return "close" not in conn if self.version == "HTTP/1.1" else "keep-alive" in conn

    # ── parsing ───────────────────────────────────────────────────────────────

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "HTTPRequest":
        """Read and parse a complete HTTP request from a live socket."""
        raw = _recv_until_crlf2(sock)
        header_part, _, leftover = raw.partition(b"\r\n\r\n")
        lines = header_part.decode("utf-8", errors="replace").split("\r\n")

        parts = lines[0].split()
        if len(parts) < 3:
            raise ValueError(f"Malformed request line: {lines[0]!r}")
        method, path, version = parts[0], parts[1], parts[2]

        headers, raw_headers = _parse_headers(lines[1:])
        body = _read_body(sock, headers, leftover)
        return cls(
            method=method, path=path, version=version,
            headers=headers, raw_headers=raw_headers, body=body,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "HTTPRequest":
        """Parse from a complete in-memory byte string."""
        header_part, _, body_bytes = data.partition(b"\r\n\r\n")
        lines = header_part.decode("utf-8", errors="replace").split("\r\n")

        parts = lines[0].split()
        if len(parts) < 3:
            raise ValueError(f"Malformed request line: {lines[0]!r}")
        method, path, version = parts[0], parts[1], parts[2]

        headers, raw_headers = _parse_headers(lines[1:])

        te = headers.get("transfer-encoding", "")
        if "chunked" in te.lower():
            body_bytes = _decode_chunked_bytes(body_bytes)
        else:
            cl = int(headers.get("content-length", "0") or "0")
            body_bytes = body_bytes[:cl] if cl else b""

        ce = headers.get("content-encoding", "")
        if ce:
            body_bytes = _decompress(body_bytes, ce)

        return cls(
            method=method, path=path, version=version,
            headers=headers, raw_headers=raw_headers, body=body_bytes,
        )

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self, *, recompress: bool = False) -> bytes:
        """
        Serialise to HTTP wire bytes.

        Transfer-Encoding is always removed; Content-Length is set from body.
        Content-Encoding is removed unless recompress=True (body re-compressed).
        """
        body, hdrs = _build_headers_for_wire(
            self.body, self.raw_headers, self.headers, recompress=recompress
        )
        out = io.BytesIO()
        out.write(f"{self.method} {self.path} {self.version}\r\n".encode())
        for name, value in hdrs:
            out.write(f"{name}: {value}\r\n".encode())
        out.write(b"\r\n")
        out.write(body)
        return out.getvalue()


@dataclass
class HTTPResponse:
    version: str
    status_code: int
    reason: str
    headers: dict[str, str]
    raw_headers: list[tuple[str, str]]
    body: bytes

    # ── convenience ──────────────────────────────────────────────────────────

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def is_keep_alive(self) -> bool:
        conn = (self.header("connection") or "").lower()
        return "close" not in conn if self.version == "HTTP/1.1" else "keep-alive" in conn

    # ── parsing ───────────────────────────────────────────────────────────────

    @classmethod
    def from_socket(
        cls, sock: socket.socket, request_method: str = "GET"
    ) -> "HTTPResponse":
        """Read and parse a complete HTTP response from a live socket."""
        raw = _recv_until_crlf2(sock)
        header_part, _, leftover = raw.partition(b"\r\n\r\n")
        lines = header_part.decode("utf-8", errors="replace").split("\r\n")

        parts = lines[0].split(None, 2)
        if len(parts) < 2:
            raise ValueError(f"Malformed status line: {lines[0]!r}")
        version = parts[0]
        status_code = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""

        headers, raw_headers = _parse_headers(lines[1:])

        no_body = (
            request_method == "HEAD"
            or status_code in (204, 304)
            or 100 <= status_code < 200
        )
        body = _read_body(
            sock, headers, leftover, is_response=True, no_body=no_body
        )
        return cls(
            version=version, status_code=status_code, reason=reason,
            headers=headers, raw_headers=raw_headers, body=body,
        )

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self, *, recompress: bool = False) -> bytes:
        body, hdrs = _build_headers_for_wire(
            self.body, self.raw_headers, self.headers, recompress=recompress
        )
        out = io.BytesIO()
        out.write(f"{self.version} {self.status_code} {self.reason}\r\n".encode())
        for name, value in hdrs:
            out.write(f"{name}: {value}\r\n".encode())
        out.write(b"\r\n")
        out.write(body)
        return out.getvalue()
