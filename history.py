import sqlite3
import threading
import json
import http_parser
import datetime
from contextlib import contextmanager
import logging
from pathlib import Path
from typing import Iterator, Sequence

DB_PATH = Path("history.db")
log = logging.getLogger(__name__)

local = threading.local()

# Returns the database connection
def connection():
    if not getattr(local, "connection", None):
        local.connection = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        local.connection.row_factory = sqlite3.Row
        local.connection.execute("PRAGMA journal_mode=WAL")
        local.connection.execute("PRAGMA synchronous=NORMAL")
    return local.connection

@contextmanager
#Either commits changes to database or undos on error
def tx():
    conn = connection()
    try:
        yield connection
        conn.commit()
    except Exception:
        conn.rollback()
        raise


_DDL = """
CREATE TABLE IF NOT EXISTS flows (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    host             TEXT    NOT NULL,
    port             INTEGER NOT NULL,
    protocol         TEXT    NOT NULL,
 
    req_method       TEXT    NOT NULL,
    req_path         TEXT    NOT NULL,
    req_version      TEXT    NOT NULL,
    req_headers      TEXT    NOT NULL,
    req_body         BLOB,
 
    req_mod_headers  TEXT,
    req_mod_body     BLOB,
 
    resp_status      INTEGER,
    resp_reason      TEXT,
    resp_version     TEXT,
    resp_headers     TEXT,
    resp_body        BLOB,
 
    resp_mod_headers TEXT,
    resp_mod_body    BLOB,
 
    content_type     TEXT,
    resp_size        INTEGER
);
 
CREATE INDEX IF NOT EXISTS idx_host        ON flows(host);
CREATE INDEX IF NOT EXISTS idx_method      ON flows(req_method);
CREATE INDEX IF NOT EXISTS idx_status      ON flows(resp_status);
CREATE INDEX IF NOT EXISTS idx_timestamp   ON flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_host_method ON flows(host, req_method);
"""

def makeDB(path: Path = DB_PATH):
    global DB_PATH
    DB_PATH = path
    with tx() as connection:
        connection.executescript(_DDL)
    log.info("History Database ready: %s", DB_PATH.resolve())

# Helpers
#----------------------------
def convertHeadersToJson(raw: list[tuple[str, str]]):
    return json.dumps(raw)

def printTimestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")

def contentType(headers: dict[str,str]):
    ct = headers.get("content-type", "")
    return ct.split(";")[0].strip()
#----------------------------

def log_flow(
    *,
    host: str,
    port: int,
    protocol: str,
    original_request: http_parser.HTTPRequest,
    modified_request: http_parser.HTTPRequest | None = None,
    original_response: http_parser.HTTPResponse | None = None,
    modified_response: http_parser.HTTPResponse | None = None,
) -> int:
    """
    Insert a complete flow into the history database.
 
    Pass modified_request / modified_response only when the proxy has actually
    changed something — they are stored as NULL otherwise.
 
    Returns the new row id.
    """
    req = original_request
    resp = original_response
 
    # Detect whether request/response were genuinely modified
    req_mod_headers: str | None = None
    req_mod_body: bytes | None = None
    if modified_request is not None and (
        modified_request.raw_headers != req.raw_headers
        or modified_request.body != req.body
    ):
        req_mod_headers = convertHeadersToJson(modified_request.raw_headers)
        req_mod_body = modified_request.body or None
 
    resp_mod_headers: str | None = None
    resp_mod_body: bytes | None = None
    if resp is not None and modified_response is not None and (
        modified_response.raw_headers != resp.raw_headers
        or modified_response.body != resp.body
    ):
        resp_mod_headers = convertHeadersToJson(modified_response.raw_headers)
        resp_mod_body = modified_response.body or None
 
    with tx() as connection:
        cur = connection.execute(
            """
            INSERT INTO flows (
                timestamp, host, port, protocol,
                req_method, req_path, req_version, req_headers, req_body,
                req_mod_headers, req_mod_body,
                resp_status, resp_reason, resp_version, resp_headers, resp_body,
                resp_mod_headers, resp_mod_body,
                content_type, resp_size
            ) VALUES (
                :ts, :host, :port, :proto,
                :method, :path, :ver, :req_hdrs, :req_body,
                :req_mod_hdrs, :req_mod_body,
                :status, :reason, :rver, :resp_hdrs, :resp_body,
                :resp_mod_hdrs, :resp_mod_body,
                :ct, :size
            )
            """,
            {
                "ts": printTimestamp(),
                "host": host,
                "port": port,
                "proto": protocol,
                "method": req.method,
                "path": req.path,
                "ver": req.version,
                "req_hdrs": convertHeadersToJson(req.raw_headers),
                "req_body": req.body or None,
                "req_mod_hdrs": req_mod_headers,
                "req_mod_body": req_mod_body,
                "status": resp.status_code if resp else None,
                "reason": resp.reason if resp else None,
                "rver": resp.version if resp else None,
                "resp_hdrs": convertHeadersToJson(resp.raw_headers) if resp else None,
                "resp_body": resp.body or None,
                "resp_mod_hdrs": resp_mod_headers,
                "resp_mod_body": resp_mod_body,
                "ct": _content_type(resp.headers) if resp else None,
                "size": len(resp.body) if resp else None,
            },
        )
        row_id: int = cur.lastrowid  # type: ignore[assignment]
 
    log.debug(
        "Logged flow #%d  %s %s %s → %s",
        row_id, protocol.upper(), req.method, host + req.path,
        resp.status_code if resp else "—",
    )
    return row_id

def search(
    *,
    host: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    protocol: str | None = None,
    path_contains: str | None = None,
    content_type: str | None = None,
    modified_only: bool = False,
    since: str | None = None,       # ISO-8601 string
    until: str | None = None,       # ISO-8601 string
    limit: int = 100,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """
    Flexible flow search.  All filters are optional and AND-combined.
 
    Parameters
    ----------
    host            Exact host match.
    method          Exact HTTP method (GET, POST, …).
    status_code     Exact response status.
    protocol        'http' or 'https'.
    path_contains   Substring match on req_path (case-insensitive).
    content_type    Prefix match on Content-Type (e.g. 'application/json').
    modified_only   If True, return only flows where something was rewritten.
    since / until   Inclusive timestamp bounds (ISO-8601).
    limit / offset  Pagination.
 
    Returns a list of sqlite3.Row objects (dict-like).
    """
    clauses: list[str] = []
    params: list[object] = []
 
    if host is not None:
        clauses.append("host = ?")
        params.append(host)
    if method is not None:
        clauses.append("req_method = ?")
        params.append(method.upper())
    if status_code is not None:
        clauses.append("resp_status = ?")
        params.append(status_code)
    if protocol is not None:
        clauses.append("protocol = ?")
        params.append(protocol.lower())
    if path_contains is not None:
        clauses.append("req_path LIKE ? ESCAPE '\\'")
        params.append(f"%{path_contains}%")
    if content_type is not None:
        clauses.append("content_type LIKE ? ESCAPE '\\'")
        params.append(f"{content_type}%")
    if modified_only:
        clauses.append(
            "(req_mod_headers IS NOT NULL OR resp_mod_headers IS NOT NULL)"
        )
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until is not None:
        clauses.append("timestamp <= ?")
        params.append(until)
 
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, timestamp, host, port, protocol,
               req_method, req_path, resp_status, resp_reason,
               content_type, resp_size,
               req_mod_headers IS NOT NULL AS req_modified,
               resp_mod_headers IS NOT NULL AS resp_modified
        FROM flows
        {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params.extend([limit, offset])
    return connection().execute(sql, params).fetchall()

def getFlow(flow_id: int):
    rows = connection().execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchall()
    return rows[0] if rows else None

def deleteFlow(flow_id: int):
    with tx() as connection:
        cur = connection.execute("DELETE FROM flows WHERE id = ?", (flow_id,))
        return cur.rowcount > 0

def clear():
    with tx() as connection:
        cur = connection.execute("DELETE FROM flows")
        return cur.rowcount

def stats() -> dict[str, object]:
    """Return summary statistics over the whole history."""
    row = connection().execute(
        """
        SELECT
            COUNT(*)                                   AS total,
            COUNT(DISTINCT host)                       AS unique_hosts,
            SUM(req_mod_headers IS NOT NULL
                OR resp_mod_headers IS NOT NULL)       AS modified_count,
            MIN(timestamp)                             AS earliest,
            MAX(timestamp)                             AS latest
        FROM flows
        """
    ).fetchone()
 
    by_method: list[sqlite3.Row] = _conn().execute(
        "SELECT req_method, COUNT(*) AS n FROM flows GROUP BY req_method ORDER BY n DESC"
    ).fetchall()
 
    by_status: list[sqlite3.Row] = _conn().execute(
        "SELECT resp_status, COUNT(*) AS n FROM flows GROUP BY resp_status ORDER BY n DESC"
    ).fetchall()
 
    return {
        "total": row["total"],
        "unique_hosts": row["unique_hosts"],
        "modified_count": row["modified_count"],
        "earliest": row["earliest"],
        "latest": row["latest"],
        "by_method": {r["req_method"]: r["n"] for r in by_method},
        "by_status": {r["resp_status"]: r["n"] for r in by_status},
    }

