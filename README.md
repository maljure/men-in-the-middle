# Intercepting Proxy & Vulnerability Scanner — Build Roadmap

> Python-based Burp Suite / OWASP ZAP alternative.
> Intercept, inspect, drop, and modify HTTP/HTTPS traffic in real time.
> Modular vulnerability scanning: SQLi, XSS, header analysis, directory fuzzing.

---

## Phase 1 — TLS Interception Layer || $${\color{green}COMPLETE}$$

- Generate a root CA cert and key on first run, persist to disk
- Build a dynamic cert factory that signs per-hostname certs from your CA
- Add a cert cache (scaffold already in proxy.py)
- Replace the blind CONNECT relay with a TLS MITM — wrap both sides of the tunnel with `ssl.wrap_socket()`
- Verify the real server's cert on the upstream side
- Write a CA install helper so users can trust it in their OS/browser store

---

## Phase 2 — HTTP Parser || $${\color{green}COMPLETE}$$

- Parse raw bytes into structured request/response objects (method, path, headers dict, body)
- Handle chunked transfer encoding
- Handle compressed bodies (gzip/deflate) — decompress for inspection, recompress before forwarding
- Handle keep-alive and connection reuse
- Preserve the ability to re-serialize back to raw bytes after modification

---

## Phase 3 — Intercept & Modify Engine || $${\color{green}COMPLETE}$$

- Build a thread-safe queue that holds requests before forwarding
- Add intercept rules (by host, path, method, content-type)
- Build a drop/forward/modify decision loop
- Allow body and header editing on intercepted requests
- Do the same for responses

---

## Phase 4 — History Log

- Store every request/response pair to SQLite
- Index by host, method, status code, timestamp
- Add search and filter capability
- Store original and modified versions separately

---

## Phase 5 — CLI Interface

- Live traffic feed printed to terminal
- Intercept mode toggle
- Commands to forward, drop, or edit a queued request
- Replay a request from history
- Filter display by host or status code

---

## Phase 6 — Vulnerability Scanners

Build a scanner plugin interface — each scanner receives a request object and returns findings.

| Scanner | What it does |
|---|---|
| **SQLi** | Inject payloads into query params and body fields, detect error patterns in response |
| **XSS** | Inject payloads into params, detect reflection in response body |
| **Header Analysis** | Check for missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **Directory Scanner** | Fuzz common paths against the target, flag 200/403 responses |
| **Sensitive Data** | Regex scan responses for API keys, tokens, and PII patterns |

---

## Phase 7 — Fuzzer

- Build a wordlist/payload loader
- Identify injectable points in a request automatically (params, headers, body fields)
- Iterate payloads, send modified requests, collect responses
- Diff responses to identify anomalies (length change, status change, error strings)

---

## Phase 8 — Reporting

- Aggregate findings from all scanners per host
- Severity classification: Info / Low / Medium / High
- Export to JSON and plain text
- Deduplicate findings

---

Phases 1 and 2 are blockers — nothing else works without TLS interception and a proper HTTP parser.
The CLI in Phase 5 makes everything from Phase 6 onward much easier to develop and debug interactively.
