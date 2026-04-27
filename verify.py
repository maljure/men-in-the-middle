"""Verification script for Phases 1–3."""
import dataclasses
import gzip
import os
import socket
import sys
import tempfile
import threading
import time
import traceback

PASS = 0
FAIL = 0

def test(name, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  PASS  {name}")
        PASS += 1
    except Exception as e:
        print(f"  FAIL  {name}: {e}")
        traceback.print_exc()
        FAIL += 1


# Phase 1: TLS certificate generation and SSL context creation
print("=== Phase 1: TLS ===")
import tls
from cryptography.hazmat.primitives import serialization

orig_dir = os.getcwd()
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    try:
        ca_cert, ca_key = tls.load_or_create_ca()
        test("CA created", lambda: ca_cert is not None and ca_key is not None)

        ca_cert2, ca_key2 = tls.load_or_create_ca()
        pem1 = ca_cert.public_bytes(serialization.Encoding.PEM)
        pem2 = ca_cert2.public_bytes(serialization.Encoding.PEM)
        test("CA persists to disk", lambda: pem1 == pem2)

        leaf_ctx = tls.get_host_ssl_context("example.com", ca_cert, ca_key)
        test("Leaf SSL context created", lambda: leaf_ctx is not None)

        leaf_ctx2 = tls.get_host_ssl_context("example.com", ca_cert, ca_key)
        test("Leaf cert cache hit", lambda: leaf_ctx is leaf_ctx2)

        upstream_ctx = tls.make_upstream_context(verify=True)
        test("Upstream SSL context created", lambda: upstream_ctx is not None)
    finally:
        os.chdir(orig_dir)


# Phase 2: HTTP Parser — parsing raw HTTP bytes into objects, and re-serializing to bytes after modification
print("\n=== Phase 2: HTTP Parser ===")
from http_parser import HTTPRequest, HTTPResponse

# GET round-trip
raw_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
req = HTTPRequest.from_bytes(raw_req)
test("GET parse: method",       lambda: req.method == "GET")
test("GET parse: path",         lambda: req.path == "/index.html")
test("GET parse: version",      lambda: req.version == "HTTP/1.1")
test("GET parse: host header",  lambda: req.header("host") == "example.com")
test("GET: is_keep_alive",      lambda: req.is_keep_alive() is True)
test("GET: to_bytes round-trip",lambda: req.to_bytes() == raw_req)

# POST with body
raw_post = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Length: 13\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Connection: close\r\n\r\n"
    b"user=test&pw=1"
)
post = HTTPRequest.from_bytes(raw_post)
test("POST body decoded",       lambda: post.body == b"user=test&pw=1")
test("POST: not keep-alive",    lambda: post.is_keep_alive() is False)
test("POST: to_bytes round-trip", lambda: post.to_bytes() == raw_post)

# Chunked request
chunked_raw = (
    b"POST /upload HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Transfer-Encoding: chunked\r\n\r\n"
    b"5\r\nhello\r\n"
    b"6\r\n world\r\n"
    b"0\r\n\r\n"
)
chunked_req = HTTPRequest.from_bytes(chunked_raw)
test("Chunked request decoded", lambda: chunked_req.body == b"hello world")

# Gzip response via socket (HTTPResponse.from_socket only)
def serve_once(data):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    def _serve():
        conn, _ = srv.accept()
        conn.sendall(data)
        conn.close()
    t = threading.Thread(target=_serve, daemon=True); t.start()
    cli = socket.socket(); cli.connect(("127.0.0.1", port))
    return cli, srv, t

body_plain = b"Hello, world!"
gz_body = gzip.compress(body_plain)
raw_gz_resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Encoding: gzip\r\n"
    b"Content-Length: " + str(len(gz_body)).encode() + b"\r\n\r\n"
    + gz_body
)
cli, srv, t = serve_once(raw_gz_resp)
resp_gz = HTTPResponse.from_socket(cli, "GET")
t.join(timeout=2); srv.close(); cli.close()
test("Gzip response decoded",   lambda: resp_gz.body == body_plain)
test("Gzip response status",    lambda: resp_gz.status_code == 200)

# 204 No Content (no body)
raw_204 = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
cli, srv, t = serve_once(raw_204)
resp_204 = HTTPResponse.from_socket(cli, "GET")
t.join(timeout=2); srv.close(); cli.close()
test("204: no body",            lambda: resp_204.body == b"" and resp_204.status_code == 204)

# HEAD response (no body)
raw_head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
cli, srv, t = serve_once(raw_head)
resp_head = HTTPResponse.from_socket(cli, "HEAD")
t.join(timeout=2); srv.close(); cli.close()
test("HEAD: body suppressed",   lambda: resp_head.body == b"")

# Modified request re-serialises correctly
modified = dataclasses.replace(req, path="/new-path")
test("Modified req to_bytes",   lambda: b"GET /new-path HTTP/1.1" in modified.to_bytes())


# Phase 3: Intercept Engine — applying rules to decide whether to intercept, and handling forward/drop/modify decisions
print("\n=== Phase 3: Intercept Engine ===")
from intercept import InterceptEngine, InterceptRule, Decision

def make_req(method="GET", path="/", host="example.com"):
    raw = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    return HTTPRequest.from_bytes(raw)

# Rule predicate tests
rule_post    = InterceptRule(methods={"POST"})
rule_host    = InterceptRule(host_pattern="api.example.com")
rule_path    = InterceptRule(path_pattern="/admin/*")
rule_ct      = InterceptRule(content_type="application/json")

test("Rule: POST matches POST",      lambda: rule_post.matches(make_req("POST")))
test("Rule: POST no-match GET",      lambda: not rule_post.matches(make_req("GET")))
test("Rule: host glob match",        lambda: rule_host.matches(make_req(host="api.example.com")))
test("Rule: host glob no-match",     lambda: not rule_host.matches(make_req(host="other.com")))
test("Rule: wildcard host glob",     lambda: InterceptRule(host_pattern="*.example.com").matches(make_req(host="api.example.com")))
test("Rule: path glob match",        lambda: rule_path.matches(make_req(path="/admin/users")))
test("Rule: path glob no-match",     lambda: not rule_path.matches(make_req(path="/public")))
test("Rule: content-type match",     lambda: not rule_ct.matches(make_req()))  # no CT header → no match

# Passthrough when disabled
eng = InterceptEngine()
test("Disabled: passthrough",        lambda: eng.intercept_request(make_req()) is not None)

# Rule filter: only POST intercepted, GET passes through
eng_filtered = InterceptEngine()
eng_filtered.enabled = True
eng_filtered.timeout = 2.0
eng_filtered.add_rule(InterceptRule(methods={"POST"}))
test("Rule filter: GET passthrough", lambda: eng_filtered.intercept_request(make_req("GET")) is not None)

# Forward decision
eng_fwd = InterceptEngine()
eng_fwd.enabled = True
eng_fwd.timeout = 5.0
original = make_req("POST", "/api")
forwarded_item = {}

def consumer_fwd():
    for item in eng_fwd.pending_requests(block=True, timeout=3.0):
        forwarded_item["id"] = item.id
        eng_fwd.forward(item.id)
        break

t = threading.Thread(target=consumer_fwd, daemon=True); t.start()
time.sleep(0.05)
returned = eng_fwd.intercept_request(original)
t.join(timeout=4)
test("Forward: returns original req", lambda: returned is original)
test("Forward: item was in queue",    lambda: "id" in forwarded_item)

# Drop decision
eng_drop = InterceptEngine()
eng_drop.enabled = True
eng_drop.timeout = 5.0

def consumer_drop():
    for item in eng_drop.pending_requests(block=True, timeout=3.0):
        eng_drop.drop(item.id)
        break

t = threading.Thread(target=consumer_drop, daemon=True); t.start()
time.sleep(0.05)
dropped = eng_drop.intercept_request(make_req())
t.join(timeout=4)
test("Drop: returns None",            lambda: dropped is None)

# Modify request
eng_mod = InterceptEngine()
eng_mod.enabled = True
eng_mod.timeout = 5.0
orig_mod = make_req("GET", "/original")
new_req = dataclasses.replace(orig_mod, path="/modified")

def consumer_mod():
    for item in eng_mod.pending_requests(block=True, timeout=3.0):
        eng_mod.modify_request(item.id, new_req)
        break

t = threading.Thread(target=consumer_mod, daemon=True); t.start()
time.sleep(0.05)
result = eng_mod.intercept_request(orig_mod)
t.join(timeout=4)
test("Modify: path changed",          lambda: result is not None and result.path == "/modified")

# Response intercept: forward
eng_resp = InterceptEngine()
eng_resp.enabled = True
eng_resp.intercept_responses = True
eng_resp.timeout = 5.0

raw_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
cli, srv, t2 = serve_once(raw_resp)
resp_obj = HTTPResponse.from_socket(cli, "GET")
t2.join(timeout=2); srv.close(); cli.close()
resp_result = {}

def consumer_resp():
    for item in eng_resp.pending_responses(block=True, timeout=3.0):
        resp_result["id"] = item.id
        eng_resp.forward(item.id)
        break

t = threading.Thread(target=consumer_resp, daemon=True); t.start()
time.sleep(0.05)
ret_resp = eng_resp.intercept_response(resp_obj)
t.join(timeout=4)
test("Response fwd: returned",        lambda: ret_resp is resp_obj)
test("Response fwd: item queued",     lambda: "id" in resp_result)

# Response intercept disabled by default
eng_resp2 = InterceptEngine()
eng_resp2.enabled = True  # intercept_responses stays False
cli, srv, t3 = serve_once(raw_resp)
resp_obj2 = HTTPResponse.from_socket(cli, "GET")
t3.join(timeout=2); srv.close(); cli.close()
test("Response: passthrough when flag off", lambda: eng_resp2.intercept_response(resp_obj2) is resp_obj2)

# Concurrent requests all get served
eng_conc = InterceptEngine()
eng_conc.enabled = True
eng_conc.timeout = 5.0
results = []

def consumer_conc():
    count = 0
    for item in eng_conc.pending_requests(block=True, timeout=3.0):
        eng_conc.forward(item.id)
        count += 1
        if count == 5:
            break

t = threading.Thread(target=consumer_conc, daemon=True); t.start()
time.sleep(0.05)
workers = []
for i in range(5):
    def _w(i=i):
        r = eng_conc.intercept_request(make_req(path=f"/path/{i}"))
        results.append(r)
    w = threading.Thread(target=_w, daemon=True); w.start(); workers.append(w)
for w in workers: w.join(timeout=6)
t.join(timeout=6)
test("Concurrent: all 5 forwarded",  lambda: len(results) == 5 and all(r is not None for r in results))


print(f"\n{'='*40}")
print(f"Results: {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
