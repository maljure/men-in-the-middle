"""Phase 3 — Intercept & Modify Engine

A thread-safe engine that sits between the proxy relay loops and the
network, allowing requests and responses to be queued, inspected,
modified, forwarded, or dropped before transmission.

Usage (programmatic — Phase 5 CLI will build on this):

    from intercept import engine, InterceptRule

    # Intercept all POST requests to example.com
    engine.add_rule(InterceptRule(host_pattern="example.com", methods={"POST"}))
    engine.enabled = True

    # In another thread, consume pending requests:
    for item in engine.pending_requests(block=True):
        print(item.request)
        engine.forward(item.id)              # forward unchanged
        # engine.drop(item.id)              # client gets 502
        # engine.modify_request(item.id, modified_req)
"""

from __future__ import annotations

import dataclasses
import fnmatch
import queue
import threading
import uuid
from enum import Enum, auto
from typing import Iterator

from http_parser import HTTPRequest, HTTPResponse


# Decision enum for consumer actions on pending items
class Decision(Enum):
    FORWARD  = auto()
    DROP     = auto()
    MODIFIED = auto()


# InterceptRule defines criteria for matching requests to intercept

@dataclasses.dataclass
class InterceptRule:
    """
    Predicate that decides whether a request should be intercepted.

    Each field is optional; omitting it means "match anything".

    host_pattern   — fnmatch glob against the Host header value (e.g. "*.example.com")
    path_pattern   — fnmatch glob against the request path     (e.g. "/api/*")
    methods        — set of uppercase HTTP method names        (e.g. {"POST", "PUT"})
    content_type   — substring match against Content-Type      (e.g. "application/json")
    """
    host_pattern:  str | None = None
    path_pattern:  str | None = None
    methods:       frozenset[str] | set[str] | None = None
    content_type:  str | None = None

    def matches(self, req: HTTPRequest) -> bool:
        if self.methods and req.method.upper() not in {m.upper() for m in self.methods}:
            return False
        host = (req.header("host") or "").split(":")[0]
        if self.host_pattern and not fnmatch.fnmatch(host, self.host_pattern):
            return False
        if self.path_pattern and not fnmatch.fnmatch(req.path, self.path_pattern):
            return False
        if self.content_type:
            ct = (req.header("content-type") or "").lower()
            if self.content_type.lower() not in ct:
                return False
        return True

# PendingRequest and PendingResponse represent items waiting for client decisions

@dataclasses.dataclass
class PendingRequest:
    """A request waiting in the intercept queue for a client decision."""
    id:      str
    request: HTTPRequest
    _event:  threading.Event = dataclasses.field(
        default_factory=threading.Event, repr=False
    )
    _result: tuple[Decision, HTTPRequest | None] | None = dataclasses.field(
        default=None, repr=False
    )

    def wait(self, timeout: float = 300.0) -> tuple[Decision, HTTPRequest | None]:
        """Block until a decision is made. Times out to DROP after *timeout* seconds."""
        if not self._event.wait(timeout=timeout):
            return Decision.DROP, None
        assert self._result is not None
        return self._result


@dataclasses.dataclass
class PendingResponse:
    """A response waiting in the intercept queue for a client decision."""
    id:       str
    response: HTTPResponse
    _event:   threading.Event = dataclasses.field(
        default_factory=threading.Event, repr=False
    )
    _result: tuple[Decision, HTTPResponse | None] | None = dataclasses.field(
        default=None, repr=False
    )

    def wait(self, timeout: float = 300.0) -> tuple[Decision, HTTPResponse | None]:
        if not self._event.wait(timeout=timeout):
            return Decision.DROP, None
        assert self._result is not None
        return self._result


# InterceptEngine manages rules and queues for pending requests/responses, and is
class InterceptEngine:
    """
    Central intercept controller.

    Thread-safe: many proxy worker threads may call intercept_request /
    intercept_response concurrently.  A consumer thread (CLI or future UI)
    reads from pending_requests() / pending_responses() and calls
    forward / drop / modify_request / modify_response to unblock workers.

    Attributes:
        enabled              — master switch; when False all traffic passes through
        intercept_responses  — when True, matched responses are also queued
        timeout              — seconds to wait for a consumer decision before auto-DROP
    """

    def __init__(self) -> None:
        self.enabled:             bool  = False
        self.intercept_responses: bool  = False
        self.timeout:             float = 300.0

        self._rules:      list[InterceptRule] = []
        self._rules_lock  = threading.Lock()

        self._req_queue:  queue.Queue[PendingRequest]  = queue.Queue()
        self._resp_queue: queue.Queue[PendingResponse] = queue.Queue()

        # id → pending item for O(1) lookup by forward/drop/modify
        self._req_map:  dict[str, PendingRequest]  = {}
        self._resp_map: dict[str, PendingResponse] = {}
        self._map_lock  = threading.Lock()

    # Rule management

    def add_rule(self, rule: InterceptRule) -> None:
        with self._rules_lock:
            self._rules.append(rule)

    def remove_rule(self, index: int) -> InterceptRule:
        with self._rules_lock:
            return self._rules.pop(index)

    def clear_rules(self) -> None:
        with self._rules_lock:
            self._rules.clear()

    def list_rules(self) -> list[InterceptRule]:
        with self._rules_lock:
            return list(self._rules)

    def _matches_any_rule(self, req: HTTPRequest) -> bool:
        with self._rules_lock:
            if not self._rules:
                return True  # no rules → intercept everything
            return any(r.matches(req) for r in self._rules)

    # Interception points called by proxy workers

    def intercept_request(self, req: HTTPRequest) -> HTTPRequest | None:
        """
        Called by a proxy worker before forwarding a request upstream.

        Returns the (possibly modified) request to forward, or None to drop it.
        Returns *req* immediately when interception is disabled or no rule matches.
        """
        if not self.enabled or not self._matches_any_rule(req):
            return req

        item = PendingRequest(id=str(uuid.uuid4()), request=req)
        with self._map_lock:
            self._req_map[item.id] = item
        self._req_queue.put(item)

        decision, modified = item.wait(timeout=self.timeout)

        with self._map_lock:
            self._req_map.pop(item.id, None)

        if decision == Decision.DROP:
            return None
        if decision == Decision.MODIFIED and modified is not None:
            return modified
        return req

    # Interception point for responses is similar, but only active if both enabled and intercept_responses are True

    def intercept_response(self, resp: HTTPResponse) -> HTTPResponse | None:
        """
        Called by a proxy worker before sending a response back to the client.

        Only active when both `enabled` and `intercept_responses` are True.
        Returns the (possibly modified) response, or None to drop it.
        """
        if not self.enabled or not self.intercept_responses:
            return resp

        item = PendingResponse(id=str(uuid.uuid4()), response=resp)
        with self._map_lock:
            self._resp_map[item.id] = item
        self._resp_queue.put(item)

        decision, modified = item.wait(timeout=self.timeout)

        with self._map_lock:
            self._resp_map.pop(item.id, None)

        if decision == Decision.DROP:
            return None
        if decision == Decision.MODIFIED and modified is not None:
            return modified
        return resp

    # Client API for consuming pending items and making decisions

    def pending_requests(
        self, block: bool = False, timeout: float | None = None
    ) -> Iterator[PendingRequest]:
        """Yield PendingRequest items from the queue. Non-blocking by default."""
        try:
            while True:
                yield self._req_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return

    def pending_responses(
        self, block: bool = False, timeout: float | None = None
    ) -> Iterator[PendingResponse]:
        """Yield PendingResponse items from the queue. Non-blocking by default."""
        try:
            while True:
                yield self._resp_queue.get(block=block, timeout=timeout)
        except queue.Empty:
            return

    def forward(self, item_id: str) -> bool:
        """Forward the queued request/response unchanged. Returns False if not found."""
        return self._resolve(item_id, Decision.FORWARD, None)

    def drop(self, item_id: str) -> bool:
        """Drop the queued request/response. Returns False if not found."""
        return self._resolve(item_id, Decision.DROP, None)

    def modify_request(self, item_id: str, new_req: HTTPRequest) -> bool:
        """Forward a modified request. Returns False if id not found."""
        return self._resolve(item_id, Decision.MODIFIED, new_req)

    def modify_response(self, item_id: str, new_resp: HTTPResponse) -> bool:
        """Forward a modified response. Returns False if id not found."""
        return self._resolve(item_id, Decision.MODIFIED, new_resp)

    # Utility methods for monitoring queue sizes
    def pending_request_count(self) -> int:
        return self._req_queue.qsize()

    def pending_response_count(self) -> int:
        return self._resp_queue.qsize()

    # Internal methods for resolving pending items

    def _resolve(
        self,
        item_id: str,
        decision: Decision,
        payload: HTTPRequest | HTTPResponse | None,
    ) -> bool:
        with self._map_lock:
            item = self._req_map.get(item_id) or self._resp_map.get(item_id)
        if item is None:
            return False
        item._result = (decision, payload)
        item._event.set()
        return True

engine = InterceptEngine()
