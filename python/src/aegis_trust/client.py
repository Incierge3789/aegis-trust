"""Aegis-core REST API client wrapper.

Thin facade over the auto-generated client. Provides connection testing
and convenient access to the Aegis enterprise backend endpoints.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import time
import warnings
from typing import Any, Callable, Literal

import httpx
from dataclasses import dataclass, field

from aegis_trust._constants import AUDIT_SCHEMA_VERSION
from aegis_trust.types import (
    AuditChainStatus,
    CapabilityGrant,
    FieldStats,
    FunctionStats,
    IngestEntry,
    IngestResponse,
    PolicySyncEntry,
    PolicySyncResponse,
    PurposeStats,
    ShieldStats,
    StreamStatus,
)

logger = logging.getLogger("aegis")

_DEFAULT_BASE_URL = "https://localhost:8443/api/v1"

_base_url_path_completed_warned = False


def normalize_base_url(url: str) -> str:
    """Complete a pathless base URL to ``…/api/v1``.

    S015 install-friction fix (P-37, hit live this sprint): the gateway serves
    every endpoint under ``/api/v1``. A base URL of just host:port (no path)
    makes every call 404 with no hint it is a path problem. If the caller passes
    a pathless URL, complete it and warn once so the assumption is visible. An
    explicit non-root path is respected unchanged. Parity with node
    ``normalizeBaseUrl``.
    """
    global _base_url_path_completed_warned
    from urllib.parse import urlsplit, urlunsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if parts.scheme and parts.netloc and parts.path in ("", "/"):
        completed = urlunsplit((parts.scheme, parts.netloc, "/api/v1", "", ""))
        if not _base_url_path_completed_warned:
            _base_url_path_completed_warned = True
            logging.getLogger("aegis").warning(
                "base URL %r has no path; the gateway serves under '/api/v1', so "
                "using %r. Set the full URL to silence this.",
                url,
                completed,
            )
        return completed
    return url


_HEALTH_TIMEOUT = 2.0
_API_TIMEOUT = 10.0


def _resolve_access_cache_ttl() -> float:
    """TTL (seconds) for cached allow decisions.

    The cache spares repeated identical calls a gateway round-trip, but the
    window is also a fail-open exposure: a gateway that goes down or a policy
    that revokes access is not seen until the entry expires (S015 P-27,
    confirmed live). Set ``AEGIS_ACCESS_CACHE_TTL_S=0`` to disable the cache so
    every call re-consults the gateway (zero stale window, higher latency).
    Deny is never cached regardless. Default 30s.
    """
    raw = os.environ.get("AEGIS_ACCESS_CACHE_TTL_S")
    if raw is None or raw.strip() == "":
        return 30.0
    try:
        n = float(raw)
    except ValueError:
        return 30.0
    return n if n >= 0 else 30.0


_ACCESS_CACHE_TTL_S = _resolve_access_cache_ttl()

# Pluggable metrics callback. The SDK does not import any specific metrics
# library so users (or this process's other code) own the registry —
# embedding prometheus_client here would pollute every host process.
MetricsHook = Callable[[str, float, int], None]
_metrics_hook: MetricsHook | None = None


def set_metrics_hook(hook: MetricsHook | None) -> None:
    """Register a callback invoked after every backend request.

    Signature: ``hook(endpoint: str, duration_s: float, status: int) -> None``.
    Called even on non-200 responses. Exceptions raised by the hook are
    swallowed; instrumentation must never break the data path.

    Pass ``None`` to remove the hook. Hook is process-global, not per-client.
    """
    global _metrics_hook
    _metrics_hook = hook


def _emit_metric(endpoint: str, started: float, status: int) -> None:
    hook = _metrics_hook
    if hook is None:
        return
    try:
        hook(endpoint, time.monotonic() - started, status)
    except Exception:
        logger.debug("metrics hook raised; ignoring", exc_info=True)


def _clear_sensitive(*objs: Any) -> None:
    """Best-effort zeroize of sensitive values (AO-005, SDK-side).

    CPython does NOT guarantee prompt memory erasure for str/bytes: PyObject
    refs may survive in caches, tracebacks, or small-int/string interning. For
    bearer tokens and secret payloads this helper:

    1. Overwrites the original buffer in place when the value is a bytearray.
    2. Drops references and triggers a gc.collect() cycle.

    Authoritative zeroize is the gateway's responsibility — aegis-core runs in
    Rust where memory lifetime is deterministic. SDK cannot make that
    guarantee; it minimizes the surface instead. See SECURITY.md §Memory posture.
    """
    for obj in objs:
        if isinstance(obj, bytearray):
            for i in range(len(obj)):
                obj[i] = 0
    gc.collect()


@dataclass(frozen=True)
class CoreDecisionEvidence:
    """Evidence pointer attached to a Core BoundaryDecisionView."""

    decision_id: str
    policy: str
    enforced_by: str
    integrity_checkable_at: str
    recorded_at: str


@dataclass(frozen=True)
class BoundaryDecisionView:
    """Wire shape of the gateway's ``BoundaryDecisionView`` (POST
    ``/check-boundary``). ``outcome`` is the SCREAMING_SNAKE_CASE
    ``DecisionOutcome`` enum (``decision_bundle.rs``); ``reason_code`` is
    snake_case. Field *names* are surfaced (never values)."""

    source: str  # "CORE"
    outcome: (
        str  # PROTECTED | ACCESS_REDUCED | CHECK_REQUIRED | APPROVAL_REQUIRED | BLOCKED
    )
    purpose_label: str
    allowed_fields: list[str] = field(default_factory=list)
    withheld_fields: list[str] = field(default_factory=list)
    reason_code: str = ""
    reason_label: str = ""
    evidence_available: bool = False
    evidence: CoreDecisionEvidence | None = None


class AegisClient:
    """Client for the Aegis enterprise backend REST API.

    Most users never instantiate this directly — `@shield` auto-detects whether
    a backend is reachable and uses it transparently. Construct one explicitly
    only when you want to override the URL, supply an authentication token, or
    integrate with the enterprise backend from a non-decorator code path.

    Args:
        base_url: Backend base URL. Defaults to the local development endpoint
            when omitted.
        token: Bearer token sent on each request. Empty string disables auth.
        verify_ssl: Whether to verify the backend's TLS certificate. Defaults to
            True; set to False only for trusted local development.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        token: str = "",
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = normalize_base_url(base_url or _DEFAULT_BASE_URL)
        self._token = token
        self._verify_ssl = verify_ssl
        self._httpx: httpx.Client | None = None
        self._async_httpx: httpx.AsyncClient | None = None
        # Cache key embeds _token_epoch so a token rotation invalidates
        # all prior allow decisions (deny is never cached).
        self._access_cache: dict[tuple[int, str, tuple[str, ...]], float] = {}
        self._token_epoch: int = 0
        # High-water mark of every ingest response — drives verify_inclusion().
        self._max_audit_seq: int = 0
        # Strong refs for tasks scheduled by set_token() so asyncio does
        # not drop them before aclose() runs (bpo-44665).
        self._pending_aclose_tasks: set[asyncio.Task[None]] = set()

    def _get_httpx(self) -> httpx.Client:
        """Get a plain httpx client (no auth header when token is empty)."""
        if self._httpx is None:
            self._httpx = httpx.Client(
                base_url=self._base_url,
                verify=self._verify_ssl,
                headers=self._auth_headers(),
                timeout=httpx.Timeout(_API_TIMEOUT),
            )
        return self._httpx

    def _get_async_httpx(self) -> httpx.AsyncClient:
        """Get an async httpx client. Lazily constructed on first async call.

        AsyncClient lets the @shield async path avoid blocking the event loop
        on the underlying POST.
        """
        if self._async_httpx is None:
            self._async_httpx = httpx.AsyncClient(
                base_url=self._base_url,
                verify=self._verify_ssl,
                headers=self._auth_headers(),
                timeout=httpx.Timeout(_API_TIMEOUT),
            )
        return self._async_httpx

    def _auth_headers(self) -> dict[str, str]:
        # Always attach the Aegis-Api-Version dated header.
        # Client contract: server may opt to respond per legacy semantics if it
        # supports older dated versions.
        from aegis_trust import AEGIS_API_VERSION, AEGIS_API_VERSION_HEADER

        headers: dict[str, str] = {AEGIS_API_VERSION_HEADER: AEGIS_API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def is_available(self) -> bool:
        """Check if the Aegis enterprise backend is reachable."""
        try:
            resp = httpx.get(
                f"{self._base_url}/health",
                verify=self._verify_ssl,
                timeout=_HEALTH_TIMEOUT,
            )
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, Exception):
            return False

    @staticmethod
    def _check_access_body(
        purpose: str, scope: list[str], tool_name: str = "shielded_call"
    ) -> dict[str, Any]:
        """Build the ``/check-access`` request body.

        Contract fix (CSR-03): the gateway's ``CheckAccessRequest.scope`` field
        is a single ``Option<String>`` advisory scope identifier (aegis_gateway
        ``rest.rs:296``), NOT an array. Sending a JSON array deserializes as a
        type error server-side (non-200 -> fail-closed), so the prior
        ``{"purpose", "scope": [...]}`` body silently broke every scope-bearing
        ``/check-access`` call. The authoritative gate is the JWT subject +
        purpose; ``scope`` is advisory minimum-disclosure metadata where ``None``
        means "purpose-level access only". This emits what the endpoint expects
        without changing :meth:`authorize`'s grant/deny contract:

        - 0 scopes  -> omit ``scope`` (None / purpose-level)
        - 1 scope   -> send the single string
        - >1 scopes -> see :meth:`authorize`/:meth:`aauthorize`: the caller
          FAILS CLOSED before a request is built (this body builder is never
          invoked with >1 scope on the gate path).

        Review finding B (fail-closed regression fix): a >1-scope check must NOT
        silently drop to purpose-level. Earlier, sending the array produced a
        server type error (non-2xx -> deny); the scope->``Option<String>`` fix
        turned ">1 scope" into "omit scope", which made the server evaluate at
        purpose-level and could ALLOW where the caller asked for a stricter,
        narrower scope — a fail-open regression. :meth:`authorize` therefore
        DENIES a multi-scope check rather than send a purpose-level request the
        single-scope server would evaluate more permissively than asked.

        NOTE: ``/check-boundary`` correctly uses ``scope: list[str]`` and does
        NOT route through here.

        ``tool_name`` is a REQUIRED (non-Option) field on the gateway's
        ``CheckAccessRequest`` (aegis_gateway ``rest.rs``). Omitting it makes the
        gateway reject the body with 422 -> fail-closed deny on EVERY FULL
        authorize, so a FULL gate can never grant against a live gateway. It is
        an audit LABEL only (it does not affect the allow/deny decision — that is
        JWT subject + purpose + scope). (Found by the S015 live SDK<->gateway
        e2e; same class as the Doctor-v1 ``agent_id`` always-BLOCK bug.)
        """
        body: dict[str, Any] = {
            "purpose": purpose,
            "tool_name": tool_name or "shielded_call",
        }
        if len(scope) == 1:
            body["scope"] = scope[0]
        return body

    def check_access(self, purpose: str, scope: list[str]) -> dict[str, Any]:
        """Check access permission via the Aegis enterprise backend."""
        resp = self._get_httpx().post(
            "/check-access",
            json=self._check_access_body(purpose, scope),
        )
        resp.raise_for_status()
        return resp.json()

    async def acheck_access(self, purpose: str, scope: list[str]) -> dict[str, Any]:
        """Async variant of :meth:`check_access`."""
        resp = await self._get_async_httpx().post(
            "/check-access",
            json=self._check_access_body(purpose, scope),
        )
        resp.raise_for_status()
        return resp.json()

    # ── check-boundary (Doctor v1, Core-backed) ───────────
    @staticmethod
    def _check_boundary_body(
        purpose: str,
        scope: list[str],
        *,
        destination: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
    ) -> dict[str, Any]:
        """Build the ``/check-boundary`` request body.

        ``purpose`` + ``scope`` are required; ``scope`` is a *list* here (the
        boundary endpoint's contract, unlike ``/check-access``). The
        authenticated principal is the JWT subject server-side and is NEVER sent
        in the body; ``agent_id`` is advisory.
        """
        body: dict[str, Any] = {"purpose": purpose, "scope": list(scope)}
        if destination is not None:
            body["destination"] = destination
        if agent_id is not None:
            body["agent_id"] = agent_id
        if environment is not None:
            body["environment"] = environment
        if mode is not None:
            body["mode"] = mode
        if schema_version is not None:
            body["schema_version"] = schema_version
        return body

    @staticmethod
    def _parse_boundary_view(body: Any) -> BoundaryDecisionView:
        """Parse a ``/check-boundary`` 200 body into a
        :class:`BoundaryDecisionView`. Raises :class:`ValueError` on a malformed
        shape so the Doctor v1 entry point maps it to a fail-closed BLOCK.

        Review finding A (fail-closed): require the FULL ``BoundaryDecisionView``
        shape — a partial-but-valid-JSON body such as ``{"outcome": "PROTECTED"}``
        (every other field missing/defaulted) MUST NOT be trusted and map to
        ALLOW. Every required field must be present and correctly typed:
        ``source`` (str), ``outcome`` (str), ``allowed_fields`` (list[str]),
        ``withheld_fields`` (list[str]), ``reason_code`` (str). Any
        missing/mistyped required field -> ValueError -> CORE_MALFORMED_RESPONSE
        -> BLOCK.
        """
        if not isinstance(body, dict):
            raise ValueError("check-boundary: body is not a dict")
        source = body.get("source")
        if not isinstance(source, str):
            raise ValueError("check-boundary: 'source' missing or not a str")
        outcome = body.get("outcome")
        if not isinstance(outcome, str):
            raise ValueError("check-boundary: 'outcome' missing or not a str")
        reason_code = body.get("reason_code")
        if not isinstance(reason_code, str):
            raise ValueError("check-boundary: 'reason_code' missing or not a str")
        # allowed_fields / withheld_fields are REQUIRED here (no default): a
        # missing array is a malformed view, not an empty allow set.
        allowed = body.get("allowed_fields")
        withheld = body.get("withheld_fields")
        if not isinstance(allowed, list) or not all(
            isinstance(x, str) for x in allowed
        ):
            raise ValueError("check-boundary: 'allowed_fields' invalid")
        if not isinstance(withheld, list) or not all(
            isinstance(x, str) for x in withheld
        ):
            raise ValueError("check-boundary: 'withheld_fields' invalid")
        ev_raw = body.get("evidence")
        evidence: CoreDecisionEvidence | None = None
        if isinstance(ev_raw, dict):
            evidence = CoreDecisionEvidence(
                decision_id=str(ev_raw.get("decision_id", "")),
                policy=str(ev_raw.get("policy", "")),
                enforced_by=str(ev_raw.get("enforced_by", "")),
                integrity_checkable_at=str(ev_raw.get("integrity_checkable_at", "")),
                recorded_at=str(ev_raw.get("recorded_at", "")),
            )
        return BoundaryDecisionView(
            source=source,
            outcome=outcome,
            purpose_label=str(body.get("purpose_label", "")),
            allowed_fields=list(allowed),
            withheld_fields=list(withheld),
            reason_code=reason_code,
            reason_label=str(body.get("reason_label", "")),
            evidence_available=bool(body.get("evidence_available", False)),
            evidence=evidence,
        )

    def check_boundary(
        self,
        purpose: str,
        scope: list[str],
        *,
        destination: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
    ) -> BoundaryDecisionView:
        """POST ``/check-boundary`` and return the parsed
        :class:`BoundaryDecisionView`. Reuses the same auth header / base-url /
        timeout / httpx plumbing as :meth:`check_access`. Non-2xx raises (via
        ``raise_for_status``) so the Doctor v1 entry point maps it to a
        fail-closed BLOCK.
        """
        resp = self._get_httpx().post(
            "/check-boundary",
            json=self._check_boundary_body(
                purpose,
                scope,
                destination=destination,
                agent_id=agent_id,
                environment=environment,
                mode=mode,
                schema_version=schema_version,
            ),
        )
        resp.raise_for_status()
        return self._parse_boundary_view(resp.json())

    async def acheck_boundary(
        self,
        purpose: str,
        scope: list[str],
        *,
        destination: str | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        mode: str | None = None,
        schema_version: int | None = None,
    ) -> BoundaryDecisionView:
        """Async variant of :meth:`check_boundary`."""
        resp = await self._get_async_httpx().post(
            "/check-boundary",
            json=self._check_boundary_body(
                purpose,
                scope,
                destination=destination,
                agent_id=agent_id,
                environment=environment,
                mode=mode,
                schema_version=schema_version,
            ),
        )
        resp.raise_for_status()
        return self._parse_boundary_view(resp.json())

    # ── check_access enforcement (AO-003) ───────────────────────────
    def _cache_key(
        self, purpose: str, scope: list[str]
    ) -> tuple[int, str, tuple[str, ...]]:
        return (self._token_epoch, purpose, tuple(sorted(scope)))

    def _cached_allow(self, purpose: str, scope: list[str]) -> bool:
        cached = self._access_cache.get(self._cache_key(purpose, scope))
        return cached is not None and time.monotonic() < cached

    def _remember_allow(
        self, purpose: str, scope: list[str], *, epoch_at_request: int
    ) -> None:
        # Only cache when the request was issued under the current token
        # epoch. An in-flight authorize() started before set_token() must
        # not poison the cache for the new principal.
        if epoch_at_request != self._token_epoch:
            return
        self._access_cache[self._cache_key(purpose, scope)] = (
            time.monotonic() + _ACCESS_CACHE_TTL_S
        )

    @staticmethod
    def _check_access_allowed(body: Any) -> bool:
        """A 200 response is fail-OPEN unless the body explicitly says
        ``allowed=true``. Treat missing or malformed payloads as denied:
        AO-003 must default to deny.
        """
        if isinstance(body, dict):
            allowed = body.get("allowed")
            if isinstance(allowed, bool):
                return allowed
        return False

    def authorize(self, purpose: str, scope: list[str]) -> bool:
        """Sync gate: call check_access and return True iff backend allows.

        Returns False on 403 (deny), connection errors, malformed response, or
        a 200 whose body lacks ``{"allowed": true}``. A 200-allow result is
        cached for :data:`_ACCESS_CACHE_TTL_S` seconds, keyed by the current token
        epoch so token rotation invalidates the cache. Deny is never cached.

        Review finding B: a >1-scope request fails closed (deny) before any
        request is sent — see :meth:`_check_access_body`.
        """
        if len(scope) > 1:
            logger.warning(
                "authorize: >1 scope vs single-scope server, fail-closed (finding B)"
            )
            return False
        if self._cached_allow(purpose, scope):
            return True
        epoch_at_request = self._token_epoch
        t0 = time.monotonic()
        try:
            resp = self._get_httpx().post(
                "/check-access",
                json=self._check_access_body(purpose, scope),
            )
        except Exception:
            _emit_metric("check-access", t0, 0)
            logger.warning("authorize: transport error, fail-closed")
            return False
        _emit_metric("check-access", t0, resp.status_code)
        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                logger.warning("authorize: non-JSON 200 body, fail-closed")
                return False
            if self._check_access_allowed(body):
                self._remember_allow(purpose, scope, epoch_at_request=epoch_at_request)
                return True
            return False
        if resp.status_code == 403:
            return False
        logger.warning("authorize: unexpected %s, fail-closed", resp.status_code)
        return False

    async def aauthorize(self, purpose: str, scope: list[str]) -> bool:
        """Async variant of :meth:`authorize`."""
        if len(scope) > 1:
            logger.warning(
                "aauthorize: >1 scope vs single-scope server, fail-closed (finding B)"
            )
            return False
        if self._cached_allow(purpose, scope):
            return True
        epoch_at_request = self._token_epoch
        t0 = time.monotonic()
        try:
            resp = await self._get_async_httpx().post(
                "/check-access",
                json=self._check_access_body(purpose, scope),
            )
        except Exception:
            _emit_metric("check-access", t0, 0)
            logger.warning("aauthorize: transport error, fail-closed")
            return False
        _emit_metric("check-access", t0, resp.status_code)
        if resp.status_code == 200:
            try:
                body = resp.json()
            except Exception:
                logger.warning("aauthorize: non-JSON 200 body, fail-closed")
                return False
            if self._check_access_allowed(body):
                self._remember_allow(purpose, scope, epoch_at_request=epoch_at_request)
                return True
            return False
        if resp.status_code == 403:
            return False
        logger.warning("aauthorize: unexpected %s, fail-closed", resp.status_code)
        return False

    def log_audit(
        self,
        *,
        purpose: str,
        tool_name: str,
        requester_id: str,
        decision: str,
        session_id: str | None = None,
        reason: str | None = None,
        bytes_returned: int | None = None,
    ) -> None:
        """Record an audit entry in the Aegis enterprise backend."""
        payload: dict[str, Any] = {
            "purpose": purpose,
            "tool_name": tool_name,
            "requester_id": requester_id,
            "decision": decision,
        }
        if session_id is not None:
            payload["session_id"] = session_id
        if reason is not None:
            payload["reason"] = reason
        if bytes_returned is not None:
            payload["bytes_returned"] = bytes_returned
        resp = self._get_httpx().post("/audit-log", json=payload)
        resp.raise_for_status()

    # ── Shield API ─────────────────────────────────────────

    @staticmethod
    def _ingest_payload(entries: list[IngestEntry]) -> dict[str, Any]:
        return {
            "entries": [
                {
                    "function": e.function,
                    "purpose": e.purpose,
                    "scope": list(e.scope),
                    "blocked_fields": list(e.blocked_fields),
                    "timestamp": e.timestamp,
                    "count": e.count,
                    "deny_fields": list(e.deny_fields),
                    "schema_version": AUDIT_SCHEMA_VERSION,
                }
                for e in entries
            ]
        }

    @staticmethod
    def _parse_ingest_body(body: Any) -> IngestResponse:
        """Validate and extract an :class:`IngestResponse` from a 200 body.

        aegis-core can in principle return HTTP 200 with a shape that
        differs from the OpenAPI contract (bug, proxy rewrite, version
        drift). This helper centralizes strict schema checks and raises
        :class:`ValueError` on any violation. The outer try/except in
        ``_shield_full`` treats that as a transport error and returns the
        AO-002 fail-closed empty result — never raise into the caller.
        """
        if not isinstance(body, dict):
            raise ValueError("ingest: body is not a dict")
        data = body.get("data")
        if not isinstance(data, dict):
            raise ValueError("ingest: body['data'] missing or not a dict")
        ingested = data.get("ingested")
        seq_start = data.get("audit_seq_start")
        seq_end = data.get("audit_seq_end")
        if not isinstance(ingested, int) or ingested < 0:
            raise ValueError("ingest: 'ingested' invalid")
        if not isinstance(seq_start, int) or seq_start < 0:
            raise ValueError("ingest: 'audit_seq_start' invalid")
        if not isinstance(seq_end, int) or seq_end < seq_start:
            raise ValueError("ingest: 'audit_seq_end' invalid or non-monotonic")
        return IngestResponse(
            ingested=ingested,
            audit_seq_start=seq_start,
            audit_seq_end=seq_end,
        )

    def _record_seq(self, parsed: IngestResponse) -> IngestResponse:
        """Bump the highest observed audit seq so verify_inclusion() can
        prove later that this client's records landed in the chain."""
        if parsed.audit_seq_end > self._max_audit_seq:
            self._max_audit_seq = parsed.audit_seq_end
        return parsed

    @staticmethod
    def _require_full_acceptance(parsed: IngestResponse, expected: int) -> None:
        """FULL mode is audit-before-release: the gateway must durably accept
        ALL entries before the @shield path releases the filtered data.

        A contract-valid ``200 {"ingested": 0, ...}`` (or any
        ``ingested < expected``) means at least one audit record was NOT durably
        committed — releasing the data anyway is a fail-OPEN on audit
        completeness (AO-003). Raise so the ``_shield_full`` try/except returns
        the type-shaped empty (fail-closed) instead of leaking.

        Only ``ingested == expected`` is asserted: the ``audit_seq_*`` window is
        gateway-assigned and not contracted to equal the batch size (a valid
        response can carry ``ingested == 1`` with a wider seq range), so a
        window-size check would risk fail-closing a legitimate ingest.
        """
        if parsed.ingested != expected:
            raise ValueError(
                f"ingest: partial acceptance ({parsed.ingested}/{expected}) — "
                "audit incomplete, failing closed"
            )

    def ingest(self, entries: list[IngestEntry]) -> IngestResponse:
        """Send @shield block records to the Aegis enterprise backend (POST /shield/ingest)."""
        t0 = time.monotonic()
        resp = self._get_httpx().post(
            "/shield/ingest", json=self._ingest_payload(entries)
        )
        _emit_metric("shield.ingest", t0, resp.status_code)
        resp.raise_for_status()
        parsed = self._parse_ingest_body(resp.json())
        self._require_full_acceptance(parsed, len(entries))
        return self._record_seq(parsed)

    async def aingest(self, entries: list[IngestEntry]) -> IngestResponse:
        """Async variant of :meth:`ingest`. Uses :class:`httpx.AsyncClient`
        so the @shield async path does not block the event loop.
        """
        t0 = time.monotonic()
        resp = await self._get_async_httpx().post(
            "/shield/ingest", json=self._ingest_payload(entries)
        )
        _emit_metric("shield.ingest", t0, resp.status_code)
        resp.raise_for_status()
        parsed = self._parse_ingest_body(resp.json())
        self._require_full_acceptance(parsed, len(entries))
        return self._record_seq(parsed)

    # ── audit chain verification (AO-004) ───────────────────────────
    @staticmethod
    def _parse_chain_body(body: Any) -> AuditChainStatus:
        if not isinstance(body, dict):
            raise ValueError("verify: body is not a dict")
        chain_valid = body.get("chain_valid")
        total = body.get("total_entries")
        if not isinstance(chain_valid, bool):
            raise ValueError("verify: 'chain_valid' must be bool")
        if not isinstance(total, int) or total < 0:
            raise ValueError("verify: 'total_entries' invalid")
        return AuditChainStatus(chain_valid=chain_valid, total_entries=total)

    def verify_audit_chain(self) -> AuditChainStatus:
        """Verify the backend audit chain integrity (GET /audit/verify)."""
        resp = self._get_httpx().get("/audit/verify")
        resp.raise_for_status()
        return self._parse_chain_body(resp.json())

    async def averify_audit_chain(self) -> AuditChainStatus:
        """Async variant of :meth:`verify_audit_chain`."""
        resp = await self._get_async_httpx().get("/audit/verify")
        resp.raise_for_status()
        return self._parse_chain_body(resp.json())

    def verify_inclusion(self, *, seq_end: int | None = None) -> bool:
        """Per-call non-repudiation gate (AO-004).

        Returns True iff the backend chain is currently valid AND it
        contains entries up to ``seq_end`` (defaults to the highest seq
        this client ever ingested via :meth:`ingest`). A bare
        `/audit/verify` only proves chain health; this proves *this*
        call's record is included.
        """
        target = seq_end if seq_end is not None else self._max_audit_seq
        if target <= 0:
            return False
        try:
            status = self.verify_audit_chain()
        except Exception:
            logger.warning("verify_inclusion: chain query failed, fail-closed")
            return False
        return status.chain_valid and status.total_entries >= target

    async def averify_inclusion(self, *, seq_end: int | None = None) -> bool:
        """Async variant of :meth:`verify_inclusion`."""
        target = seq_end if seq_end is not None else self._max_audit_seq
        if target <= 0:
            return False
        try:
            status = await self.averify_audit_chain()
        except Exception:
            logger.warning("averify_inclusion: chain query failed, fail-closed")
            return False
        return status.chain_valid and status.total_entries >= target

    async def ais_available(self) -> bool:
        """Async variant of :meth:`is_available`."""
        try:
            resp = await self._get_async_httpx().get("/health", timeout=_HEALTH_TIMEOUT)
            return resp.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException, Exception):
            return False

    async def aclose(self) -> None:
        """Close any open async client (called from tests / shutdown)."""
        if self._async_httpx is not None:
            await self._async_httpx.aclose()
            self._async_httpx = None

    # ── AI-native v1: tool-call / capability lineage / streaming ─────
    # Wire contract: boundary-core docs/AI_NATIVE_V1_CONTRACT.md (frozen
    # 2026-07-03, additive-only; /api/v1 base is the SDK-canonical form).
    # These are the WIRE-FLOOR methods — the in-path interposition layer
    # (MCP proxy / @guard_tool / delegate() / stream_session()) builds on
    # them; application code should prefer that layer so the boundary sits
    # IN the call path, not beside it.

    #: Decision outcomes that permit the guarded action to proceed.
    PASSING_OUTCOMES = ("PROTECTED", "ACCESS_REDUCED")

    @staticmethod
    def _require_decision(body: Any, op: str) -> dict[str, Any]:
        """Fail-closed shape check for decision-bearing responses."""
        if not isinstance(body, dict):
            raise ValueError(f"{op}: body is not a dict")
        decision = body.get("decision")
        if not isinstance(decision, dict):
            raise ValueError(f"{op}: 'decision' missing or not a dict")
        if not isinstance(decision.get("outcome"), str):
            raise ValueError(f"{op}: 'decision.outcome' missing")
        if not isinstance(decision.get("ledgered"), bool):
            raise ValueError(f"{op}: 'decision.ledgered' missing")
        return body

    @staticmethod
    def _tool_call_body(
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None,
        session_id: str | None,
        destination: str | None,
        capability: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": tool,
            "purpose": purpose,
            "owner": owner,
            "fields": list(fields or []),
        }
        if session_id is not None:
            payload["session_id"] = session_id
        if destination is not None:
            payload["destination"] = destination
        if capability is not None:
            payload["capability"] = capability
        return payload

    def tool_call(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
    ) -> dict[str, Any]:
        """Decide ONE tool invocation at the boundary (POST /tool-call).

        Arguments never leave the caller — refs and labels only (INV-6).
        Returns ``{"decision": ..., "enforcement": ...}``; a BLOCKED outcome
        is still HTTP 200 — gate on ``decision["outcome"]`` being in
        :data:`PASSING_OUTCOMES` AND ``decision["ledgered"]`` (or use
        :meth:`tool_allowed`).
        """
        t0 = time.monotonic()
        resp = self._get_httpx().post(
            "/tool-call",
            json=self._tool_call_body(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
            ),
        )
        _emit_metric("tool_call", t0, resp.status_code)
        resp.raise_for_status()
        return self._require_decision(resp.json(), "tool-call")

    async def atool_call(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
    ) -> dict[str, Any]:
        """Async variant of :meth:`tool_call` (the per-tool-call hot path)."""
        t0 = time.monotonic()
        resp = await self._get_async_httpx().post(
            "/tool-call",
            json=self._tool_call_body(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
            ),
        )
        _emit_metric("tool_call", t0, resp.status_code)
        resp.raise_for_status()
        return self._require_decision(resp.json(), "tool-call")

    def tool_allowed(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
    ) -> bool:
        """Fail-closed boolean gate over :meth:`tool_call` (authorize() parity):
        any transport error, non-200, malformed body, non-passing outcome, or
        unledgered decision is a deny."""
        try:
            body = self.tool_call(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
            )
        except Exception:
            logger.warning("tool_allowed: request failed, fail-closed deny")
            return False
        decision = body["decision"]
        return decision["outcome"] in self.PASSING_OUTCOMES and decision["ledgered"]

    async def atool_allowed(
        self,
        tool: str,
        purpose: str,
        owner: str,
        *,
        fields: list[str] | None = None,
        session_id: str | None = None,
        destination: str | None = None,
        capability: str | None = None,
    ) -> bool:
        """Async variant of :meth:`tool_allowed` (same fail-closed contract)."""
        try:
            body = await self.atool_call(
                tool,
                purpose,
                owner,
                fields=fields,
                session_id=session_id,
                destination=destination,
                capability=capability,
            )
        except Exception:
            logger.warning("tool_allowed: request failed, fail-closed deny")
            return False
        decision = body["decision"]
        return decision["outcome"] in self.PASSING_OUTCOMES and decision["ledgered"]

    @staticmethod
    def _parse_capability_grant(body: Any) -> CapabilityGrant:
        if not isinstance(body, dict):
            raise ValueError("capability/mint: body is not a dict")
        token = body.get("capability")
        cap_id = body.get("id")
        exp = body.get("exp")
        depth = body.get("depth")
        root = body.get("root_delegator")
        if not isinstance(token, str) or not token:
            raise ValueError("capability/mint: 'capability' missing")
        if not isinstance(cap_id, str) or not cap_id:
            raise ValueError("capability/mint: 'id' missing")
        if not isinstance(exp, int) or exp <= 0:
            raise ValueError("capability/mint: 'exp' invalid")
        if not isinstance(depth, int) or depth <= 0:
            raise ValueError("capability/mint: 'depth' invalid")
        if not isinstance(root, str) or not root:
            raise ValueError("capability/mint: 'root_delegator' missing")
        return CapabilityGrant(
            capability=token, id=cap_id, exp=exp, depth=depth, root_delegator=root
        )

    def capability_mint(
        self,
        for_agent: str,
        purposes: list[str],
        *,
        scope: list[str] | None = None,
        tools: list[str] | None = None,
        ttl_secs: int | None = None,
        parent_capability: str | None = None,
    ) -> CapabilityGrant:
        """Mint a delegation capability (POST /capability/mint).

        Root grants are bounded by the caller's role NOW; a child grant
        (``parent_capability``) can only NARROW its parent. The boundary
        witnesses the mint on the chain BEFORE returning the token.
        """
        payload: dict[str, Any] = {
            "for_agent": for_agent,
            "purposes": list(purposes),
            "scope": list(scope or []),
            "tools": list(tools or []),
        }
        if ttl_secs is not None:
            payload["ttl_secs"] = int(ttl_secs)
        if parent_capability is not None:
            payload["parent_capability"] = parent_capability
        resp = self._get_httpx().post("/capability/mint", json=payload)
        resp.raise_for_status()
        return self._parse_capability_grant(resp.json())

    def capability_revoke(
        self,
        *,
        capability: str | None = None,
        capability_id: str | None = None,
    ) -> str:
        """Revoke a capability (POST /capability/revoke). Present the token
        (holder / delegator / root delegator) or, as Admin, the id. Returns
        the revoked id. Revocation is transitive and cuts matching streams."""
        payload: dict[str, Any] = {}
        if capability is not None:
            payload["capability"] = capability
        if capability_id is not None:
            payload["capability_id"] = capability_id
        resp = self._get_httpx().post("/capability/revoke", json=payload)
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise ValueError("capability/revoke: 'ok' missing")
        revoked = body.get("revoked")
        if not isinstance(revoked, str) or not revoked:
            raise ValueError("capability/revoke: 'revoked' missing")
        return revoked

    def stream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Open a continuous-authz stream (POST /stream/open) with a full
        Common Envelope. Returns ``{"decision":…, "enforcement":…, "stream":…}``
        — ``stream`` is non-null (``{"stream_id":…, "status":"open"}``) iff the
        decision passes AND is ledgered."""
        resp = self._get_httpx().post("/stream/open", json={"envelope": envelope})
        resp.raise_for_status()
        return self._parse_stream_open(
            self._require_decision(resp.json(), "stream/open")
        )

    @staticmethod
    def _parse_stream_open(body: Any) -> dict[str, Any]:
        stream = body.get("stream")
        if stream is not None:
            if not isinstance(stream, dict) or not isinstance(
                stream.get("stream_id"), str
            ):
                raise ValueError("stream/open: 'stream.stream_id' missing")
        return body

    async def astream_open(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Async variant of :meth:`stream_open`."""
        resp = await self._get_async_httpx().post(
            "/stream/open", json={"envelope": envelope}
        )
        resp.raise_for_status()
        return self._parse_stream_open(
            self._require_decision(resp.json(), "stream/open")
        )

    @staticmethod
    def _parse_stream_status(body: Any) -> StreamStatus:
        if not isinstance(body, dict) or not isinstance(body.get("status"), str):
            raise ValueError("stream/heartbeat: 'status' missing")
        reason = body.get("reason")
        return StreamStatus(
            status=body["status"],
            reason=reason if isinstance(reason, str) else None,
        )

    def stream_heartbeat(self, stream_id: str) -> StreamStatus:
        """Revalidate a stream NOW (POST /stream/heartbeat) against the live
        registries (duress / legal hold / delegation expiry). ``status`` is
        ``ok | revoked | closed``; anything but ``ok`` means STOP."""
        resp = self._get_httpx().post(
            "/stream/heartbeat", json={"stream_id": stream_id}
        )
        resp.raise_for_status()
        return self._parse_stream_status(resp.json())

    async def astream_heartbeat(self, stream_id: str) -> StreamStatus:
        """Async variant of :meth:`stream_heartbeat` (the background-loop path)."""
        resp = await self._get_async_httpx().post(
            "/stream/heartbeat", json={"stream_id": stream_id}
        )
        resp.raise_for_status()
        return self._parse_stream_status(resp.json())

    def stream_close(self, stream_id: str) -> bool:
        """Close a stream (POST /stream/close; owner or Admin). Witnessed."""
        resp = self._get_httpx().post("/stream/close", json={"stream_id": stream_id})
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise ValueError("stream/close: 'ok' missing")
        return True

    async def astream_close(self, stream_id: str) -> bool:
        """Async variant of :meth:`stream_close`."""
        resp = await self._get_async_httpx().post(
            "/stream/close", json={"stream_id": stream_id}
        )
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise ValueError("stream/close: 'ok' missing")
        return True

    # ── token rotation (AO-001 + AO-004) ────────────────────────────
    def set_token(self, new_token: str) -> None:
        """Rotate the bearer token used for subsequent requests.

        The module-level :class:`AegisClient` is cached in :mod:`aegis.shield`
        which previously meant ``os.environ["AEGIS_TOKEN"]`` updates never
        reached the backend — every request kept using the token captured at
        first ``_get_client()`` call. This method:

        1. Updates the stored token.
        2. Schedules a close of the old sync/async httpx clients so their
           sockets are released (no FD leak on rotation).
        3. Invalidates the check-access cache — token changes imply a
           different principal and previous allow decisions are no longer
           authoritative.
        4. Best-effort zeroize of the old token if it was a ``bytearray``.

        Async-client shutdown: if called from a running event loop the
        old ``AsyncClient.aclose()`` is scheduled as a task; if there is
        no running loop a warning is emitted and the client is left for
        GC (the sync path is always closed inline).
        """
        old = self._token
        old_sync = self._httpx
        old_async = self._async_httpx
        self._token = new_token
        # Bump epoch so any in-flight authorize() captured under the prior
        # epoch becomes a no-op when it tries to cache its result.
        self._token_epoch += 1
        if isinstance(old, bytearray):
            _clear_sensitive(old)
        self._httpx = None
        self._async_httpx = None
        self._access_cache.clear()

        # Deterministic close of the sync client — cheap, always safe.
        if old_sync is not None:
            try:
                old_sync.close()
            except Exception:  # pragma: no cover
                logger.debug("set_token: sync client close raised", exc_info=True)

        # Async client close needs an event loop. Schedule it if we have
        # one; warn loudly if we do not, so operators catch rotations
        # happening outside of async contexts.
        if old_async is not None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None:
                task = loop.create_task(old_async.aclose())
                # Keep a strong reference until the task finishes —
                # asyncio stores only a weak ref internally (bpo-44665).
                self._pending_aclose_tasks.add(task)
                task.add_done_callback(self._pending_aclose_tasks.discard)
            else:
                warnings.warn(
                    "AegisClient.set_token() called outside an event loop "
                    "while an async httpx client was open; its socket will "
                    "be released by GC. Call `await client.aclose()` before "
                    "rotating to free the FD immediately.",
                    ResourceWarning,
                    stacklevel=2,
                )

    def policy_sync(self, purposes: dict[str, PolicySyncEntry]) -> PolicySyncResponse:
        """Sync SDK purpose policies to the Aegis enterprise backend (POST /shield/policy-sync).

        Requires Admin role on the the Aegis enterprise backend side.
        """
        payload = {
            "purposes": {
                name: {
                    "scope": list(entry.scope),
                    "deny_fields": list(entry.deny_fields),
                }
                for name, entry in purposes.items()
            }
        }
        resp = self._get_httpx().post("/shield/policy-sync", json=payload)
        resp.raise_for_status()
        data = resp.json()["data"]
        return PolicySyncResponse(
            synced=data["synced"],
            added=data.get("added", []),
            updated=data.get("updated", []),
        )

    def get_stats(
        self,
        *,
        from_time: str | None = None,
        to_time: str | None = None,
        purpose: str | None = None,
    ) -> ShieldStats:
        """Retrieve shield statistics (GET /shield/stats)."""
        params: dict[str, str] = {}
        if from_time is not None:
            params["from"] = from_time
        if to_time is not None:
            params["to"] = to_time
        if purpose is not None:
            params["purpose"] = purpose
        resp = self._get_httpx().get("/shield/stats", params=params)
        resp.raise_for_status()
        data = resp.json()["data"]
        return ShieldStats(
            period_from=data["period"]["from"],
            period_to=data["period"]["to"],
            total_calls=data["total_calls"],
            total_blocked_fields=data["total_blocked_fields"],
            by_purpose={
                k: PurposeStats(calls=v["calls"], blocked=v["blocked"])
                for k, v in data.get("by_purpose", {}).items()
            },
            by_field={
                k: FieldStats(blocked_count=v["blocked_count"])
                for k, v in data.get("by_field", {}).items()
            },
            by_function={
                k: FunctionStats(calls=v["calls"], purposes=v.get("purposes", []))
                for k, v in data.get("by_function", {}).items()
            },
        )

    def get_report(
        self, *, fmt: Literal["json", "pdf"] = "json"
    ) -> dict[str, Any] | bytes:
        """Retrieve shield audit report (GET /shield/report).

        Args:
            fmt: "json" (default) or "pdf".

        Returns:
            dict for JSON format, bytes for PDF format.
        """
        params = {"format": fmt} if fmt != "json" else {}
        resp = self._get_httpx().get("/shield/report", params=params)
        resp.raise_for_status()
        if fmt == "pdf":
            return resp.content
        return resp.json()["data"]
