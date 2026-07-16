"""shield-proxy: MCP process-boundary enforcement point (canonical contract v0).

Sits between any MCP host (Claude Code, codex, agy, Claude Desktop, ...) and
any MCP server, with zero modification to either side:

    host  <--stdio-->  aegis-mcp-proxy  <--stdio-->  real MCP server

Every ``tools/call`` *result* coming back from the server is filtered through
the canonical policy (purpose resolved via the policy's ``tools`` map or the
call's explicit ``purpose`` argument) before the host's model ever sees it,
and a canonical audit event v0 is emitted (``enforcement_point=mcp_proxy``).

Fail-closed doctrine:
- tool not in the policy's ``tools`` map and no declared purpose ⇒ the call is
  NOT forwarded; the host receives an ``isError`` result (unknown_tool).
- any filtering error ⇒ empty content is returned, never the raw payload.

Gated data paths: ``tools/call`` plus the sibling server->host data methods
``resources/read`` and ``prompts/get`` (each requires a purpose mapping in the
policy's ``tools`` map, else blocked). JSON-RPC batches are rejected outright
(no batching in current MCP; a batch would bypass per-id result filtering).
Non-JSON server stdout lines are dropped, not relayed.

v0 limits (documented):
- only structured payloads are minimized — JSON found in ``structuredContent``
  / ``content[].text`` / ``contents[].text`` / ``messages[].content.text``.
  Free-text output passes through; route sensitive data through structured
  results.
- host->server direction (tool *arguments*, sampling responses) is not
  inspected: the proxy minimizes what enters the host's context, it does not
  yet police what the host sends out. Egress policy (``destinations``) is
  enforced by the SDK/gateway forms in v0.

Usage:
    python -m aegis_trust.mcp_proxy --policy policy.json [--agent-id claude-code] \
        -- <real-server-command> [args...]

Host registration (e.g. Claude Code .mcp.json):
    {"mcpServers": {"crm": {"command": "python3",
        "args": ["-m", "aegis_trust.mcp_proxy", "--policy", "/etc/aegis/policy.json",
                 "--agent-id", "claude-code", "--", "node", "crm-server.js"]}}}
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from typing import Any, BinaryIO

from aegis_trust.canonical import (
    ENFORCEMENT_MCP_PROXY,
    CanonicalEmitter,
    CanonicalPolicy,
    CanonicalPurpose,
    load_canonical_policy,
)
from aegis_trust.errors import AegisConfigError

try:  # single-source runtime version
    from aegis_trust import __version__ as _sdk_version
except Exception:  # pragma: no cover
    _sdk_version = "unknown"

PROXY_RUNTIME = f"mcp-proxy/{_sdk_version}"


class GatewayGate:
    """FULL-mode per-call gate for the proxy path (the third PEP grows teeth).

    LITE keeps today's behavior (local canonical filtering only). In FULL the
    proxy consults the gateway BEFORE forwarding a gated call, so a policy
    deny stops the tool from ever running — same fail-closed conventions as
    ``@shield``: a gate error is a deny, never a pass-through.

    Two gate kinds, EXPLICIT (never auto-probed — a silent up/downgrade of the
    enforcement primitive is exactly the drift Aegis refuses):

    - ``check-access``: the ``@shield``-parity purpose gate (POST
      /check-access) — works against every live gateway today. Scope-form
      purposes are checked one scope per call (the client fail-closes
      multi-scope requests, finding B).
    - ``tool-call``: the AI-native per-tool-call gate (POST /tool-call,
      AI_NATIVE_V1_CONTRACT.md) — role-keyed tool whitelist + chain-witnessed
      decision. Requires a boundary that serves the AI-native family.
    """

    def __init__(self, client: Any, kind: str, owner: str) -> None:
        if kind not in ("check-access", "tool-call"):
            raise ValueError(f"unknown gate kind {kind!r}")
        self.client = client
        self.kind = kind
        self.owner = owner

    def check(self, tool: str, purpose: CanonicalPurpose) -> tuple[bool, str]:
        """Returns (allowed, reason_code). Fail-closed on every error path."""
        scope = list(purpose.scope or [])
        if self.kind == "tool-call":
            # tool_allowed() is fail-closed internally (transport / non-200 /
            # malformed / non-passing / unledgered are all a deny).
            allowed = self.client.tool_allowed(
                tool, purpose.name, self.owner, fields=scope
            )
            return (True, "") if allowed else (False, "gateway_denied")
        # check_access (not authorize): authorize() swallows transport errors
        # into False, which would collapse "policy denied" and "gateway down"
        # into one audit reason. Both are a deny — but an auditor/on-call needs
        # to tell them apart, so the raising primitive + distinct reason codes.
        try:
            if scope:
                granted = all(
                    bool(self.client.check_access(purpose.name, [s]).get("allowed"))
                    for s in scope
                )
            else:
                granted = bool(
                    self.client.check_access(purpose.name, []).get("allowed")
                )
        except Exception:
            return False, "gateway_unavailable"
        return (True, "") if granted else (False, "gateway_denied")


class ShieldProxy:
    """JSON-RPC line proxy with tool-result minimization."""

    def __init__(
        self,
        policy: CanonicalPolicy,
        emitter: CanonicalEmitter,
        agent_id: str,
        session_id: str | None = None,
        gate: GatewayGate | None = None,
    ) -> None:
        self.policy = policy
        self.emitter = emitter
        self.agent_id = agent_id
        self.session_id = session_id
        self.gate = gate
        self._pending: dict[Any, dict[str, str]] = {}
        self._lock = threading.Lock()

    # Data-bearing server->host methods the proxy gates. tools/call carries
    # results; resources/read and prompts/get are sibling data paths on the
    # SAME boundary and would otherwise bypass minimization entirely.
    _GATED_METHODS = ("tools/call", "resources/read", "prompts/get")

    # -- host -> server ----------------------------------------------------
    def handle_client_line(self, line: bytes) -> tuple[bytes | None, bytes | None]:
        """Returns (forward_to_server, reply_to_client). Exactly one is set."""
        try:
            msg = json.loads(line)
        except ValueError:
            return line, None  # not ours to judge; transport passthrough
        if isinstance(msg, list):
            # JSON-RPC batch: a batched tools/call response would come back as
            # a batch and bypass result filtering. Current MCP spec has no
            # batching; fail-closed, never forward.
            self.emitter.emit(
                principal=self._principal(),
                purpose="unknown",
                operation="<batch>",
                decision="deny",
                outcome="blocked",
                reason_code="batch_rejected",
                blocked_fields=[],
            )
            return None, self._block_reply(None, "<batch>", "batch_rejected")
        if not isinstance(msg, dict) or msg.get("method") not in self._GATED_METHODS:
            return line, None

        method = msg["method"]
        params = msg.get("params") or {}
        if method == "tools/call":
            operation = params.get("name") or "<unknown>"
            lookup = operation
            arguments = params.get("arguments") or {}
            declared = arguments.get("purpose") if isinstance(arguments, dict) else None
        else:
            # resources/read, prompts/get: purpose is declared per-method in
            # the policy's tools map (e.g. "resources/read": "internal_docs").
            operation = f"{method}:{params.get('uri') or params.get('name') or ''}"
            lookup = method
            declared = None
        purpose = self.policy.purpose_for_tool(lookup, declared_purpose=declared)

        if purpose is None:
            # fail-closed: unmapped tool/method => block, never forward
            self.emitter.emit(
                principal=self._principal(),
                purpose=declared or "unknown",
                operation=operation,
                decision="deny",
                outcome="blocked",
                reason_code="unknown_tool",
                blocked_fields=[],
            )
            return None, self._block_reply(msg.get("id"), operation, "unknown_tool")

        if self.gate is not None:
            allowed, reason = self.gate.check(operation, purpose)
            if not allowed:
                # FULL gate deny: the tool NEVER runs (pre-call, like @shield —
                # side effects prevented, not just output discarded).
                self.emitter.emit(
                    principal=self._principal(),
                    purpose=purpose.name,
                    operation=operation,
                    decision="deny",
                    outcome="blocked",
                    reason_code=reason,
                    blocked_fields=[],
                )
                return None, self._block_reply(msg.get("id"), operation, reason)

        if msg.get("id") is not None:
            with self._lock:
                self._pending[msg["id"]] = {"tool": operation, "purpose": purpose.name}
        return line, None

    @staticmethod
    def _block_reply(msg_id: Any, operation: str, reason: str) -> bytes:
        reply = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Aegis shield-proxy: '{operation}' blocked ({reason}, fail-closed).",
                    }
                ],
                "isError": True,
            },
        }
        return json.dumps(reply, ensure_ascii=False).encode() + b"\n"

    # -- server -> host ----------------------------------------------------
    def handle_server_line(self, line: bytes) -> bytes:
        try:
            msg = json.loads(line)
        except ValueError:
            # MCP stdio frames are JSON lines. A non-JSON stdout line is a
            # protocol violation and could be a raw data dump around the
            # filter — drop it (fail-closed), never relay.
            sys.stderr.write("aegis-mcp-proxy: dropped non-JSON server stdout line\n")
            return b""
        if isinstance(msg, list):
            sys.stderr.write("aegis-mcp-proxy: dropped JSON-RPC batch from server\n")
            return b""
        if not isinstance(msg, dict) or "id" not in msg or "result" not in msg:
            return line
        with self._lock:
            call = self._pending.pop(msg["id"], None)
        if call is None:
            return line

        purpose = self.policy.purposes[call["purpose"]]
        result = msg["result"]
        blocked: list[str] = []
        if isinstance(result, dict):
            if isinstance(result.get("structuredContent"), (dict, list)):
                filtered, removed = self.policy.filter_payload(
                    purpose, result["structuredContent"]
                )
                result["structuredContent"] = filtered
                blocked.extend(removed)
            # content (tools/call), contents (resources/read), messages
            # (prompts/get) all carry text items on the same boundary.
            for key in ("content", "contents", "messages"):
                for item in result.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    holder = item
                    if key == "messages" and isinstance(item.get("content"), dict):
                        holder = item["content"]
                    text = holder.get("text")
                    if not isinstance(text, str):
                        continue
                    try:
                        payload = json.loads(text)
                    except ValueError:
                        continue  # v0 limit: free text passes through
                    if isinstance(payload, (dict, list)):
                        filtered, removed = self.policy.filter_payload(purpose, payload)
                        holder["text"] = json.dumps(filtered, ensure_ascii=False)
                        blocked.extend(removed)

        blocked = sorted(set(blocked))
        self.emitter.emit(
            principal=self._principal(),
            purpose=purpose.name,
            operation=call["tool"],
            decision="allow",
            outcome="access_reduced" if blocked else "protected",
            reason_code="minimum_disclosure" if blocked else None,
            blocked_fields=blocked,
            scope=purpose.scope,
            deny_fields=purpose.deny_fields,
        )
        return json.dumps(msg, ensure_ascii=False).encode() + b"\n"

    def _principal(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "transport": "mcp",
        }


def _pump_client_to_server(
    proxy: ShieldProxy, client_in: BinaryIO, server_in: BinaryIO, client_out: BinaryIO
) -> None:
    for line in iter(client_in.readline, b""):
        if not line.strip():
            continue
        forward, reply = proxy.handle_client_line(line)
        if reply is not None:
            client_out.write(reply)
            client_out.flush()
        if forward is not None:
            server_in.write(forward if forward.endswith(b"\n") else forward + b"\n")
            server_in.flush()
    try:
        server_in.close()
    except OSError:
        pass


def _pump_server_to_client(
    proxy: ShieldProxy, server_out: BinaryIO, client_out: BinaryIO
) -> None:
    for line in iter(server_out.readline, b""):
        if not line.strip():
            continue
        client_out.write(proxy.handle_server_line(line))
        client_out.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-mcp-proxy",
        description="Aegis shield-proxy: canonical-policy enforcement at the MCP process boundary.",
    )
    parser.add_argument(
        "--policy", required=True, help="aegis-policy v0 document (JSON or YAML)"
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("AEGIS_AGENT_ID", "mcp-host"),
        help="advisory principal id of the host agent (e.g. claude-code, codex, agy)",
    )
    parser.add_argument("--session-id", default=os.environ.get("AEGIS_SESSION_ID"))
    parser.add_argument("--audit-path", default=None, help="canonical event JSONL path")
    parser.add_argument(
        "--gate",
        choices=["check-access", "tool-call"],
        default=os.environ.get("AEGIS_MCP_GATE", "check-access"),
        help=(
            "FULL-mode gate primitive (explicit, never auto-probed): "
            "'check-access' = @shield-parity purpose gate (works on every live "
            "gateway); 'tool-call' = AI-native per-tool-call gate "
            "(AI_NATIVE_V1_CONTRACT.md; requires a boundary serving it)"
        ),
    )
    parser.add_argument(
        "--owner",
        default=os.environ.get("AEGIS_OWNER"),
        help="principal.owner for the tool-call gate (defaults to --agent-id)",
    )
    parser.add_argument(
        "server_cmd", nargs=argparse.REMAINDER, help="-- real MCP server command"
    )
    args = parser.parse_args(argv)

    # argparse validates `choices` only for the flag form; an invalid
    # AEGIS_MCP_GATE env value arrives via `default` unchecked. Validate the
    # merged value like the Node proxy does (exit 2, same message shape).
    if args.gate not in ("check-access", "tool-call"):
        parser.error(f"unknown --gate {args.gate} (check-access | tool-call)")

    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing real MCP server command after --")

    try:
        policy = load_canonical_policy(
            args.policy
        )  # fail-closed: structural error aborts startup
    except AegisConfigError as exc:
        # Coded one-liner on stderr, exit 2 — parity with the Node proxy.
        # A raw traceback here hid the machine-parseable `code` operators grep
        # for, and exit 1 diverged from Node's exit 2 for the same mistake.
        print(f"aegis-mcp-proxy: {exc} [{exc.code}]", file=sys.stderr)
        return 2
    emitter = CanonicalEmitter(
        ENFORCEMENT_MCP_PROXY,
        PROXY_RUNTIME,
        path=args.audit_path,
        policy_id=policy.policy_id,
    )
    # FULL-mode gate: armed only on explicit intent (AEGIS_MODE=full, or
    # AEGIS_MODE=auto resolving FULL via the same detector @shield uses).
    # Unset/lite keeps today's LITE-only proxy byte-for-byte.
    gate = None
    mode_env = os.environ.get("AEGIS_MODE", "").strip().lower()
    if mode_env and mode_env != "lite":
        from aegis_trust.shield import _detect_mode, _get_client
        from aegis_trust.types import Mode

        if _detect_mode() == Mode.FULL:
            gate = GatewayGate(
                _get_client(), args.gate, owner=args.owner or args.agent_id
            )
            print(
                f"aegis-mcp-proxy: FULL gate armed ({args.gate}) — gateway consulted "
                "before every gated call (deny = tool never runs, fail-closed)",
                file=sys.stderr,
            )

    proxy = ShieldProxy(
        policy,
        emitter,
        agent_id=args.agent_id,
        session_id=args.session_id,
        gate=gate,
    )

    server = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr.fileno(),
    )
    assert server.stdin is not None and server.stdout is not None

    client_in = sys.stdin.buffer
    client_out = sys.stdout.buffer
    t1 = threading.Thread(
        target=_pump_client_to_server,
        args=(proxy, client_in, server.stdin, client_out),
        daemon=True,
    )
    t2 = threading.Thread(
        target=_pump_server_to_client,
        args=(proxy, server.stdout, client_out),
        daemon=True,
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join(timeout=5)
    server.terminate()
    return server.wait(timeout=5) or 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
