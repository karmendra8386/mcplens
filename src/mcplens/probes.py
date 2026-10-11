"""Runtime behavioral verification (dynamic probes).

Static rules read what a server *claims*. Probes check what it *does*:

* the server is launched in a sandbox whose HOME is stocked with canary
  credential files containing unique tokens;
* each tool is invoked once with safe, schema-derived benign inputs;
* we watch for canary tokens leaking into responses, undeclared filesystem
  writes (tree hashed before/after every call, attributed per tool), and
  network egress to a local listener the tool was handed as a URL argument.

Probes are deliberately benign: no destructive payloads, free-form command
parameters are never exercised, destructive-looking tools are skipped, and
the real HOME is never touched.
"""
from __future__ import annotations

import asyncio
import re
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional

from . import transport
from .models import Finding, ToolInfo, ToolProbeResult
from .rules import OWASP, READONLY_PREFIXES, SHELL_PARAM_NAMES, WRITE_WORDS
from .sandbox import Sandbox, diff_trees

DESTRUCTIVE_NAME_RE = re.compile(
    r"(delete|remove|drop|destroy|wipe|erase|purge|kill|shutdown|format|uninstall)",
    re.IGNORECASE,
)
NETWORK_WORDS = re.compile(
    r"\b(fetch|fetches|http|https|url|download|downloads|weather|web|api|network|online|request|requests)\b",
    re.IGNORECASE,
)
READONLY_CLAIM_RE = re.compile(r"read[- ]only", re.IGNORECASE)
EXEC_WORDS = re.compile(r"\b(execute|executes|run|runs|shell|command|commands)\b", re.IGNORECASE)


# --------------------------------------------------------------------------
# Local egress listener
# --------------------------------------------------------------------------

class EgressListener:
    """A throwaway HTTP server on 127.0.0.1 that records every hit."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                listener.hits.append(self.path)
                body = b"mcplens egress probe ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle

            def log_message(self, *args: Any) -> None:  # silence
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcplens-egress-probe"

    def __enter__(self) -> "EgressListener":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


# --------------------------------------------------------------------------
# Declared behavior inference
# --------------------------------------------------------------------------

def is_readonly_claimed(tool: ToolInfo) -> bool:
    return tool.name.lower().startswith(READONLY_PREFIXES) or \
        bool(READONLY_CLAIM_RE.search(tool.description or ""))


def declared_behaviors(tool: ToolInfo) -> list[str]:
    desc = tool.description or ""
    out: list[str] = []
    if is_readonly_claimed(tool):
        out.append("read-only access")
    if WRITE_WORDS.search(desc):
        out.append("writes or modifies data")
    if NETWORK_WORDS.search(desc):
        out.append("network access")
    if EXEC_WORDS.search(desc):
        out.append("command execution")
    return out


def has_shell_param(tool: ToolInfo) -> bool:
    props = tool.input_schema.get("properties") or {}
    for pname, pschema in props.items():
        if isinstance(pschema, dict) and pname.lower() in SHELL_PARAM_NAMES \
                and pschema.get("type") == "string" \
                and not pschema.get("enum") and not pschema.get("pattern"):
            return True
    return False


# --------------------------------------------------------------------------
# Benign argument derivation
# --------------------------------------------------------------------------

def _derive_value(pname: str, pschema: dict[str, Any], listener_url: str,
                  benign_file: str) -> tuple[bool, Any]:
    """Return (ok, value). ok=False means we cannot derive a safe value."""
    if "enum" in pschema and pschema["enum"]:
        return True, pschema["enum"][0]
    if "default" in pschema:
        return True, pschema["default"]
    ptype = pschema.get("type")
    plow = pname.lower()
    if ptype == "string" or (ptype is None and pschema.get("format")):
        if "url" in plow or "uri" in plow or pschema.get("format") in ("uri", "url"):
            return True, listener_url
        if any(h in plow for h in ("path", "file", "dir", "folder", "filename")):
            return True, benign_file
        if "email" in plow:
            return True, "probe@example.invalid"
        return True, "mcplens-probe"
    if ptype == "integer":
        val = pschema.get("minimum", 1)
        if "maximum" in pschema:
            val = min(val, pschema["maximum"])
        return True, int(val)
    if ptype == "number":
        val = pschema.get("minimum", 1)
        if "maximum" in pschema:
            val = min(val, pschema["maximum"])
        return True, float(val)
    if ptype == "boolean":
        return True, False
    if ptype == "array":
        return True, []
    if ptype == "object":
        return True, {}
    if ptype is None:
        return True, "mcplens-probe"
    return False, None


def derive_args(tool: ToolInfo, listener_url: str, benign_file: str) -> tuple[Optional[dict], Optional[str]]:
    """Return (args, None) or (None, reason-not-probed)."""
    if DESTRUCTIVE_NAME_RE.search(tool.name):
        return None, "tool name suggests a destructive operation — not probed"
    if has_shell_param(tool):
        return None, "free-form command parameter — never exercised by probes"
    props = tool.input_schema.get("properties") or {}
    required = set(tool.input_schema.get("required") or [])
    args: dict[str, Any] = {}
    for pname, pschema in props.items():
        if not isinstance(pschema, dict):
            continue
        ok, value = _derive_value(pname, pschema, listener_url, benign_file)
        if not ok:
            if pname in required:
                return None, f"cannot derive a safe value for required parameter '{pname}'"
            continue
        args[pname] = value
    missing = required - set(args)
    if missing:
        return None, f"cannot derive safe values for required parameters: {sorted(missing)}"
    return args, None


# --------------------------------------------------------------------------
# Probe run
# --------------------------------------------------------------------------

@dataclass
class ProbeRun:
    tools: list[ToolInfo]
    findings: list[Finding]
    results: list[ToolProbeResult]
    sandbox: Sandbox


def _finding(rule_id, severity, title, tool_name, detail, owasp_key) -> Finding:
    return Finding(rule_id=rule_id, severity=severity, title=title, tool=tool_name,
                   detail=detail, owasp=OWASP[owasp_key], source="probe")


async def _probe_async(target: transport.Target, sandbox: Sandbox,
                       listener: EgressListener) -> ProbeRun:
    findings: list[Finding] = []
    results: list[ToolProbeResult] = []
    tokens = sandbox.tokens()

    benign_file = sandbox.work / "benign_input.txt"
    benign_file.write_text("hello from the mcplens probe\n", encoding="utf-8")

    async with transport.connect(target, extra_env=sandbox.env(),
                                 cwd=str(sandbox.work)) as session:
        tools = await transport._list_tools(session)

        for tool in tools:
            declared = declared_behaviors(tool)
            result = ToolProbeResult(tool=tool.name, probed=False, declared=declared)
            args, skip_reason = derive_args(tool, listener.url, str(benign_file))
            if args is None:
                result.note = skip_reason or "not probed"
                results.append(result)
                continue

            before_tree = sandbox.tree_hashes()
            hits_before = len(listener.hits)
            result.probed = True
            try:
                call = await asyncio.wait_for(
                    session.call_tool(tool.name, args),
                    timeout=transport.CALL_TIMEOUT,
                )
                text = transport.result_text(call)
                is_error = bool(getattr(call, "isError", None)
                                or getattr(call, "is_error", False))
            except Exception as exc:  # timeout, protocol error, transport drop
                text, is_error = "", True
                result.error = f"{type(exc).__name__}: {exc}"

            after_tree = sandbox.tree_hashes()
            changes = diff_trees(before_tree, after_tree)
            new_hits = listener.hits[hits_before:]

            if is_error:
                result.observed.append("errored during probe invocation")
                if not result.error:
                    snippet = text.strip().splitlines()[0][:160] if text.strip() else "tool returned an error"
                    result.error = snippet
                findings.append(_finding(
                    "MCPL105", "low", "Tool errored under benign probe input",
                    tool.name, f"Invoking with safe derived arguments produced an "
                               f"error: {result.error}", "MCP08"))
            else:
                result.observed.append("returned a response")

            # (a) canary token leak => undeclared sensitive-file read
            leaked = [rel for token, rel in tokens.items() if token in text]
            if leaked:
                result.observed.append(f"returned contents of canary file(s): {', '.join(leaked)}")
                findings.append(_finding(
                    "MCPL101", "critical", "Tool returned canary credential contents",
                    tool.name, "The tool's response contained the unique token planted "
                               f"in sandbox canary file(s) {', '.join(leaked)}. The tool "
                               "read sensitive files its description never discloses — "
                               "behavioral confirmation of an undeclared sensitive read.",
                    "MCP02"))

            # (b) filesystem changes attributed to this invocation
            changed_paths = changes["created"] + changes["modified"] + changes["deleted"]
            if changed_paths:
                result.observed.append(
                    "filesystem changes: " + ", ".join(changed_paths))
                if is_readonly_claimed(tool):
                    findings.append(_finding(
                        "MCPL103", "critical", "Read-only-claimed tool modified the filesystem",
                        tool.name, f"'{tool.name}' presents as read-only but changed "
                                   f"files during probing: {', '.join(changed_paths)}. "
                                   "Declared and observed behavior disagree.", "MCP06"))
                elif not WRITE_WORDS.search(tool.description or ""):
                    findings.append(_finding(
                        "MCPL102", "high", "Tool modified the filesystem without declaring it",
                        tool.name, f"Probing caused filesystem changes not hinted at "
                                   f"in the description: {', '.join(changed_paths)}.",
                        "MCP06"))

            # (c) network egress during this invocation
            if new_hits:
                if NETWORK_WORDS.search(tool.description or ""):
                    result.observed.append("network request to probe URL (declared)")
                else:
                    result.observed.append("network request to probe URL (undeclared)")
                    findings.append(_finding(
                        "MCPL104", "high", "Tool made an undeclared network request",
                        tool.name, "The tool fetched the local probe URL it was handed "
                                   "as an argument, but its description gives no hint of "
                                   "network use — an exfiltration-shaped behavior.",
                        "MCP02"))

            results.append(result)

    return ProbeRun(tools=tools, findings=findings, results=results, sandbox=sandbox)


def run_probes(target: transport.Target, sandbox: Optional[Sandbox] = None,
               keep_sandbox: bool = False) -> ProbeRun:
    """Synchronously probe a stdio target in a fresh sandbox."""
    if target.kind != "stdio":
        raise ValueError("dynamic probes require a stdio target")
    sandbox = sandbox or Sandbox.create()
    try:
        with EgressListener() as listener:
            return asyncio.run(_probe_async(target, sandbox, listener))
    finally:
        if not keep_sandbox:
            sandbox.cleanup()
