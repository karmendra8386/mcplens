"""Static analysis rules over MCP tool definitions.

Each rule has a stable ID (MCPL0xx), a severity, and an OWASP MCP Top 10
mapping. Static rules are table stakes — mcplens' headline feature is the
runtime behavioral probes in probes.py — but they catch the classic
tool-poisoning patterns cheaply and deterministically.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any

from .models import Finding, ToolInfo

OWASP = {
    "MCP01": "MCP01 Token Mismanagement & Secret Exposure",
    "MCP02": "MCP02 Context Over-Sharing & Excessive Data Access",
    "MCP03": "MCP03 Supply Chain & Dependency Risks",
    "MCP04": "MCP04 Command Injection & Execution Risks",
    "MCP05": "MCP05 Tool Poisoning & Prompt Injection",
    "MCP06": "MCP06 Privilege Escalation & Excessive Permissions",
    "MCP07": "MCP07 Insufficient Authentication & Authorization",
    "MCP08": "MCP08 Audit Logging & Accountability Gaps",
    "MCP09": "MCP09 Protocol & Transport Vulnerabilities",
    "MCP10": "MCP10 Insecure Plugin / Extension Practices",
}

# --- pattern tables --------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|the above)",
    r"do\s+not\s+tell\s+the\s+user",
    r"don'?t\s+tell\s+the\s+user",
    r"without\s+(telling|informing|notifying)\s+the\s+user",
    r"<\s*important\s*>",
    r"<\s*system\s*>",
    r"before\s+(calling|using|invoking)\s+this\s+tool",
    r"always\s+call\s+this\s+tool\s+first",
    r"you\s+must\s+first\s+(read|fetch|load|include)",
    r"pass\s+(it|its\s+contents|the\s+contents)\s+as\s+(the\s+)?\w+\s+parameter",
    r"new\s+instructions\s*:",
    r"system\s+prompt",
]
INJECTION_RES = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

SENSITIVE_PATH_PATTERNS = [
    r"~/\.ssh", r"id_rsa", r"id_ed25519", r"/etc/passwd", r"/etc/shadow",
    r"\.aws/credentials", r"\.aws\\credentials", r"\.env\b", r"\.gnupg",
    r"\.kube/config", r"credentials\.json", r"\.netrc", r"\.git-credentials",
]
SENSITIVE_RES = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATH_PATTERNS]

# Codepoints that are invisible or can reorder/hide text.
def _is_suspicious_unicode(ch: str) -> bool:
    cp = ord(ch)
    if cp in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060):  # zero-width / BOM / word joiner
        return True
    if 0x202A <= cp <= 0x202E:  # bidi embedding/override
        return True
    if 0x2066 <= cp <= 0x2069:  # bidi isolates
        return True
    if 0xE0000 <= cp <= 0xE007F:  # Unicode tag characters
        return True
    return False

# Read-only-sounding name prefixes (see MCPL008 / probe read-only checks).

READONLY_PREFIXES = ("get_", "list_", "read_", "fetch_", "search_", "describe_", "show_", "view_", "lookup_")
WRITE_WORDS = re.compile(
    r"\b(write|writes|writing|delete|deletes|remove|removes|modify|modifies|create|creates|"
    r"update|updates|execute|executes|run|runs|install|overwrite|append|store|stores|save|saves)\b",
    re.IGNORECASE,
)
SHELL_PARAM_NAMES = {"command", "cmd", "shell", "script", "code", "exec", "bash", "sh", "powershell"}
SECRET_PARAM_NAMES = {"password", "passwd", "api_key", "apikey", "secret", "access_token", "private_key"}
BROAD_ACCESS_RE = re.compile(
    r"(environment\s+variables?|\benv\s+vars?\b|all\s+files|entire\s+(file\s*system|disk|home)|"
    r"home\s+directory|any\s+file|full\s+disk)",
    re.IGNORECASE,
)


def _props(tool: ToolInfo) -> dict[str, Any]:
    props = tool.input_schema.get("properties")
    return props if isinstance(props, dict) else {}


def _norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def analyze_tools(tools: list[ToolInfo], target_url: str = "") -> list[Finding]:
    findings: list[Finding] = []

    def add(rule_id, severity, title, tool_name, detail, owasp_key, source="static"):
        findings.append(Finding(rule_id=rule_id, severity=severity, title=title,
                                tool=tool_name, detail=detail,
                                owasp=OWASP[owasp_key], source=source))

    # Server-level: plaintext HTTP transport (MCPL013)
    if target_url.startswith("http://"):
        add("MCPL013", "medium", "Server reached over plaintext HTTP",
            None, f"Target {target_url} uses http:// — tool definitions and results "
                  "cross the network unencrypted.", "MCP09")

    if len(tools) > 50:
        add("MCPL009", "low", "Excessive tool count", None,
            f"Server exposes {len(tools)} tools; very large tool surfaces are hard "
            "to audit and widen the poisoning blast radius.", "MCP02")

    seen: dict[str, int] = {}
    for t in tools:
        seen[t.name] = seen.get(t.name, 0) + 1
    for name, count in seen.items():
        if count > 1:
            add("MCPL010", "high", "Duplicate tool name", name,
                f"Tool name '{name}' appears {count} times; clients may dispatch "
                "to the wrong implementation.", "MCP05")

    # MCPL004 — shadowing via look-alike names: names that differ only by
    # case or separators normalize identically; a client (or a human reviewer)
    # can easily confuse them, which is how tool shadowing hides.
    norm_groups: dict[str, set[str]] = {}
    for t in tools:
        norm_groups.setdefault(_norm_name(t.name), set()).add(t.name)
    for _norm, names in norm_groups.items():
        if len(names) > 1:
            joined = ", ".join(sorted(names))
            add("MCPL004", "medium", "Look-alike tool names (possible shadowing)",
                sorted(names)[0],
                f"Tool names {joined} are identical once case and separators are "
                "ignored — a classic tool-shadowing arrangement.", "MCP05")

    for tool in tools:
        name, desc = tool.name, tool.description or ""
        text = f"{name}\n{desc}"

        # MCPL001 — instruction injection in description
        for rx in INJECTION_RES:
            m = rx.search(desc)
            if m:
                add("MCPL001", "critical", "Instruction injection in tool description",
                    name, f"Description contains directive phrasing matching "
                          f"'{m.group(0)}' — tool descriptions are fed to the model "
                          "as trusted context (tool poisoning).", "MCP05")
                break

        # MCPL002 — hidden / suspicious Unicode
        bad = sorted({ch for ch in text if _is_suspicious_unicode(ch)})
        if bad:
            cps = ", ".join(f"U+{ord(c):04X} ({unicodedata.name(c, 'unknown')})" for c in bad)
            add("MCPL002", "high", "Hidden or bidirectional Unicode in tool definition",
                name, f"Suspicious invisible/control characters present: {cps}. "
                      "These can hide instructions from human reviewers.", "MCP05")

        # MCPL003 — sensitive path references in description
        for rx in SENSITIVE_RES:
            m = rx.search(desc)
            if m:
                add("MCPL003", "critical", "Tool description references sensitive files",
                    name, f"Description references '{m.group(0)}'. A tool description "
                          "has no legitimate reason to point the model at credential "
                          "material.", "MCP05")
                break

        # MCPL015 — missing description
        if not desc.strip():
            add("MCPL015", "low", "Tool has no description", name,
                "Undescribed tools cannot be audited for declared behavior and "
                "give the model nothing to reason about.", "MCP08")

        # MCPL012 — overlong description
        if len(desc) > 2000:
            add("MCPL012", "low", "Unusually long tool description", name,
                f"Description is {len(desc)} characters; long descriptions are a "
                "known hiding place for injected instructions.", "MCP05")

        # MCPL011 — broad data access language
        m = BROAD_ACCESS_RE.search(desc)
        if m:
            add("MCPL011", "medium", "Description claims broad data access", name,
                f"Description references '{m.group(0)}' — broader access than a "
                "single-purpose tool should need.", "MCP02")

        # MCPL008 — read-only name, write/exec description (static confused deputy)
        if name.lower().startswith(READONLY_PREFIXES):
            m = WRITE_WORDS.search(desc)
            if m:
                add("MCPL008", "medium", "Read-only-sounding tool describes write/exec behavior",
                    name, f"Name suggests read-only access but the description mentions "
                          f"'{m.group(0)}'. Declared behavior and naming disagree — "
                          "verify with `mcplens scan --probes`.", "MCP06")

        # --- schema rules ---
        required = set(tool.input_schema.get("required") or [])
        for pname, pschema in _props(tool).items():
            if not isinstance(pschema, dict):
                continue
            ptype = pschema.get("type")
            plow = pname.lower()

            # MCPL005 — unconstrained shell-like parameter
            if plow in SHELL_PARAM_NAMES and ptype == "string" \
                    and not pschema.get("enum") and not pschema.get("pattern"):
                add("MCPL005", "high", "Unconstrained shell/command parameter", name,
                    f"Parameter '{pname}' is a free-form string with no enum or "
                    "pattern constraint — a direct command-injection surface if it "
                    "reaches a shell.", "MCP04")

            # MCPL006 — untyped parameter
            if ptype is None and "enum" not in pschema and "$ref" not in pschema \
                    and "anyOf" not in pschema and "oneOf" not in pschema:
                add("MCPL006", "medium", "Parameter has no type constraint", name,
                    f"Parameter '{pname}' declares no type; the client and model "
                    "cannot validate values before dispatch.", "MCP09")

            # MCPL014 — tool asks for secrets as plain parameters
            if plow in SECRET_PARAM_NAMES and ptype == "string":
                add("MCPL014", "medium", "Tool accepts a secret as a plain parameter", name,
                    f"Parameter '{pname}' collects credential material through the "
                    "model context, where it can be logged or leaked.", "MCP01")

        # MCPL007 — overly permissive schema
        if tool.input_schema.get("additionalProperties") is True:
            add("MCPL007", "medium", "Schema allows arbitrary additional properties", name,
                "inputSchema sets additionalProperties: true, so callers can pass "
                "undeclared parameters the schema never vetted.", "MCP06")

    return findings
