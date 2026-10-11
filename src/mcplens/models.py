"""Core data structures for mcplens."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: i for i, name in enumerate(SEVERITIES)}
SEVERITY_PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1}


@dataclass
class ToolInfo:
    """A single tool definition as advertised by an MCP server (tools/list)."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mcp(cls, tool: Any) -> "ToolInfo":
        schema = getattr(tool, "inputSchema", None) or \
            getattr(tool, "input_schema", None) or {}
        if not isinstance(schema, dict):
            try:
                schema = dict(schema)
            except Exception:
                schema = {}
        return cls(
            name=getattr(tool, "name", "") or "",
            description=getattr(tool, "description", None) or "",
            input_schema=schema,
        )

    def canonical(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Finding:
    rule_id: str
    severity: str  # one of SEVERITIES
    title: str
    tool: Optional[str]  # tool name, or None for server-level findings
    detail: str
    owasp: str = ""  # OWASP MCP Top 10 mapping, e.g. "MCP05 Tool Poisoning"
    source: str = "static"  # "static" or "probe"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolProbeResult:
    tool: str
    probed: bool
    note: str = ""
    declared: list[str] = field(default_factory=list)   # behaviors implied by name/description
    observed: list[str] = field(default_factory=list)   # behaviors actually observed
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    target_label: str
    transport: str  # "stdio" or "http"
    tools: list[ToolInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    probes: list[ToolProbeResult] = field(default_factory=list)
    probes_run: bool = False

    @property
    def score(self) -> int:
        score = 100
        for f in self.findings:
            score -= SEVERITY_PENALTY.get(f.severity, 0)
        return max(0, score)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_label,
            "transport": self.transport,
            "grade": self.grade,
            "score": self.score,
            "tools": [t.canonical() for t in self.tools],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "probes_run": self.probes_run,
            "probes": [p.to_dict() for p in self.probes],
        }
