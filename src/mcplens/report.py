"""Human-readable rendering of scan reports, snapshots, and diffs."""
from __future__ import annotations

from .baseline import DiffResult
from .models import ScanReport, SEVERITIES

_SEV_MARK = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def render_text(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"mcplens scan — {report.target_label} [{report.transport}]")
    lines.append("=" * 72)
    lines.append(f"Tools enumerated: {len(report.tools)}")
    for t in report.tools:
        desc = (t.description or "").strip().splitlines()
        first = desc[0][:90] if desc else "(no description)"
        lines.append(f"  - {t.name}: {first}")
    lines.append("")

    findings = report.sorted_findings()
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append(f"Findings: {len(findings)} "
                 f"(critical {counts['critical']}, high {counts['high']}, "
                 f"medium {counts['medium']}, low {counts['low']}, info {counts['info']})")
    for f in findings:
        where = f.tool or "server"
        lines.append(f"  [{_SEV_MARK[f.severity]:8}] {f.rule_id} ({f.source}) {where}: {f.title}")
        lines.append(f"             {f.detail}")
        lines.append(f"             OWASP: {f.owasp}")
    if not findings:
        lines.append("  (none)")
    lines.append("")

    if report.probes_run:
        lines.append("Behavioral probes (declared vs observed):")
        for p in report.probes:
            if not p.probed:
                lines.append(f"  - {p.tool}: NOT PROBED — {p.note}")
                continue
            declared = ", ".join(p.declared) if p.declared else "nothing specific"
            observed = "; ".join(p.observed) if p.observed else "no observable behavior"
            lines.append(f"  - {p.tool}: declared [{declared}] | observed [{observed}]")
            if p.error:
                lines.append(f"      error: {p.error}")
        lines.append("")

    lines.append(f"Grade: {report.grade}  (score {report.score}/100)")
    return "\n".join(lines)


def render_diff(result: DiffResult, label: str) -> str:
    lines = [f"mcplens diff — {label}", "=" * 72]
    lines.append(f"Baseline set hash: {result.old_set_hash[:16]}…")
    lines.append(f"Current  set hash: {result.new_set_hash[:16]}…")
    if not result.has_changes:
        lines.append("No changes: tool definitions match the baseline exactly.")
        return "\n".join(lines)
    lines.append(f"CHANGES DETECTED: {len(result.changes)}")
    for c in result.changes:
        if c.kind == "changed":
            lines.append(f"  ~ CHANGED  {c.name} (fields: {', '.join(c.fields)})")
        elif c.kind == "added":
            lines.append(f"  + ADDED    {c.name}")
        else:
            lines.append(f"  - REMOVED  {c.name}")
    lines.append("")
    lines.append("A changed tool definition after approval is the rug-pull pattern: "
                 "re-audit before trusting this server again.")
    return "\n".join(lines)
