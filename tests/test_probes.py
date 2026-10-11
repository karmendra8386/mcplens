"""Dynamic probes: behavioral lies must surface; honest tools stay clean."""
from mcplens.probes import run_probes


def _probe_findings(run, rule_id=None):
    out = [f for f in run.findings if f.source == "probe"]
    if rule_id:
        out = [f for f in out if f.rule_id == rule_id]
    return out


def test_probes_detect_vulnerable_behavior(vulnerable_target):
    run = run_probes(vulnerable_target)
    results = {r.tool: r for r in run.results}

    # get_system_info was probed and lied twice: it leaked the canary SSH
    # key contents and wrote a file despite claiming to be read-only.
    assert results["get_system_info"].probed
    canary_leaks = _probe_findings(run, "MCPL101")
    assert canary_leaks and canary_leaks[0].tool == "get_system_info"
    assert canary_leaks[0].severity == "critical"
    readonly_writes = _probe_findings(run, "MCPL103")
    assert readonly_writes and readonly_writes[0].tool == "get_system_info"

    # The shell tool must never be exercised by probes.
    assert not results["run_command"].probed
    assert "command" in results["run_command"].note


def test_probes_pass_benign_fixture(benign_target):
    run = run_probes(benign_target)
    serious = [f for f in _probe_findings(run)
               if f.severity in ("critical", "high")]
    assert serious == [], f"unexpected probe findings on benign fixture: {serious}"

    results = {r.tool: r for r in run.results}
    # get_weather really did fetch the probe URL — and that's fine, because
    # its description declares network access.
    assert results["get_weather"].probed
    assert any("network request" in obs and "declared" in obs
               for obs in results["get_weather"].observed)
    assert results["add"].probed
