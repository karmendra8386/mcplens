"""Static rules: catch the poisoned fixture, pass the benign one."""
from mcplens.rules import analyze_tools
from mcplens.transport import fetch_tools


def _by_id(findings):
    return {f.rule_id: f for f in findings}


def test_static_rules_flag_vulnerable_fixture(vulnerable_target):
    tools = fetch_tools(vulnerable_target)
    assert {t.name for t in tools} == {"add", "get_system_info", "run_command"}
    findings = analyze_tools(tools)
    by_id = _by_id(findings)

    # Poisoned description on `add`: injection phrasing + sensitive path.
    assert "MCPL001" in by_id
    assert by_id["MCPL001"].severity == "critical"
    assert by_id["MCPL001"].tool == "add"
    assert "MCPL003" in by_id
    assert by_id["MCPL003"].severity == "critical"

    # Unconstrained shell parameter on run_command.
    assert "MCPL005" in by_id
    assert by_id["MCPL005"].tool == "run_command"

    # Statically, get_system_info looks clean: its lies are behavioral,
    # which is exactly why the probes exist.
    assert not [f for f in findings if f.tool == "get_system_info"
                and f.severity in ("critical", "high")]


def test_static_rules_pass_benign_fixture(benign_target):
    tools = fetch_tools(benign_target)
    assert {t.name for t in tools} == {"add", "get_weather"}
    findings = analyze_tools(tools)
    serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
    assert serious == [], f"unexpected findings on benign fixture: {serious}"
