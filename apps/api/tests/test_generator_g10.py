"""G10 acceptance tests: explainer, optimizer, round-trip."""

from __future__ import annotations

from app.services.generator import explain as explain_mod
from app.services.generator import optimize as optimize_mod
from app.services.generator import roundtrip as roundtrip_mod


# --- explainer -------------------------------------------------------------


def test_explain_splunk_base_and_contains():
    q = 'index=sysmon sourcetype=Sysmon Image="*\\powershell.exe" CommandLine="*-enc*"'
    text = explain_mod.explain(q, "splunk")
    assert "Splunk" in text
    assert "index=sysmon" in text


def test_explain_in_list():
    q = 'index=sysmon Image IN ("*\\a.exe", "*\\b.exe", "*\\c.exe")'
    text = explain_mod.explain(q, "splunk")
    assert "matches any of 3 values" in text


def test_explain_notable_and_rba():
    q = "action.notable = 1\naction.risk = 1\naction.risk.param._risk_score = 60\nmitre_attack T1059.001"
    text = explain_mod.explain(q, "splunk")
    assert "notable" in text.lower()
    assert "risk" in text.lower()
    assert "T1059.001" in text


def test_explain_empty():
    assert "Empty" in explain_mod.explain("", "splunk")


# --- optimizer -------------------------------------------------------------


def test_optimize_collapses_or_into_in():
    q = '(Image="a" OR Image="b" OR Image="c")'
    optimized, changed, notes = optimize_mod.optimize(q, "splunk")
    assert changed
    assert "IN (" in optimized
    assert '"a", "b", "c"' in optimized


def test_optimize_no_change_when_nothing_to_do():
    q = 'index=main Image="a"'
    optimized, changed, notes = optimize_mod.optimize(q, "splunk")
    assert optimized == q
    assert changed is False


def test_optimize_normalizes_whitespace():
    q = 'index=main      Image="a"'
    optimized, changed, notes = optimize_mod.optimize(q, "splunk")
    assert "  " not in optimized
    assert changed


def test_optimize_preserves_mixed_fields():
    # Different fields must NOT be collapsed into an IN list.
    q = '(Image="a" OR CommandLine="b")'
    optimized, changed, notes = optimize_mod.optimize(q, "splunk")
    assert "IN (" not in optimized


# --- round-trip ------------------------------------------------------------


def test_round_trip_full_coverage():
    detection = {
        "selection": {"Image|endswith": ["\\powershell.exe"], "CommandLine|contains": "-enc"},
        "condition": "selection",
    }
    query = 'index=sysmon Image="*\\powershell.exe" CommandLine="*-enc*"'
    result = roundtrip_mod.round_trip(query, detection)
    assert result["parsed"] is True
    assert result["semantic_match"] is True
    assert result["coverage"] >= 0.8


def test_round_trip_detects_missing_literal():
    detection = {
        "selection": {"CommandLine|contains": ["-enc", "downloadstring", "frombase64string"]},
        "condition": "selection",
    }
    # Query dropped two of the three literals.
    query = 'index=sysmon CommandLine="*-enc*"'
    result = roundtrip_mod.round_trip(query, detection)
    assert result["semantic_match"] is False
    assert "downloadstring" in result["missing_literals"]


def test_round_trip_no_literals():
    result = roundtrip_mod.round_trip("index=main", {"condition": "selection"})
    assert result["semantic_match"] is None
