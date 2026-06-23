"""G8 acceptance tests: offline + live validators."""

from __future__ import annotations

from app.services.generator import validators


# --- offline: well-formed queries pass --------------------------------------


def test_offline_valid_splunk():
    r = validators.validate("splunk", 'index=sysmon EventCode=1 Image="*\\powershell.exe"', "offline")
    assert r.ok is True
    assert r.errors == []


def test_offline_valid_kql():
    r = validators.validate("sentinel", 'DeviceProcessEvents | where FileName == "powershell.exe"', "offline")
    assert r.ok is True


def test_offline_valid_aql():
    r = validators.validate("qradar", "SELECT * FROM events WHERE \"Command\" ILIKE '%-enc%'", "offline")
    assert r.ok is True


# --- offline: broken queries fail -------------------------------------------


def test_offline_unbalanced_parens():
    r = validators.validate("splunk", 'index=sysmon (Image="x" OR Image="y"', "offline")
    assert r.ok is False
    assert any("Unclosed" in e or "Unbalanced" in e for e in r.errors)


def test_offline_unterminated_string():
    r = validators.validate("splunk", 'index=sysmon Image="unterminated', "offline")
    assert r.ok is False
    assert any("Unterminated" in e for e in r.errors)


def test_offline_empty_query():
    r = validators.validate("splunk", "   ", "offline")
    assert r.ok is False
    assert any("Empty" in e for e in r.errors)


def test_offline_aql_select_without_from():
    r = validators.validate("qradar", "SELECT sourceip WHERE x = 1", "offline")
    assert r.ok is False
    assert any("FROM" in e for e in r.errors)


def test_offline_balanced_ignores_delims_in_strings():
    # Parens inside a quoted string must not trip the balance check.
    r = validators.validate("splunk", 'index=main CommandLine="echo (hi)"', "offline")
    assert r.ok is True


def test_offline_kql_leading_where_warns():
    r = validators.validate("sentinel", "| where x == 1", "offline")
    assert r.ok is True  # structurally balanced
    assert any("table" in w for w in r.warnings)


# --- live: skipped without credentials --------------------------------------


def test_live_skipped_without_env(monkeypatch):
    monkeypatch.delenv("SPLUNK_URL", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    r = validators.validate("splunk", "index=main", "live")
    assert r.ok is None
    assert r.mode == "live"
    assert "skipped" in (r.note or "").lower()


def test_live_unwired_target_skips():
    r = validators.validate("chronicle", "metadata.event_type != \"\"", "live")
    assert r.ok is None
    assert "No live validator" in (r.note or "")
