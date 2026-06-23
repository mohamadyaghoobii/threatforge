"""G1 acceptance tests for the new generator service."""

from __future__ import annotations

from app.services.generator import profiles, targets
from app.services.generator.backends import builtin
from app.services.generator.warnings import (
    WARNING_CODES,
    WarningSeverity,
    emit,
    from_legacy_strings,
    warning_code_catalog,
)


def test_warning_code_catalog_has_required_codes():
    required = {
        "FIELD_NOT_IN_PROFILE",
        "MODIFIER_NOT_SUPPORTED",
        "CONDITION_AMBIGUOUS",
        "AGGREGATION_NOT_SUPPORTED",
        "BACKEND_UNAVAILABLE",
        "UNMAPPED_TARGET",
        "LEGACY_FALLBACK",
        "EMPTY_DETECTION",
    }
    assert required.issubset(set(WARNING_CODES.keys()))


def test_warning_code_catalog_serializes():
    catalog = warning_code_catalog()
    assert any(entry["code"] == "BACKEND_UNAVAILABLE" for entry in catalog)
    sample = catalog[0]
    assert {"code", "severity", "title", "description", "suggestion"} <= set(sample.keys())


def test_emit_known_code_uses_catalog_defaults():
    w = emit("FIELD_NOT_IN_PROFILE", field="Image", profile="splunk_sysmon")
    assert w.code == "FIELD_NOT_IN_PROFILE"
    assert w.severity == WarningSeverity.WARNING
    assert w.field == "Image"
    assert w.profile == "splunk_sysmon"
    assert w.suggestion is not None


def test_emit_unknown_code_falls_back_to_message():
    w = emit("TOTALLY_UNKNOWN_CODE", message="hello")
    assert w.code == "TOTALLY_UNKNOWN_CODE"
    assert w.severity == WarningSeverity.WARNING
    assert w.message == "hello"


def test_from_legacy_strings_wraps_into_structured():
    result = from_legacy_strings(["msg1", "msg2"], target="splunk", profile="splunk_sysmon", output_format="spl")
    assert len(result) == 2
    assert all(w.code == "LEGACY_FALLBACK" for w in result)
    assert {w.message for w in result} == {"msg1", "msg2"}
    assert all(w.target == "splunk" for w in result)


def test_target_catalog_lists_required_targets():
    ids = {t["id"] for t in targets.list_targets()}
    required = {
        "splunk",
        "sentinel",
        "elastic",
        "opensearch",
        "qradar",
        "chronicle",
        "logscale",
        "sumologic",
        "devo",
        "wazuh",
    }
    assert required <= ids


def test_target_catalog_lists_splunk_formats():
    catalog = targets.list_targets()
    splunk = next(t for t in catalog if t["id"] == "splunk")
    fmt_ids = {f["id"] for f in splunk["formats"]}
    assert {"spl", "savedsearches_conf", "ess_notable", "risk_based_alert", "dashboard_panel"} <= fmt_ids


def test_target_catalog_includes_loaded_profiles():
    profiles.refresh_cache()
    catalog = targets.list_targets()
    splunk = next(t for t in catalog if t["id"] == "splunk")
    profile_ids = {p["id"] for p in splunk["profiles"]}
    assert {"splunk_sysmon", "splunk_windows_security"} <= profile_ids


def test_target_normalization_via_alias():
    assert targets.normalize_target("kql") == "sentinel"
    assert targets.normalize_target("humio") == "logscale"
    assert targets.normalize_target("SPLUNK") == "splunk"
    assert targets.normalize_target("elasticsearch") == "elastic"


def test_profile_loader_resolves_splunk_sysmon():
    profiles.refresh_cache()
    profile = profiles.get_profile("splunk_sysmon")
    assert profile is not None
    assert profile.target == "splunk"
    assert profile.base.index == "sysmon"
    assert "savedsearches_conf" in profile.output_formats
    assert "savedsearches_conf" in profile.output_defaults
    assert profile.output_defaults["savedsearches_conf"].cron_schedule == "*/15 * * * *"


def test_builtin_backend_runs_and_returns_structured_warnings():
    raw = (
        "title: Test\n"
        "logsource:\n"
        "  product: windows\n"
        "  category: process_creation\n"
        "detection:\n"
        "  selection:\n"
        "    CommandLine|contains: ' -enc '\n"
        "  condition: selection\n"
    )
    query, warnings = builtin.convert(raw, "splunk", profile=None, output_format="default")
    assert "CommandLine" in query
    assert all(hasattr(w, "code") for w in warnings)
