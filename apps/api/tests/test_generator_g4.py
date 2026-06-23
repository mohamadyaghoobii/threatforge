"""G4 acceptance tests: Splunk profile pack + savedsearches/notable/RBA."""

from __future__ import annotations

import pytest

from app.services.generator import formats, profiles
from app.services.generator.formats import FormatContext


@pytest.fixture(autouse=True)
def _fresh_profiles():
    profiles.refresh_cache()
    yield


# --- profile pack ----------------------------------------------------------

EXPECTED_SPLUNK_PROFILES = {
    "splunk_sysmon",
    "splunk_windows_security",
    "splunk_powershell",
    "splunk_cim_endpoint",
    "splunk_cim_network",
    "splunk_cim_auth",
    "splunk_linux_syslog",
    "splunk_aws_cloudtrail",
    "splunk_azure_activity",
    "splunk_okta",
    "splunk_o365",
    "splunk_palo_traffic",
}


def test_twelve_splunk_profiles_load():
    ids = {p.id for p in profiles.list_profiles(target="splunk")}
    missing = EXPECTED_SPLUNK_PROFILES - ids
    assert not missing, f"missing profiles: {missing}"
    assert len(EXPECTED_SPLUNK_PROFILES) >= 12


def test_field_mapping_pack_loads():
    pack = profiles.load_field_mapping_pack("splunk_cim_endpoint")
    assert pack.get("Image") == "process_path"
    assert pack.get("CommandLine") == "process"


def test_profile_field_overrides_resolved():
    overrides = profiles.profile_field_overrides("splunk_cim_endpoint")
    assert overrides.get("Image") == "process_path"


# --- format layer ----------------------------------------------------------


def test_format_registry_has_splunk_formats():
    for fmt in ["spl", "savedsearches_conf", "ess_notable", "risk_based_alert", "dashboard_panel", "datamodel_tstats"]:
        assert formats.resolve("splunk", fmt) is not None, fmt


def test_spl_plan_is_passthrough():
    plan = formats.resolve("splunk", "spl")
    assert plan.backend_format == "spl"
    assert plan.formatter is None


def test_rich_plans_request_spl_body():
    for fmt in ["savedsearches_conf", "ess_notable", "risk_based_alert", "dashboard_panel"]:
        plan = formats.resolve("splunk", fmt)
        assert plan.backend_format == "spl"
        assert plan.formatter is not None


def _ctx(output_format: str) -> FormatContext:
    profile = profiles.get_profile("splunk_sysmon")
    return FormatContext(
        target="splunk",
        output_format=output_format,
        title="Encoded PowerShell",
        description="Detects encoded PowerShell",
        severity="high",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059.001"],
        profile=profile,
        profile_id="splunk_sysmon",
    )


BODY = 'index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="* -enc *"'


def test_savedsearches_conf_renders_full_stanza():
    plan = formats.resolve("splunk", "savedsearches_conf")
    out = formats.apply(plan, BODY, _ctx("savedsearches_conf"))
    assert out.startswith("[MetaSec Security Center - Encoded PowerShell]")
    assert "search = " + BODY in out
    assert "cron_schedule = */15 * * * *" in out
    assert "alert.suppress = 1" in out
    assert "action.notable = 1" in out
    assert "action.notable.param.security_domain = endpoint" in out
    # MITRE annotation JSON present with the technique id
    assert '"mitre_attack":["T1059.001"]' in out
    assert "action.correlationsearch.enabled = 1" in out


def test_savedsearches_conf_includes_rba_when_enabled():
    plan = formats.resolve("splunk", "savedsearches_conf")
    out = formats.apply(plan, BODY, _ctx("savedsearches_conf"))
    assert "action.risk = 1" in out
    assert "action.risk.param._risk_score = 40" in out
    assert "action.risk.param._risk_object = user" in out


def test_risk_based_alert_format():
    plan = formats.resolve("splunk", "risk_based_alert")
    out = formats.apply(plan, BODY, _ctx("risk_based_alert"))
    assert "action.risk = 1" in out
    assert "action.risk.param._risk_object = user" in out
    assert "RBA" in out


def test_dashboard_panel_is_xml():
    plan = formats.resolve("splunk", "dashboard_panel")
    out = formats.apply(plan, BODY, _ctx("dashboard_panel"))
    assert out.strip().startswith("<panel>")
    assert "<title>Encoded PowerShell</title>" in out
    assert "stats count by" in out
    assert "</panel>" in out.strip()


def test_severity_number_from_profile():
    ctx = _ctx("savedsearches_conf")
    assert ctx.severity_number() == 4  # high -> 4 in splunk_sysmon severity_map
