"""G5 acceptance tests: Sentinel profile pack + analytic rule ARM."""

from __future__ import annotations

import json

import pytest
import yaml

from app.services.generator import formats, profiles
from app.services.generator.formats import FormatContext


@pytest.fixture(autouse=True)
def _fresh():
    profiles.refresh_cache()
    yield


EXPECTED_SENTINEL_PROFILES = {
    "sentinel_defender_device_process",
    "sentinel_defender_device_network",
    "sentinel_defender_device_file",
    "sentinel_defender_device_registry",
    "sentinel_defender_device_logon",
    "sentinel_defender_email",
    "sentinel_security_event",
    "sentinel_aad_signin",
    "sentinel_office_activity",
    "sentinel_syslog",
}


def test_ten_sentinel_profiles_load():
    ids = {p.id for p in profiles.list_profiles(target="sentinel")}
    missing = EXPECTED_SENTINEL_PROFILES - ids
    assert not missing, f"missing: {missing}"
    assert len(EXPECTED_SENTINEL_PROFILES) >= 10


def test_sentinel_format_registry():
    for fmt in ["kql", "analytic_rule_arm", "hunting_query_yaml", "workbook_panel"]:
        assert formats.resolve("sentinel", fmt) is not None, fmt


def _ctx(output_format: str) -> FormatContext:
    profile = profiles.get_profile("sentinel_defender_device_process")
    return FormatContext(
        target="sentinel",
        output_format=output_format,
        title="Encoded PowerShell",
        description="Detects encoded PowerShell",
        severity="high",
        rule_id=42,
        external_rule_id="abcd-1234",
        mitre_tactics=["Execution", "Defense Evasion"],
        mitre_techniques=["T1059.001", "T1059"],
        profile=profile,
        profile_id="sentinel_defender_device_process",
    )


BODY = 'DeviceProcessEvents | where FileName in~ ("powershell.exe") | where ProcessCommandLine has "-enc"'


def test_analytic_rule_arm_structure():
    plan = formats.resolve("sentinel", "analytic_rule_arm")
    out = formats.apply(plan, BODY, _ctx("analytic_rule_arm"))
    doc = json.loads(out)
    assert doc["type"] == "Microsoft.SecurityInsights/alertRules"
    assert doc["kind"] == "Scheduled"
    props = doc["properties"]
    assert props["query"] == BODY
    assert props["severity"] == "High"
    assert props["queryFrequency"] == "PT15M"
    # tactics mapped to Sentinel enum (no spaces)
    assert "Execution" in props["tactics"]
    assert "DefenseEvasion" in props["tactics"]
    # parent technique + sub-technique split
    assert "T1059" in props["techniques"]
    assert "T1059.001" in props["subTechniques"]
    # entity mappings from profile entity_inference
    types = {m["entityType"] for m in props["entityMappings"]}
    assert "Host" in types and "Account" in types and "Process" in types
    assert props["incidentConfiguration"]["createIncident"] is True


def test_hunting_query_yaml():
    plan = formats.resolve("sentinel", "hunting_query_yaml")
    out = formats.apply(plan, BODY, _ctx("hunting_query_yaml"))
    doc = yaml.safe_load(out)
    assert doc["name"] == "Encoded PowerShell"
    assert doc["query"] == BODY
    assert "Execution" in doc["tactics"]
    assert "T1059" in doc["relevantTechniques"]


def test_workbook_panel_json():
    plan = formats.resolve("sentinel", "workbook_panel")
    out = formats.apply(plan, BODY, _ctx("workbook_panel"))
    doc = json.loads(out)
    assert doc["type"] == 3
    assert doc["content"]["query"] == BODY
    assert doc["content"]["title"] == "Encoded PowerShell"


def test_kql_is_passthrough():
    plan = formats.resolve("sentinel", "kql")
    assert plan.backend_format == "kql"
    assert plan.formatter is None
