"""G7 acceptance tests: QRadar, Chronicle, LogScale, Sumo, Devo, Wazuh formats."""

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


def test_profiles_load_for_all_targets():
    assert {p.id for p in profiles.list_profiles(target="qradar")} >= {"qradar_windows_dsm", "qradar_linux_dsm"}
    assert {p.id for p in profiles.list_profiles(target="chronicle")} >= {"udm_windows", "udm_linux"}
    assert {p.id for p in profiles.list_profiles(target="logscale")} >= {"logscale_falcon", "logscale_sysmon"}
    assert {p.id for p in profiles.list_profiles(target="sumologic")} >= {"cse_windows", "cse_cloud_aws"}
    assert {p.id for p in profiles.list_profiles(target="devo")} >= {"devo_windows", "devo_linux"}
    assert {p.id for p in profiles.list_profiles(target="wazuh")} >= {"wazuh_default", "wazuh_linux"}


def test_format_registry_complete():
    cases = {
        "qradar": ["aql", "custom_rule_xml", "building_block_xml", "ariel_search_json"],
        "chronicle": ["udm_search", "yara_l_rule", "retrohunt"],
        "logscale": ["query", "alert_yaml", "dashboard_widget"],
        "sumologic": ["query", "cse_rule_yaml"],
        "devo": ["linq", "alert_definition_json"],
        "wazuh": ["rule_xml", "detection_rule_ndjson"],
    }
    for target, fmts in cases.items():
        for fmt in fmts:
            assert formats.resolve(target, fmt) is not None, f"{target}/{fmt}"


def _ctx(target: str, output_format: str, profile_id: str) -> FormatContext:
    return FormatContext(
        target=target,
        output_format=output_format,
        title="Encoded PowerShell",
        description="Detects encoded PowerShell",
        severity="high",
        rule_id=9,
        external_rule_id="tf-9",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059.001"],
        profile=profiles.get_profile(profile_id),
        profile_id=profile_id,
    )


def test_qradar_custom_rule_xml():
    plan = formats.resolve("qradar", "custom_rule_xml")
    out = formats.apply(plan, 'SELECT * FROM events WHERE "Command" ILIKE \'%-enc%\'', _ctx("qradar", "custom_rule_xml", "qradar_windows_dsm"))
    assert out.startswith("<rule>")
    assert "<severity>7</severity>" in out
    assert "dispatch_offense" in out
    assert "</rule>" in out


def test_chronicle_yaral():
    plan = formats.resolve("chronicle", "yara_l_rule")
    out = formats.apply(plan, '$e.target.process.command_line = /.*-enc.*/ nocase', _ctx("chronicle", "yara_l_rule", "udm_windows"))
    assert out.startswith("rule ")
    assert "meta:" in out
    assert 'mitre_attack_technique = "T1059.001"' in out
    assert "condition:" in out


def test_logscale_alert_yaml():
    plan = formats.resolve("logscale", "alert_yaml")
    out = formats.apply(plan, '#repo=falcon CommandLine=/-enc/i', _ctx("logscale", "alert_yaml", "logscale_falcon"))
    doc = yaml.safe_load(out)
    assert doc["name"].startswith("MetaSec Security Center -")
    assert doc["throttleField"] == "aid"
    assert "MetaSec Security Center" in doc["labels"]


def test_sumo_cse_rule_yaml():
    plan = formats.resolve("sumologic", "cse_rule_yaml")
    out = formats.apply(plan, 'metadata_deviceEventId = "1"', _ctx("sumologic", "cse_rule_yaml", "cse_windows"))
    doc = yaml.safe_load(out)
    assert doc["enabled"] is True
    assert doc["score"] == 6  # high


def test_devo_alert_json():
    plan = formats.resolve("devo", "alert_definition_json")
    out = formats.apply(plan, 'from box.win', _ctx("devo", "alert_definition_json", "devo_windows"))
    doc = json.loads(out)
    assert doc["priority"] == "HIGH"
    assert "T1059.001" in doc["categories"]


def test_wazuh_rule_xml():
    plan = formats.resolve("wazuh", "rule_xml")
    out = formats.apply(plan, 'process.command_line: "*-enc*"', _ctx("wazuh", "rule_xml", "wazuh_default"))
    assert "<group name=\"metasec,\">" in out
    assert 'level="12"' in out  # high -> 12
    assert "<id>T1059.001</id>" in out
