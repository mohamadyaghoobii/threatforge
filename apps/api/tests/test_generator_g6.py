"""G6 acceptance tests: Elastic + OpenSearch profile packs + detection rule NDJSON."""

from __future__ import annotations

import json

import pytest

from app.services.generator import formats, profiles
from app.services.generator.formats import FormatContext


@pytest.fixture(autouse=True)
def _fresh():
    profiles.refresh_cache()
    yield


def test_elastic_profiles_load():
    ids = {p.id for p in profiles.list_profiles(target="elastic")}
    expected = {
        "ecs_windows_sysmon",
        "ecs_windows_security",
        "ecs_linux_auditbeat",
        "ecs_endpoint_security",
        "ecs_cloud_aws",
        "ecs_network_zeek",
    }
    assert expected <= ids


def test_opensearch_profiles_load():
    ids = {p.id for p in profiles.list_profiles(target="opensearch")}
    assert {"opensearch_ecs", "opensearch_wazuh"} <= ids


def test_elastic_format_registry():
    for fmt in ["kql", "lucene", "eql", "esql", "detection_rule_ndjson"]:
        assert formats.resolve("elastic", fmt) is not None, fmt


def test_opensearch_format_registry():
    for fmt in ["kql", "dsl", "detection_rule_ndjson"]:
        assert formats.resolve("opensearch", fmt) is not None, fmt


def _ctx(target: str, output_format: str) -> FormatContext:
    pid = "ecs_windows_sysmon" if target == "elastic" else "opensearch_ecs"
    return FormatContext(
        target=target,
        output_format=output_format,
        title="Encoded PowerShell",
        description="Detects encoded PowerShell",
        severity="high",
        rule_id=7,
        external_rule_id="tf-7",
        references=["https://attack.mitre.org/techniques/T1059/001/"],
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059.001", "T1059"],
        profile=profiles.get_profile(pid),
        profile_id=pid,
    )


BODY = 'process.name : ("powershell.exe") and process.command_line : "*-enc*"'


def test_elastic_detection_rule_ndjson():
    plan = formats.resolve("elastic", "detection_rule_ndjson")
    assert plan.backend_format == "kql"
    out = formats.apply(plan, BODY, _ctx("elastic", "detection_rule_ndjson"))
    # NDJSON => single line, valid JSON.
    assert "\n" not in out.strip()
    doc = json.loads(out)
    assert doc["type"] == "query"
    assert doc["language"] == "kuery"
    assert doc["query"] == BODY
    assert doc["severity"] == "high"
    assert doc["risk_score"] == 73
    assert "logs-*" in doc["index"]
    # threat mapping with technique + sub-technique
    threat = doc["threat"][0]
    assert threat["tactic"]["id"] == "TA0002"
    tech = threat["technique"][0]
    assert tech["id"] == "T1059"
    assert any(s["id"] == "T1059.001" for s in tech["subtechnique"])


def test_opensearch_detection_rule_lucene_language():
    plan = formats.resolve("opensearch", "detection_rule_ndjson")
    assert plan.backend_format == "lucene"
    out = formats.apply(plan, BODY, _ctx("opensearch", "detection_rule_ndjson"))
    doc = json.loads(out)
    assert doc["language"] == "lucene"


def test_elastic_query_formats_passthrough():
    for fmt in ["kql", "lucene", "eql", "esql"]:
        plan = formats.resolve("elastic", fmt)
        assert plan.formatter is None
