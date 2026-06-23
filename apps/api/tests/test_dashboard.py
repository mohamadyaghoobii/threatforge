"""Dashboard generator tests."""

from __future__ import annotations

import json
import xml.dom.minidom as minidom

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.get("/api/repositories")
        c.post("/api/rules/import")
        yield c


def _scope_for(client) -> dict:
    # Use a tactic that exists in the imported corpus.
    tactics = client.get("/api/mitre/tactics").json()
    top = max(tactics, key=lambda t: t["rule_count"])["tactic"] if tactics else "Execution"
    return {"tactics": [top]}


def test_catalog(client):
    cat = client.get("/api/dashboards/catalog").json()
    assert "splunk" in cat["targets"]
    assert "sentinel" in cat["targets"]
    assert "elastic" in cat["targets"]
    assert "kill_chain" in cat["layouts"]


def test_generate_splunk_xml_is_valid(client):
    body = {
        "name": "Test Splunk Dashboard",
        "target": "splunk",
        "layout": "by_severity",
        "profile": "splunk_sysmon",
        "scope": _scope_for(client),
    }
    r = client.post("/api/dashboards/generate", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["panel_count"] >= 1
    assert data["format"] == "simple_xml"
    # Must be well-formed XML; rich dashboards are <form> (time picker).
    doc = minidom.parseString(data["artifact"])
    assert doc.documentElement.tagName in ("form", "dashboard")
    assert "<panel>" in data["artifact"]
    # Rich output: overview + per-detection single/chart/table panels.
    assert "<single>" in data["artifact"]
    assert "timechart" in data["artifact"]


def test_generate_sentinel_workbook_is_valid_json(client):
    body = {"name": "Test Sentinel WB", "target": "sentinel", "layout": "kill_chain", "scope": _scope_for(client)}
    r = client.post("/api/dashboards/generate", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    wb = json.loads(data["artifact"])
    assert wb["version"] == "Notebook/1.0"
    assert any(item["type"] == 3 for item in wb["items"])  # at least one query tile


def test_generate_elastic_ndjson_is_valid(client):
    body = {"name": "Test Elastic Dash", "target": "elastic", "layout": "grid", "scope": _scope_for(client)}
    r = client.post("/api/dashboards/generate", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    lines = [ln for ln in data["artifact"].splitlines() if ln.strip()]
    assert len(lines) >= 2  # >=1 search + 1 dashboard
    for ln in lines:
        json.loads(ln)  # each line valid JSON
    assert any(json.loads(ln)["type"] == "dashboard" for ln in lines)


def test_unsupported_target_rejected(client):
    r = client.post("/api/dashboards/generate", json={"name": "x", "target": "qradar", "scope": _scope_for(client)})
    assert r.status_code == 400


def test_save_and_list_and_delete(client):
    body = {"name": "Saved Dash", "target": "splunk", "layout": "grid", "profile": "splunk_sysmon", "scope": _scope_for(client), "save": True}
    r = client.post("/api/dashboards/generate", json=body).json()
    did = r["id"]
    assert did is not None
    listing = client.get("/api/dashboards").json()
    assert any(d["id"] == did for d in listing)
    detail = client.get(f"/api/dashboards/{did}").json()
    assert detail["artifact"]
    assert client.delete(f"/api/dashboards/{did}").json()["deleted"] == did
    assert client.get(f"/api/dashboards/{did}").status_code == 404
