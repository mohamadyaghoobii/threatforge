"""G9 acceptance tests: cache + bulk jobs."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.get("/api/repositories")
        c.post("/api/rules/import")
        yield c


def _a_rule_id(client) -> int:
    rules = client.get("/api/rules?limit=5").json()
    assert rules, "no rules imported"
    return rules[0]["id"]


def test_cache_hit_on_second_convert(client):
    client.delete("/api/generator/cache")
    rid = _a_rule_id(client)
    body = {"rule_id": rid, "target": "splunk", "profile": "splunk_sysmon", "output_format": "spl", "persist": False}
    first = client.post("/api/generator/convert", json=body).json()
    assert first["status"] == "success"
    assert first.get("metadata", {}).get("cache") != "hit"
    second = client.post("/api/generator/convert", json=body).json()
    assert second["status"] == "success"
    assert second["metadata"]["cache"] == "hit"
    assert second["query"] == first["query"]


def test_cache_stats_and_clear(client):
    client.delete("/api/generator/cache")
    rid = _a_rule_id(client)
    client.post("/api/generator/convert", json={"rule_id": rid, "target": "elastic", "output_format": "lucene", "persist": False})
    stats = client.get("/api/generator/cache-stats").json()
    assert stats["enabled"] is True
    assert stats["entries"] >= 1
    cleared = client.delete("/api/generator/cache").json()
    assert cleared["invalidated"] >= 1
    stats2 = client.get("/api/generator/cache-stats").json()
    assert stats2["entries"] == 0


def test_cache_key_separates_formats(client):
    client.delete("/api/generator/cache")
    rid = _a_rule_id(client)
    client.post("/api/generator/convert", json={"rule_id": rid, "target": "splunk", "profile": "splunk_sysmon", "output_format": "spl", "persist": False})
    client.post("/api/generator/convert", json={"rule_id": rid, "target": "splunk", "profile": "splunk_sysmon", "output_format": "savedsearches_conf", "persist": False})
    stats = client.get("/api/generator/cache-stats").json()
    assert stats["entries"] >= 2  # different output_format => different key


def test_bulk_job_runs_to_completion(client):
    rid = _a_rule_id(client)
    items = [
        {"rule_id": rid, "target": "splunk", "profile": "splunk_sysmon", "output_format": "spl"},
        {"rule_id": rid, "target": "sentinel", "output_format": "kql"},
        {"rule_id": rid, "target": "elastic", "output_format": "lucene"},
    ]
    submit = client.post("/api/generator/jobs", json={"items": items, "persist": False}).json()
    job_id = submit["job_id"]
    assert submit["total"] == 3

    # Poll until done (background thread).
    status = None
    for _ in range(50):
        status = client.get(f"/api/generator/jobs/{job_id}").json()
        if status["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert status["status"] == "completed"
    assert status["completed"] == 3
    assert status["succeeded"] == 3
    assert len(status["results"]) == 3
    assert all(r["status"] == "success" for r in status["results"])


def test_bulk_job_handles_bad_rule_id(client):
    items = [{"rule_id": 999999, "target": "splunk", "output_format": "spl"}]
    submit = client.post("/api/generator/jobs", json={"items": items, "persist": False}).json()
    job_id = submit["job_id"]
    status = None
    for _ in range(50):
        status = client.get(f"/api/generator/jobs/{job_id}").json()
        if status["status"] == "completed":
            break
        time.sleep(0.1)
    assert status["status"] == "completed"
    assert status["failed"] == 1


def test_job_list_and_404(client):
    jobs = client.get("/api/generator/jobs").json()
    assert isinstance(jobs, list)
    assert client.get("/api/generator/jobs/99999999").status_code == 404
