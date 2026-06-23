"""Atomic Bible tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # lifespan loads the atomic seed
        yield c


def test_stats(client):
    s = client.get("/api/atomic/stats").json()
    assert s["techniques"] > 100
    assert s["tests"] > 500
    assert isinstance(s["by_platform"], dict)


def test_techniques_list_and_search(client):
    techs = client.get("/api/atomic/techniques?limit=20").json()
    assert len(techs) > 0
    assert "technique_id" in techs[0] and "test_count" in techs[0]
    ps = client.get("/api/atomic/techniques?q=powershell").json()
    assert any("T1059" in t["technique_id"] for t in ps)


def test_tests_for_technique(client):
    tests = client.get("/api/atomic/techniques/T1059.001/tests").json()
    assert len(tests) > 0
    t = tests[0]
    assert t["technique_id"] == "T1059.001"
    assert "command" in t and "executor" in t and "platforms" in t


def test_platform_filter(client):
    techs = client.get("/api/atomic/techniques?platform=windows&limit=50").json()
    assert all("windows" in t["platforms"] for t in techs)


def test_search_tests(client):
    rows = client.get("/api/atomic/tests?q=mimikatz&limit=20").json()
    assert isinstance(rows, list)
    if rows:
        assert "test_name" in rows[0]


def test_descriptions_are_trimmed(client):
    rows = client.get("/api/atomic/tests?limit=200").json()
    # Bible is condensed: descriptions stay short.
    assert all(len(r.get("description") or "") <= 320 for r in rows)


# --- seed loader unit tests (handoff request) ------------------------------


def test_flatten_flat_tests_list():
    from app.services.atomic import service

    data = {"tests": [{"technique_id": "T1059", "test_name": "x", "executor": "powershell", "command": "whoami"}]}
    out = service._flatten_seed_tests(data)
    assert len(out) == 1
    assert out[0]["technique_id"] == "T1059" and out[0]["executor"] == "powershell"


def test_flatten_nested_atomic_tests():
    from app.services.atomic import service

    data = {"techniques": [{
        "attack_technique": "T1003", "display_name": "OS Cred Dumping",
        "atomic_tests": [
            {"name": "dump", "description": "d", "supported_platforms": ["windows"],
             "executor": {"name": "command_prompt", "command": "procdump", "elevation_required": True}},
        ],
    }]}
    out = service._flatten_seed_tests(data)
    assert len(out) == 1
    t = out[0]
    assert t["technique_id"] == "T1003"
    assert t["technique_name"] == "OS Cred Dumping"
    assert t["executor"] == "command_prompt"
    assert t["elevation_required"] is True
    assert t["command"] == "procdump"
    assert t["platforms"] == ["windows"]


def test_real_bible_parses_1804(client):
    # The bundled atomic_bible.json must parse to the expected size.
    s = client.get("/api/atomic/stats").json()
    assert s["tests"] >= 1800
