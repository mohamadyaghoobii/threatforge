"""Threat Intel module tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.intel import scoring


# --- pure scoring/normalization --------------------------------------------


def test_guess_type():
    assert scoring.guess_type("8.8.8.8") == "ip"
    assert scoring.guess_type("http://evil.com/x") == "url"
    assert scoring.guess_type("evil[.]com") == "domain"
    assert scoring.guess_type("a" * 64) == "hash"


def test_normalize_domain_defang():
    assert scoring.normalize("domain", "Evil[.]COM") == "evil.com"
    assert scoring.normalize("domain", "https://evil.com/path") == "evil.com"


def test_score_and_severity():
    s = scoring.score(90, "high", True)
    assert s >= 85
    assert scoring.severity_for(s) == "critical"
    low = scoring.score(50, "low", False)
    assert scoring.severity_for(low) in ("low", "medium")


def test_aging():
    assert scoring.is_active("2099-01-01 00:00:00") is True
    assert scoring.is_active("2000-01-01 00:00:00") is False


# --- ingest dedupe (unit, in-memory DB) ------------------------------------


@pytest.fixture()
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.session import Base
    import app.models.intel  # noqa: F401

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_ingest_dedup_merges_sources(db):
    from app.services.intel import ingest

    ingest.ingest_indicators(db, [
        {"ioc": "evil.com", "ioc_type": "domain", "source": "urlhaus", "confidence": "high"},
        {"ioc": "evil.com", "ioc_type": "domain", "source": "threatfox", "confidence": "medium"},
    ], source="test")
    from app.models.intel import Indicator
    rows = db.query(Indicator).all()
    assert len(rows) == 1
    import json
    assert set(json.loads(rows[0].sources_json)) == {"urlhaus", "threatfox"}


# --- API (seeded file DB) ---------------------------------------------------


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:  # lifespan loads the bundled seed
        yield c


def test_stats_populated_from_seed(client):
    s = client.get("/api/intel/stats").json()
    assert s["indicators"] > 100  # URLhaus seed
    assert s["user_agents"] > 100  # UA seed
    assert "by_type" in s and "by_severity" in s


def test_list_iocs_and_filter(client):
    rows = client.get("/api/intel/iocs?limit=10").json()
    assert len(rows) <= 10 and len(rows) > 0
    urls = client.get("/api/intel/iocs?type=url&limit=5").json()
    assert all(r["ioc_type"] == "url" for r in urls)


def test_list_user_agents(client):
    rows = client.get("/api/intel/useragents?limit=10").json()
    assert len(rows) > 0
    assert "user_agent" in rows[0] and "severity" in rows[0]


def test_useragent_tool_filter(client):
    rows = client.get("/api/intel/useragents?tool=sqlmap&limit=50").json()
    assert all(r["tool_name"] == "sqlmap" for r in rows)


def test_export_csv(client):
    r = client.get("/api/intel/iocs/export.csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers["content-type"]
    assert r.text.splitlines()[0].startswith("ioc,type,score")


# --- config-driven feed parsers (no network) -------------------------------


def test_parse_abuse_ip_csv():
    from app.services.intel.collectors import feeds

    body = '"first_seen","dst_ip","dst_port","malware"\n"2026-01-01","1.2.3.4","443","Dridex"\n"2026-01-02","5.6.7.8","8080","Emotet"\n'
    items = feeds.parse_abuse_ip_csv(body, {"id": "feodotracker", "category": "c2", "confidence": "high"})
    ips = {i["ioc"] for i in items}
    assert "1.2.3.4" in ips and "5.6.7.8" in ips
    assert all(i["ioc_type"] == "ip" for i in items)


def test_parse_hash_txt():
    from app.services.intel.collectors import feeds

    body = "# comment\n" + ("a" * 64) + "\n" + ("b" * 32) + "\nnotahash\n"
    items = feeds.parse_hash_txt(body, {"id": "malwarebazaar", "category": "malware"})
    assert len(items) == 2
    assert all(i["ioc_type"] == "hash" for i in items)


def test_ioc_sources_config_loads():
    from app.services.intel import service

    ids = {s["id"] for s in service._ioc_sources()}
    assert {"urlhaus", "threatfox", "feodotracker", "malwarebazaar", "blocklist_de"} <= ids


# --- STIX 2.1 export --------------------------------------------------------


def test_stix_bundle_structure():
    from app.services.intel import stix

    inds = [
        {"ioc": "evil.com", "normalized": "evil.com", "ioc_type": "domain", "threat_score": 90,
         "severity": "critical", "confidence": "high", "category": "malware", "tags": ["x"], "sources": ["urlhaus"]},
        {"ioc": "1.2.3.4", "normalized": "1.2.3.4", "ioc_type": "ip", "threat_score": 80,
         "severity": "high", "confidence": "high", "category": "c2", "tags": [], "sources": ["feodotracker"]},
        {"ioc": "a" * 64, "normalized": "a" * 64, "ioc_type": "hash", "threat_score": 85,
         "severity": "critical", "confidence": "high", "category": "malware", "tags": [], "sources": ["malwarebazaar"]},
    ]
    b = stix.bundle(inds)
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    indicators = [o for o in b["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 3
    patterns = " ".join(o["pattern"] for o in indicators)
    assert "domain-name:value = 'evil.com'" in patterns
    assert "ipv4-addr:value = '1.2.3.4'" in patterns
    assert "file:hashes.'SHA-256'" in patterns
    assert any(o["type"] == "marking-definition" for o in b["objects"])
    assert all(o["spec_version"] == "2.1" for o in indicators)


def test_stix_export_endpoint(client):
    r = client.get("/api/intel/iocs/export.stix?limit=50")
    assert r.status_code == 200
    import json as _json
    bundle = _json.loads(r.text)
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in bundle["objects"])


# --- lookup + aging + scheduler --------------------------------------------


def test_lookup_known_and_unknown(client):
    from urllib.parse import quote

    # Pull a real seeded IP/domain indicator (stable to look up) and verify.
    rows = client.get("/api/intel/iocs?type=ip&limit=1").json() or client.get("/api/intel/iocs?limit=1").json()
    sample = rows[0]
    hit = client.get(f"/api/intel/lookup?value={quote(sample['ioc'], safe='')}").json()
    assert hit["known"] is True
    assert hit["verdict"] == "malicious"
    miss = client.get("/api/intel/lookup?value=this-is-definitely-not-known-12345.example").json()
    assert miss["known"] is False


def test_age_endpoint(client):
    r = client.post("/api/intel/age").json()
    assert "aged_out" in r


def test_scheduler_status(client):
    s = client.get("/api/intel/status").json()
    assert "enabled" in s and "interval_minutes" in s
