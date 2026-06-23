"""G11: golden-file tests per (rule, target, profile, format).

Locks the generator's output against regressions. Runs with the builtin
AST compiler (GENERATOR_BACKEND=builtin) so the golden files are
deterministic and independent of the installed pySigma version.

Regenerate goldens after an intentional change:
    UPDATE_GOLDEN=1 python -m pytest tests/test_generator_g11_golden.py
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detectionforge_rule_engine import normalize_rule, parse_rule_yaml

GOLDEN_DIR = Path(__file__).parent / "golden"
RULES_DIR = GOLDEN_DIR / "rules"
EXPECTED_DIR = GOLDEN_DIR / "expected"
UPDATE = os.getenv("UPDATE_GOLDEN") == "1"

# (rule_file_stem, target, profile, output_format)
MATRIX = [
    ("r1_process_creation", "splunk", "splunk_sysmon", "spl"),
    ("r1_process_creation", "splunk", "splunk_sysmon", "savedsearches_conf"),
    ("r1_process_creation", "sentinel", "sentinel_defender_device_process", "kql"),
    ("r1_process_creation", "sentinel", "sentinel_defender_device_process", "analytic_rule_arm"),
    ("r1_process_creation", "elastic", "ecs_windows_sysmon", "kql"),
    ("r1_process_creation", "elastic", "ecs_windows_sysmon", "detection_rule_ndjson"),
    ("r1_process_creation", "qradar", "qradar_windows_dsm", "custom_rule_xml"),
    ("r1_process_creation", "chronicle", "udm_windows", "yara_l_rule"),
    ("r2_powershell_modifiers", "splunk", "splunk_sysmon", "spl"),
    ("r2_powershell_modifiers", "sentinel", "sentinel_defender_device_process", "kql"),
    ("r3_correlation_count", "splunk", "splunk_windows_security", "spl"),
    ("r3_correlation_count", "sentinel", "sentinel_security_event", "kql"),
    ("r4_registry_negation", "splunk", "splunk_sysmon", "spl"),
    ("r4_registry_negation", "elastic", "ecs_windows_sysmon", "kql"),
    ("r5_network_numeric", "splunk", "splunk_sysmon", "spl"),
    ("r5_network_numeric", "qradar", "qradar_windows_dsm", "aql"),
]


@pytest.fixture(scope="module")
def builtin_session(monkeypatch_module):
    """Fresh in-memory DB with the builtin backend forced."""
    from app.core.settings import get_settings
    from app.db.session import Base
    # Importing the model modules registers their tables on Base.metadata
    # before create_all runs.
    import app.models.generation  # noqa: F401
    import app.models.rule  # noqa: F401

    monkeypatch_module.setenv("GENERATOR_BACKEND", "builtin")
    get_settings.cache_clear()

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    yield Session

    get_settings.cache_clear()


@pytest.fixture(scope="module")
def monkeypatch_module():
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()


def _insert_rule(session, yaml_text: str):
    from app.models.rule import NormalizedRule, RawRule, Repository

    parsed = parse_rule_yaml(yaml_text)
    normalized = normalize_rule(parsed)
    import uuid

    db = session()
    try:
        # Unique repo name per insert: the module-scoped in-memory DB is
        # shared across the matrix and Repository.name is unique. The repo
        # name does not appear in any generated artifact, so this does not
        # affect golden output.
        repo = Repository(name=f"golden-{uuid.uuid4().hex[:12]}", url="local://golden", branch="local", type="local_sigma")
        db.add(repo)
        db.flush()
        raw = RawRule(
            repository_id=repo.id,
            source_path=f"{parsed.title}.yml",
            raw_yaml=yaml_text,
            raw_hash=hashlib.sha1(yaml_text.encode()).hexdigest(),
        )
        db.add(raw)
        db.flush()
        nr = NormalizedRule(
            raw_rule_id=raw.id,
            external_rule_id=normalized.external_rule_id,
            title=normalized.title,
            description=normalized.description,
            severity=normalized.severity,
            product=normalized.product,
            service=normalized.service,
            category=normalized.category,
            normalized_json="{}",
            mitre_tactics=json.dumps(normalized.mitre.tactics),
            mitre_techniques=json.dumps(normalized.mitre.techniques),
            quality_score=normalized.quality_score,
        )
        db.add(nr)
        db.commit()
        return db, nr.id
    except Exception:
        db.close()
        raise


@pytest.mark.parametrize("stem,target,profile,fmt", MATRIX)
def test_golden(builtin_session, stem, target, profile, fmt):
    from app.services.generator import cache, engine

    yaml_text = (RULES_DIR / f"{stem}.yml").read_text(encoding="utf-8")
    db, rid = _insert_rule(builtin_session, yaml_text)
    try:
        cache.clear(db)  # ensure builtin path, not a cached pysigma entry
        result = engine.convert(db, rid, target=target, profile=profile, output_format=fmt, persist=False)
        assert result.status == "success", result.error
        assert result.backend == "builtin"
        produced = result.query.replace("\r\n", "\n").strip()
    finally:
        db.close()

    golden_path = EXPECTED_DIR / f"{stem}__{target}__{profile}__{fmt}.txt"
    if UPDATE or not golden_path.exists():
        golden_path.write_text(produced + "\n", encoding="utf-8")
        pytest.skip(f"wrote golden {golden_path.name}")
    expected = golden_path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
    assert produced == expected, f"Golden mismatch for {golden_path.name}"
