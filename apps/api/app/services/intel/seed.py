"""Load bundled seed feeds so the Threat Intel section is populated offline.

Seeds ship in data/intel/ (real URLhaus IOC snapshot + suspicious
User-Agent corpus) and are loaded once if the tables are empty.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.models.intel import Indicator, UserAgentIntel
from app.services.intel import ingest


def _seed_dir() -> Path:
    return get_settings().data_path / "intel"


def load_seed(db: Session, force: bool = False) -> dict[str, int]:
    result = {"indicators": 0, "user_agents": 0}
    seed_dir = _seed_dir()

    ioc_path = seed_dir / "seed_iocs.json"
    if ioc_path.exists() and (force or db.query(Indicator).count() == 0):
        data = json.loads(ioc_path.read_text(encoding="utf-8"))
        items = data.get("items", data) if isinstance(data, dict) else data
        result["indicators"] = ingest.ingest_indicators(db, items, source="seed")["created"]

    ua_path = seed_dir / "seed_useragents.json"
    if ua_path.exists() and (force or db.query(UserAgentIntel).count() == 0):
        data = json.loads(ua_path.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else data.get("items", [])
        result["user_agents"] = ingest.ingest_user_agents(db, items, source="seed")["created"]

    return result
