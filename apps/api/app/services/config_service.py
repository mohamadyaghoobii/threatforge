from pathlib import Path
import yaml
from app.core.settings import get_settings


def load_yaml_config(relative_path: str) -> dict:
    settings = get_settings()
    path = settings.config_path / relative_path
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def list_yaml_files(path: Path) -> list[Path]:
    return sorted([item for item in path.rglob("*") if item.suffix.lower() in {".yml", ".yaml"}])
