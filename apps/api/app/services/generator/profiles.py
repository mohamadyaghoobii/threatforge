"""Profile YAML loader for the generator.

Profiles live under ``configs/generator/profiles/<target>/<id>.yml``.
They are validated against a schema and support ``extends:`` inheritance.

See docs/design/05-generator-v2.md, section "Profile YAML spec".
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from app.core.settings import get_settings


class ProfileBase(BaseModel):
    index: str | None = None
    sourcetype: str | None = None
    table: str | None = None
    default_filter: str | None = None


class ProfileOutputDefaults(BaseModel):
    cron_schedule: str | None = None
    earliest_time: str | None = None
    latest_time: str | None = None
    leading_filter: str | None = None
    suppression: dict[str, Any] | None = None
    notable: dict[str, Any] | None = None
    rba: dict[str, Any] | None = None
    severity_map: dict[str, Any] | None = None
    entity_mappings: list[dict[str, Any]] | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ProfileDefinition(BaseModel):
    id: str
    target: str
    name: str
    description: str | None = None
    audience: str | None = None
    extends: str | None = None
    base: ProfileBase = Field(default_factory=ProfileBase)
    default_event_code_by_category: dict[str, int] = Field(default_factory=dict)
    field_mapping_pack: str | None = None
    pysigma_pipeline: str | None = None
    processing: list[str] = Field(default_factory=list)
    output_formats: list[str] = Field(default_factory=list)
    output_defaults: dict[str, ProfileOutputDefaults] = Field(default_factory=dict)
    severity_map: dict[str, Any] = Field(default_factory=dict)
    entity_inference: dict[str, str] = Field(default_factory=dict)
    mitre_metadata_strategy: str | None = None

    model_config = {"extra": "allow"}


def _profiles_root() -> Path:
    return get_settings().config_path / "generator" / "profiles"


def _field_maps_root() -> Path:
    return get_settings().config_path / "generator" / "field_mappings"


def _walk_yaml(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(p for p in root.rglob("*") if p.suffix.lower() in {".yml", ".yaml"})


def _read_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _merge_inherited(child: dict[str, Any], parent: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(parent)
    for key, value in child.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_inherited(value, merged[key])
        else:
            merged[key] = value
    return merged


@lru_cache(maxsize=1)
def _load_raw_profiles() -> dict[str, dict[str, Any]]:
    raw: dict[str, dict[str, Any]] = {}
    for path in _walk_yaml(_profiles_root()):
        data = _read_yaml(path)
        if not data or "id" not in data:
            continue
        data["_source_path"] = str(path)
        raw[data["id"]] = data
    return raw


def _resolve_inheritance(profile_id: str, raw: dict[str, dict[str, Any]], visited: set[str] | None = None) -> dict[str, Any]:
    visited = visited or set()
    if profile_id in visited:
        raise ValueError(f"Circular profile inheritance detected at {profile_id}")
    visited.add(profile_id)
    data = deepcopy(raw[profile_id])
    parent_id = data.get("extends")
    if not parent_id:
        return data
    if parent_id not in raw:
        raise ValueError(f"Profile {profile_id!r} extends unknown profile {parent_id!r}")
    parent = _resolve_inheritance(parent_id, raw, visited)
    return _merge_inherited(data, parent)


def list_profiles(target: str | None = None) -> list[ProfileDefinition]:
    raw = _load_raw_profiles()
    out: list[ProfileDefinition] = []
    for profile_id in raw:
        try:
            resolved = _resolve_inheritance(profile_id, raw)
            resolved.pop("extends", None)
            resolved.pop("_source_path", None)
            profile = ProfileDefinition(**resolved)
        except (ValidationError, ValueError):
            continue
        if target and profile.target != target:
            continue
        out.append(profile)
    out.sort(key=lambda p: (p.target, p.id))
    return out


def get_profile(profile_id: str) -> ProfileDefinition | None:
    raw = _load_raw_profiles()
    if profile_id not in raw:
        return None
    resolved = _resolve_inheritance(profile_id, raw)
    resolved.pop("extends", None)
    resolved.pop("_source_path", None)
    try:
        return ProfileDefinition(**resolved)
    except ValidationError:
        return None


@lru_cache(maxsize=64)
def load_field_mapping_pack(pack_id: str | None) -> dict[str, str]:
    """Load a field-mapping pack (Sigma field -> SIEM field) by id.

    Returns an empty dict if the pack is missing so callers can merge it
    over target defaults without special-casing.
    """
    if not pack_id:
        return {}
    root = _field_maps_root()
    if not root.exists():
        return {}
    for path in _walk_yaml(root):
        data = _read_yaml(path)
        if data.get("id") == pack_id:
            mappings = data.get("mappings") or {}
            return {str(k): str(v) for k, v in mappings.items()}
    return {}


def profile_field_overrides(profile_id: str | None) -> dict[str, str]:
    """Resolve the field-mapping overrides for a profile, if any."""
    if not profile_id:
        return {}
    pdef = get_profile(profile_id)
    if not pdef or not pdef.field_mapping_pack:
        return {}
    return load_field_mapping_pack(pdef.field_mapping_pack)


def profile_base_selector(profile_id: str | None, target: str) -> str | None:
    """Resolve a profile's leading base selector (Splunk index/sourcetype etc.).

    Shared by the builtin compiler and the pySigma runtime so both prepend
    the same environment-specific base when a profile is chosen.
    """
    if not profile_id:
        return None
    pdef = get_profile(profile_id)
    if not pdef:
        return None
    fmt_defaults = pdef.output_defaults.get("spl") or pdef.output_defaults.get("default")
    if fmt_defaults and fmt_defaults.leading_filter:
        return fmt_defaults.leading_filter
    if pdef.base.index:
        parts = [f"index={pdef.base.index}"]
        if pdef.base.sourcetype:
            parts.append(f"sourcetype={pdef.base.sourcetype}")
        return " ".join(parts)
    if pdef.base.table:
        return pdef.base.table
    return None


def refresh_cache() -> None:
    _load_raw_profiles.cache_clear()
    load_field_mapping_pack.cache_clear()
