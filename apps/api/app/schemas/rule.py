from datetime import datetime
from typing import Any
from pydantic import BaseModel


class RepositoryOut(BaseModel):
    id: int | None = None
    name: str
    url: str
    branch: str
    type: str
    license: str | None = None
    enabled: bool = True
    last_commit_hash: str | None = None
    last_sync_status: str | None = None
    last_sync_error: str | None = None

    model_config = {"from_attributes": True}


class SyncResult(BaseModel):
    repository: str
    status: str
    commit_hash: str | None = None
    error: str | None = None


class ImportResult(BaseModel):
    repositories: int
    files_seen: int
    raw_rules_created: int
    normalized_created: int
    parse_errors: int


class RuleListItem(BaseModel):
    id: int
    title: str
    severity: str | None = None
    product: str | None = None
    service: str | None = None
    category: str | None = None
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    source_repo: str
    quality_score: int


class RuleDetail(BaseModel):
    id: int
    raw_rule_id: int
    title: str
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    product: str | None = None
    service: str | None = None
    category: str | None = None
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    quality_score: int
    normalized_json: dict
    raw_yaml: str
    source_repo: str
    source_path: str
    license: str | None = None


class ConvertRequest(BaseModel):
    rule_id: int
    target: str = "splunk"
    profile: str | None = "default_splunk_windows"
    output_format: str = "default"


class ConvertResponse(BaseModel):
    rule_id: int
    target: str
    profile: str | None = None
    output_format: str
    query: str
    status: str
    warnings: list[str]
    error: str | None = None
    created_at: datetime | None = None


class MitreTechniqueOut(BaseModel):
    technique_id: str
    rule_count: int


class MitreTacticOut(BaseModel):
    tactic: str
    rule_count: int


class TargetProfileOut(BaseModel):
    id: str
    name: str


class TargetOut(BaseModel):
    id: str
    name: str
    support_level: str
    profiles: list[TargetProfileOut]
    formats: list[str]


class UseCaseOut(BaseModel):
    id: str
    technique_id: str | None = None
    name: str
    tactics: list[str]
    platforms: list[str]
    products: list[str]
    categories: list[str]
    sources: list[str]
    severities: dict[str, int]
    rule_count: int
    best_rule_id: int | None = None
    best_rule_title: str | None = None
    best_quality_score: int
    target_support: list[str]


class FilterOptionsOut(BaseModel):
    tactics: list[str]
    techniques: list[str]
    products: list[str]
    services: list[str]
    categories: list[str]
    severities: list[str]
    sources: list[str]
