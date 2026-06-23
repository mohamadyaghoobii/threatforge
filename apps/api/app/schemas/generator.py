"""Pydantic schemas for the Generator V2 endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class WarningOut(BaseModel):
    code: str
    severity: str
    message: str
    field: str | None = None
    target: str | None = None
    profile: str | None = None
    output_format: str | None = None
    suggestion: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class WarningCodeOut(BaseModel):
    code: str
    severity: str
    title: str
    description: str
    suggestion: str | None = None


class FormatOut(BaseModel):
    id: str
    name: str
    description: str
    support_level: str
    content_type: str
    file_extension: str


class ProfileSummaryOut(BaseModel):
    id: str
    name: str
    description: str | None = None
    audience: str | None = None
    field_mapping_pack: str | None = None
    pysigma_pipeline: str | None = None
    output_formats: list[str] = Field(default_factory=list)


class TargetCatalogOut(BaseModel):
    id: str
    name: str
    description: str
    aliases: list[str] = Field(default_factory=list)
    formats: list[FormatOut] = Field(default_factory=list)
    profiles: list[ProfileSummaryOut] = Field(default_factory=list)


class ProfileDetailOut(BaseModel):
    id: str
    target: str
    name: str
    description: str | None = None
    audience: str | None = None
    base: dict[str, Any] = Field(default_factory=dict)
    default_event_code_by_category: dict[str, int] = Field(default_factory=dict)
    field_mapping_pack: str | None = None
    pysigma_pipeline: str | None = None
    processing: list[str] = Field(default_factory=list)
    output_formats: list[str] = Field(default_factory=list)
    output_defaults: dict[str, Any] = Field(default_factory=dict)
    severity_map: dict[str, Any] = Field(default_factory=dict)
    entity_inference: dict[str, str] = Field(default_factory=dict)
    mitre_metadata_strategy: str | None = None


class ConvertRequestV2(BaseModel):
    rule_id: int
    target: str = "splunk"
    profile: str | None = None
    output_format: str = "default"
    persist: bool = True


class ConvertResponseV2(BaseModel):
    rule_id: int
    target: str
    profile: str | None = None
    output_format: str
    query: str
    status: str
    warnings: list[WarningOut] = Field(default_factory=list)
    error: str | None = None
    backend: str | None = None
    created_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BulkConvertItem(BaseModel):
    rule_id: int
    target: str
    profile: str | None = None
    output_format: str = "default"


class BulkConvertRequest(BaseModel):
    items: list[BulkConvertItem]
    persist: bool = False


class BulkConvertResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    results: list[ConvertResponseV2]


class PipelineOut(BaseModel):
    id: str
    target: str
    description: str | None = None
    path: str
    status: str = "static"


class ValidateRequest(BaseModel):
    target: str
    query: str
    mode: str = "offline"


class ValidateResponse(BaseModel):
    ok: bool | None = None
    mode: str
    target: str
    errors: list[str] = Field(default_factory=list)
    warnings: list[WarningOut] = Field(default_factory=list)
    elapsed_ms: int = 0
    note: str | None = None


class ExplainRequest(BaseModel):
    target: str
    query: str
    profile: str | None = None


class ExplainResponse(BaseModel):
    target: str
    profile: str | None = None
    explanation: str
    note: str | None = None


class OptimizeRequest(BaseModel):
    target: str
    query: str


class OptimizeResponse(BaseModel):
    target: str
    original: str
    optimized: str
    changed: bool
    notes: list[str] = Field(default_factory=list)
    note: str | None = None


class RoundTripRequest(BaseModel):
    target: str
    query: str
    rule_id: int | None = None


class RoundTripResponse(BaseModel):
    target: str
    parsed: bool
    semantic_match: bool | None = None
    coverage: float | None = None
    missing_literals: list[str] = Field(default_factory=list)
    note: str | None = None


class CacheStatsOut(BaseModel):
    enabled: bool = False
    hits: int = 0
    misses: int = 0
    entries: int = 0
    bytes: int = 0
    note: str | None = None


class JobSubmitResponse(BaseModel):
    job_id: int
    status: str
    total: int


class JobStatusOut(BaseModel):
    id: int
    kind: str
    status: str
    total: int
    completed: int
    succeeded: int
    failed: int
    error: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class JobResultOut(JobStatusOut):
    results: list[dict[str, Any]] = Field(default_factory=list)
