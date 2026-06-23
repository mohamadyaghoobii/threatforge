from typing import Any
from pydantic import BaseModel, Field


class ParsedRule(BaseModel):
    title: str = "Untitled rule"
    rule_id: str | None = None
    status: str | None = None
    description: str | None = None
    author: str | None = None
    date: str | None = None
    modified: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    falsepositives: list[str] = Field(default_factory=list)
    level: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class MitreMapping(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    raw_tags: list[str] = Field(default_factory=list)


class NormalizedRule(BaseModel):
    title: str
    external_rule_id: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    platform: str | None = None
    product: str | None = None
    service: str | None = None
    category: str | None = None
    tags: list[str] = Field(default_factory=list)
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    quality_score: int = 0
