"""Schemas for the dashboard generator endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DashboardScope(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    use_case_ids: list[str] = Field(default_factory=list)
    rule_ids: list[int] = Field(default_factory=list)
    severity: str | None = None


class DashboardGenerateRequest(BaseModel):
    name: str = "MetaSec Security Dashboard"
    target: str = "splunk"
    layout: str = "kill_chain"
    profile: str | None = None
    scope: DashboardScope = Field(default_factory=DashboardScope)
    earliest: str = "-24h"
    latest: str = "now"
    save: bool = False


class DashboardPanelOut(BaseModel):
    title: str
    technique: str | None = None
    tactic: str | None = None
    severity: str | None = None
    viz: str
    backend: str | None = None


class DashboardGenerateResponse(BaseModel):
    id: int | None = None
    name: str
    target: str
    layout: str
    format: str
    content_type: str
    filename: str
    panel_count: int
    artifact: str
    panels: list[DashboardPanelOut] = Field(default_factory=list)


class DashboardSummaryOut(BaseModel):
    id: int
    name: str
    target: str
    layout: str
    output_format: str
    panel_count: int
    created_at: datetime | None = None


class DashboardDetailOut(DashboardSummaryOut):
    profile: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    artifact: str


class DashboardCatalogOut(BaseModel):
    targets: list[str]
    layouts: list[str]
