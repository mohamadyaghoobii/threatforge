"""Threat-intelligence models: unified indicators (IOCs) and User-Agents."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Indicator(Base):
    """A normalized, de-duplicated IOC (ip / domain / url / hash)."""

    __tablename__ = "intel_indicators"
    __table_args__ = (UniqueConstraint("ioc_type", "normalized", name="uq_indicator_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ioc_type: Mapped[str] = mapped_column(String(16), index=True)  # ip | domain | url | hash
    value: Mapped[str] = mapped_column(Text)
    normalized: Mapped[str] = mapped_column(Text, index=True)
    threat_score: Mapped[int] = mapped_column(Integer, default=50, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    category: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    tags_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    sources_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    is_active: Mapped[int] = mapped_column(Integer, default=1, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserAgentIntel(Base):
    """A suspicious / malicious HTTP User-Agent observed across sources."""

    __tablename__ = "intel_user_agents"
    __table_args__ = (UniqueConstraint("ua_hash", name="uq_ua_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ua_hash: Mapped[str] = mapped_column(String(64), index=True)
    user_agent: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    category: Mapped[str] = mapped_column(String(64), default="Suspicious", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    sources_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IntelRun(Base):
    """Records each ingest run for source health / freshness display."""

    __tablename__ = "intel_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # ioc | useragent | seed
    source: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    items: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    finished_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
