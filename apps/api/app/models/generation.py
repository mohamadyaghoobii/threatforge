"""Models for bulk generation jobs and the conversion cache (G9)."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class GenerationJob(Base):
    __tablename__ = "generation_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    kind: Mapped[str] = mapped_column(String(64), default="convert_bulk")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    total: Mapped[int] = mapped_column(Integer, default=0)
    completed: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    request_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ConversionCache(Base):
    __tablename__ = "conversion_cache"
    __table_args__ = (UniqueConstraint("cache_key", name="uq_conversion_cache_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cache_key: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[int] = mapped_column(Integer, index=True)
    target: Mapped[str] = mapped_column(String(64), index=True)
    profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output_format: Mapped[str] = mapped_column(String(64))
    generator_version: Mapped[str] = mapped_column(String(32))
    backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    query_text: Mapped[str] = mapped_column(Text)
    warnings_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
