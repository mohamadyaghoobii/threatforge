"""Persisted generated dashboards."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class Dashboard(Base):
    __tablename__ = "dashboards"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    target: Mapped[str] = mapped_column(String(64), index=True)
    layout: Mapped[str] = mapped_column(String(64))
    profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output_format: Mapped[str] = mapped_column(String(64))
    scope_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    panel_count: Mapped[int] = mapped_column(Integer, default=0)
    artifact_text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
