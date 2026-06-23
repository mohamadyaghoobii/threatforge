"""Recon scan persistence."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ReconScan(Base):
    __tablename__ = "recon_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    final_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    grade: Mapped[str] = mapped_column(String(2), default="F", index=True)
    technologies: Mapped[str | None] = mapped_column(Text, nullable=True)
    cms: Mapped[str | None] = mapped_column(Text, nullable=True)
    cdn: Mapped[str | None] = mapped_column(Text, nullable=True)
    secrets_count: Mapped[int] = mapped_column(Integer, default=0)
    subdomains_count: Mapped[int] = mapped_column(Integer, default=0)
    rendered: Mapped[int] = mapped_column(Integer, default=0)
    report_json: Mapped[str] = mapped_column(Text)
    screenshot_b64: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
