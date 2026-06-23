from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    url: Mapped[str] = mapped_column(Text)
    branch: Mapped[str] = mapped_column(String(255), default="main")
    type: Mapped[str] = mapped_column(String(64), default="sigma")
    license: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    local_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_commit_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    raw_rules: Mapped[list["RawRule"]] = relationship(back_populates="repository")


class RepositorySyncRun(Base):
    __tablename__ = "repository_sync_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"))
    status: Mapped[str] = mapped_column(String(64))
    commit_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RawRule(Base):
    __tablename__ = "raw_rules"
    __table_args__ = (UniqueConstraint("repository_id", "source_path", "raw_hash", name="uq_raw_rule_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id"), index=True)
    source_path: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_yaml: Mapped[str] = mapped_column(Text)
    raw_hash: Mapped[str] = mapped_column(String(128), index=True)
    license: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    repository: Mapped[Repository] = relationship(back_populates="raw_rules")
    normalized_rule: Mapped["NormalizedRule"] = relationship(back_populates="raw_rule", uselist=False)


class NormalizedRule(Base):
    __tablename__ = "normalized_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    raw_rule_id: Mapped[int] = mapped_column(ForeignKey("raw_rules.id"), unique=True, index=True)
    external_rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    product: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    normalized_json: Mapped[str] = mapped_column(Text)
    mitre_tactics: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitre_techniques: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    quality_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    raw_rule: Mapped[RawRule] = relationship(back_populates="normalized_rule")
    converted_queries: Mapped[list["ConvertedQuery"]] = relationship(back_populates="normalized_rule")


class ConvertedQuery(Base):
    __tablename__ = "converted_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    normalized_rule_id: Mapped[int] = mapped_column(ForeignKey("normalized_rules.id"), index=True)
    target_siem: Mapped[str] = mapped_column(String(64), index=True)
    profile: Mapped[str | None] = mapped_column(String(255), nullable=True)
    output_format: Mapped[str] = mapped_column(String(64), default="default")
    query_text: Mapped[str] = mapped_column(Text)
    conversion_status: Mapped[str] = mapped_column(String(64), default="success")
    conversion_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    warnings: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    normalized_rule: Mapped[NormalizedRule] = relationship(back_populates="converted_queries")
