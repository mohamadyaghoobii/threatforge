"""Atomic Red Team 'bible' — condensed atomic tests per ATT&CK technique."""

from sqlalchemy import Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AtomicTest(Base):
    """One condensed Atomic Red Team test, linked to an ATT&CK technique."""

    __tablename__ = "atomic_tests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    technique_id: Mapped[str] = mapped_column(String(24), index=True)
    technique_name: Mapped[str] = mapped_column(Text)
    tactics: Mapped[str | None] = mapped_column(Text, nullable=True)  # json list
    test_name: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    platforms: Mapped[str | None] = mapped_column(Text, nullable=True)  # json list
    executor: Mapped[str | None] = mapped_column(String(32), nullable=True)
    elevation_required: Mapped[int] = mapped_column(Integer, default=0)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    guid: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
