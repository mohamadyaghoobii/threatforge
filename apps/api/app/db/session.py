from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from app.core.settings import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models.rule import ConvertedQuery, NormalizedRule, RawRule, Repository, RepositorySyncRun  # noqa: F401
    from app.models.generation import ConversionCache, GenerationJob  # noqa: F401
    from app.models.dashboard import Dashboard  # noqa: F401
    from app.models.intel import Indicator, IntelRun, UserAgentIntel  # noqa: F401
    from app.models.atomic import AtomicTest  # noqa: F401
    from app.models.recon import ReconScan  # noqa: F401
    Base.metadata.create_all(bind=engine)
