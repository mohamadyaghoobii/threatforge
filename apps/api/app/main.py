from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.api.generator_routes import router as generator_router
from app.api.dashboard_routes import router as dashboard_router
from app.api.intel_routes import router as intel_router
from app.api.atomic_routes import router as atomic_router
from app.api.recon_routes import router as recon_router
from app.core.settings import get_settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Populate the Threat Intel + Atomic tables from bundled seed if empty.
    # Failures are logged (not silently swallowed) so deploys are debuggable.
    try:
        from app.db.session import SessionLocal
        from app.services.intel import seed

        db = SessionLocal()
        try:
            seed.load_seed(db)
            from app.services.atomic import service as atomic_service

            atomic_service.load_seed(db)
        finally:
            db.close()
    except Exception as exc:
        print(f"[startup] seed load failed: {exc!r}", flush=True)
    # Start the Threat Intel auto-update scheduler (no-op if disabled).
    try:
        from app.services.intel import scheduler

        scheduler.start()
    except Exception as exc:
        print(f"[startup] intel scheduler failed: {exc!r}", flush=True)
    yield


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
app.include_router(generator_router)
app.include_router(dashboard_router)
app.include_router(intel_router)
app.include_router(atomic_router)
app.include_router(recon_router)


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.app_name, "env": settings.app_env}
