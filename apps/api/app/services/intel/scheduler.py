"""Background auto-update scheduler for the Threat Intel module.

A single daemon thread refreshes feeds and ages indicators every
``intel_auto_refresh_minutes``. The first run is delayed by one full
interval so application startup never blocks on the network. Idempotent:
``start()`` is a no-op if already running (safe across test clients).
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.settings import get_settings

_lock = threading.Lock()
_thread: threading.Thread | None = None
_stop = threading.Event()
_state: dict[str, Any] = {
    "enabled": False,
    "interval_minutes": 0,
    "runs": 0,
    "last_run": None,
    "last_result": None,
    "next_run": None,
}


def status() -> dict[str, Any]:
    return dict(_state)


def _run_once() -> None:
    from app.db.session import SessionLocal
    from app.services.intel import service

    db = SessionLocal()
    try:
        result = service.refresh(db)
        _state["runs"] += 1
        _state["last_run"] = datetime.now(timezone.utc).isoformat()
        _state["last_result"] = {
            "sources": result.get("sources", []),
            "aged_out": result.get("aged_out", 0),
        }
    except Exception as exc:  # never let the loop die
        _state["last_result"] = {"error": str(exc)[:300]}
    finally:
        db.close()


def _loop(interval_minutes: int) -> None:
    interval = max(1, interval_minutes) * 60
    while not _stop.is_set():
        _state["next_run"] = (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat()
        # Wait the interval first (delayed first run) but stay responsive to stop.
        if _stop.wait(interval):
            break
        _run_once()


def start() -> bool:
    global _thread
    settings = get_settings()
    minutes = settings.intel_auto_refresh_minutes
    if minutes <= 0:
        _state.update({"enabled": False, "interval_minutes": 0})
        return False
    with _lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _state.update({"enabled": True, "interval_minutes": minutes})
        _thread = threading.Thread(target=_loop, args=(minutes,), name="tf-intel-scheduler", daemon=True)
        _thread.start()
        return True


def stop() -> None:
    _stop.set()
    _state["enabled"] = False


def run_now() -> dict[str, Any]:
    """Trigger a refresh immediately (manual), independent of the loop."""
    _run_once()
    return _state.get("last_result") or {}
