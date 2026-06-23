"""Asynchronous bulk conversion jobs (G9).

A job converts many (rule_id, target, profile, output_format) items in a
background thread, updating its GenerationJob row as it progresses so the
client can poll. Each worker uses its own DB session.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

from app.db.session import SessionLocal
from app.models.generation import GenerationJob
from app.services.generator import engine

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="tf-bulk")


def submit(items: list[dict[str, Any]], persist: bool = False) -> int:
    """Create a job row and dispatch it to the background executor."""
    db = SessionLocal()
    try:
        job = GenerationJob(
            kind="convert_bulk",
            status="pending",
            total=len(items),
            request_json=json.dumps({"items": items, "persist": persist}),
        )
        db.add(job)
        db.commit()
        job_id = job.id
    finally:
        db.close()
    _EXECUTOR.submit(_run_job, job_id, items, persist)
    return job_id


def _run_job(job_id: int, items: list[dict[str, Any]], persist: bool) -> None:
    db = SessionLocal()
    try:
        job = db.get(GenerationJob, job_id)
        if job is None:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        results: list[dict[str, Any]] = []
        succeeded = failed = 0
        for item in items:
            try:
                res = engine.convert(
                    db,
                    int(item["rule_id"]),
                    target=item.get("target", "splunk"),
                    profile=item.get("profile"),
                    output_format=item.get("output_format", "default"),
                    persist=persist,
                )
                if res.status == "success":
                    succeeded += 1
                else:
                    failed += 1
                results.append(
                    {
                        "rule_id": res.rule_id,
                        "target": res.target,
                        "output_format": res.output_format,
                        "status": res.status,
                        "backend": res.backend,
                        "query": res.query,
                        "warning_count": len(res.warnings),
                    }
                )
            except Exception as exc:  # one bad item must not kill the job
                failed += 1
                results.append(
                    {
                        "rule_id": item.get("rule_id"),
                        "target": item.get("target"),
                        "output_format": item.get("output_format"),
                        "status": "error",
                        "error": str(exc),
                    }
                )
            job.completed += 1
            job.succeeded = succeeded
            job.failed = failed
            db.commit()

        job.result_json = json.dumps(results)
        job.status = "completed"
        job.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        try:
            job = db.get(GenerationJob, job_id)
            if job is not None:
                job.status = "failed"
                job.error = str(exc)
                job.finished_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
