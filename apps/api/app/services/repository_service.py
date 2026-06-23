from datetime import datetime
from pathlib import Path
import shutil
import subprocess
from sqlalchemy.orm import Session
from app.core.settings import get_settings
from app.models.rule import Repository, RepositorySyncRun
from app.services.config_service import load_yaml_config


def _resolve_project_path(value: str) -> Path:
    settings = get_settings()
    path = Path(value)
    if path.is_absolute():
        return path
    return (settings.config_path / ".." / value).resolve()


def ensure_repositories_from_config(db: Session) -> list[Repository]:
    config = load_yaml_config("sources/repositories.yml")
    results: list[Repository] = []
    for item in config.get("repositories", []):
        repo = db.query(Repository).filter(Repository.name == item["name"]).first()
        local_path = item.get("local_path")
        resolved_local_path = str(_resolve_project_path(local_path)) if local_path else None
        if not repo:
            repo = Repository(
                name=item["name"],
                url=item["url"],
                branch=item.get("branch") or "main",
                type=item.get("type") or "sigma",
                license=item.get("license"),
                enabled=1 if item.get("enabled", True) else 0,
                local_path=resolved_local_path,
            )
            db.add(repo)
        else:
            repo.url = item["url"]
            repo.branch = item.get("branch") or repo.branch
            repo.type = item.get("type") or repo.type
            repo.license = item.get("license")
            repo.enabled = 1 if item.get("enabled", True) else 0
            if resolved_local_path:
                repo.local_path = resolved_local_path
        results.append(repo)
    db.commit()
    return db.query(Repository).order_by(Repository.name.asc()).all()


def _run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=900)


def _commit_hash(path: Path) -> str | None:
    result = _run(["git", "rev-parse", "HEAD"], cwd=path)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _sync_local_repository(db: Session, repo: Repository, run: RepositorySyncRun) -> tuple[str, str | None, str | None]:
    local_path = Path(repo.local_path or "")
    local_path.mkdir(parents=True, exist_ok=True)
    repo.last_commit_hash = "local"
    repo.last_sync_status = "success"
    repo.last_sync_error = None
    run.status = "success"
    run.commit_hash = "local"
    run.finished_at = datetime.utcnow()
    db.commit()
    return "success", "local", None


def sync_repository(db: Session, repo: Repository) -> tuple[str, str | None, str | None]:
    settings = get_settings()
    repos_dir = settings.data_path / "repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    run = RepositorySyncRun(repository_id=repo.id, status="running")
    db.add(run)
    db.commit()
    try:
        if repo.type.startswith("local") or repo.url.startswith("local://"):
            return _sync_local_repository(db, repo, run)
        local_path = repos_dir / repo.name
        # Disable autocrlf so Windows line-ending rewrites don't dirty the
        # working tree, and enable longpaths so deep rule paths (SigmaHQ)
        # check out on Windows (MAX_PATH 260 limit).
        gc = ["-c", "core.autocrlf=false", "-c", "core.longpaths=true"]
        if (local_path / ".git").exists():
            # Force-align to the remote, discarding any local noise. Best
            # effort: if the update fails, the existing clone is still used.
            fetched = _run(["git", *gc, "fetch", "--depth", "1", "origin", repo.branch], cwd=local_path)
            if fetched.returncode == 0:
                _run(["git", *gc, "reset", "--hard", "FETCH_HEAD"], cwd=local_path)
            else:
                _run(["git", *gc, "reset", "--hard"], cwd=local_path)
            _run(["git", *gc, "clean", "-fd"], cwd=local_path)
        else:
            # A leftover non-git directory (e.g. from a partial clone) would
            # make git refuse to clone. Remove it first.
            if local_path.exists():
                shutil.rmtree(local_path, ignore_errors=True)
            clone = _run(["git", *gc, "clone", "--depth", "1", "--branch", repo.branch, repo.url, str(local_path)])
            if clone.returncode != 0:
                # Retry against the remote default branch (the configured
                # branch may be wrong, e.g. main vs master).
                if local_path.exists():
                    shutil.rmtree(local_path, ignore_errors=True)
                clone = _run(["git", *gc, "clone", "--depth", "1", repo.url, str(local_path)])
                if clone.returncode != 0:
                    raise RuntimeError(clone.stderr.strip() or clone.stdout.strip())
        if not local_path.exists():
            raise RuntimeError(f"Clone directory missing after sync: {local_path}")
        commit = _commit_hash(local_path)
        repo.local_path = str(local_path)
        repo.last_commit_hash = commit
        repo.last_sync_status = "success"
        repo.last_sync_error = None
        run.status = "success"
        run.commit_hash = commit
        run.finished_at = datetime.utcnow()
        db.commit()
        return "success", commit, None
    except Exception as exc:
        error = str(exc)
        repo.last_sync_status = "failed"
        repo.last_sync_error = error
        run.status = "failed"
        run.error = error
        run.finished_at = datetime.utcnow()
        db.commit()
        return "failed", None, error


def sync_enabled_repositories(db: Session) -> list[tuple[Repository, str, str | None, str | None]]:
    ensure_repositories_from_config(db)
    repos = db.query(Repository).filter(Repository.enabled == 1).order_by(Repository.name.asc()).all()
    results = []
    for repo in repos:
        status, commit, error = sync_repository(db, repo)
        results.append((repo, status, commit, error))
    return results
