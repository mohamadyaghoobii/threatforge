"""sigma-cli subprocess backend.

Returns ``(query, warnings)`` on success or ``(None, warnings)`` if the
binary is missing or the conversion fails. The caller should fall back
to another backend on failure.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from app.core.settings import get_settings
from app.services.generator.warnings import GeneratorWarning, emit


def is_available() -> bool:
    return shutil.which(get_settings().sigma_cli_bin) is not None


def convert(
    raw_yaml: str,
    target: str,
    *,
    profile: str | None,
    output_format: str,
) -> tuple[str | None, list[GeneratorWarning]]:
    settings = get_settings()
    binary = shutil.which(settings.sigma_cli_bin)
    if not binary:
        return None, [
            emit(
                "BACKEND_UNAVAILABLE",
                message=f"sigma-cli binary {settings.sigma_cli_bin!r} not found on PATH",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        ]
    with tempfile.TemporaryDirectory() as tmpdir:
        rule_path = Path(tmpdir) / "rule.yml"
        rule_path.write_text(raw_yaml, encoding="utf-8")
        command = [binary, "convert", "-t", target]
        if output_format and output_format != "default":
            command.extend(["-f", output_format])
        command.append(str(rule_path))
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None, [
                emit(
                    "BACKEND_UNAVAILABLE",
                    message=f"sigma-cli invocation failed: {exc}",
                    target=target,
                    profile=profile,
                    output_format=output_format,
                )
            ]
        if result.returncode != 0:
            err = (result.stderr or result.stdout or "").strip()
            return None, [
                emit(
                    "BACKEND_UNAVAILABLE",
                    message=f"sigma-cli returned non-zero: {err[:500]}",
                    target=target,
                    profile=profile,
                    output_format=output_format,
                )
            ]
        return result.stdout.strip(), []
