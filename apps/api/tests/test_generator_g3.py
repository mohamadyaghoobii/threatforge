"""G3 acceptance tests: in-process pySigma backend + fallback chain."""

from __future__ import annotations

import pytest

from app.services.generator.backends import pysigma_runtime

PYSIGMA_AVAILABLE = pysigma_runtime.supports("splunk", "spl")

RULE = """
title: Encoded PowerShell
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: \\powershell.exe
    CommandLine|contains: ' -enc '
  condition: selection
level: high
"""


def test_registry_declares_core_targets():
    assert "splunk" in pysigma_runtime._REGISTRY
    assert "sentinel" in pysigma_runtime._REGISTRY
    assert "elastic" in pysigma_runtime._REGISTRY
    assert "opensearch" in pysigma_runtime._REGISTRY


def test_unknown_target_returns_none_with_warning():
    query, warnings = pysigma_runtime.convert(RULE, "nonexistent", profile=None, output_format="default")
    assert query is None
    assert any(w.code == "BACKEND_UNAVAILABLE" for w in warnings)


def test_elastic_kql_not_handled_by_pysigma():
    # KQL is intentionally left to the builtin compiler (pySigma emits Lucene).
    assert pysigma_runtime.supports("elastic", "kql") is False


@pytest.mark.skipif(not PYSIGMA_AVAILABLE, reason="pySigma splunk backend not installed")
def test_pysigma_splunk_default_query():
    query, warnings = pysigma_runtime.convert(RULE, "splunk", profile=None, output_format="spl")
    assert query
    assert "powershell.exe" in query
    assert "-enc" in query


@pytest.mark.skipif(not PYSIGMA_AVAILABLE, reason="pySigma splunk backend not installed")
def test_pysigma_splunk_prepends_profile_base():
    from app.services.generator import profiles

    profiles.refresh_cache()
    query, _ = pysigma_runtime.convert(RULE, "splunk", profile="splunk_sysmon", output_format="spl")
    assert query
    assert query.lstrip().lower().startswith("index=")


@pytest.mark.skipif(not PYSIGMA_AVAILABLE, reason="pySigma splunk backend not installed")
def test_pysigma_splunk_savedsearches():
    query, _ = pysigma_runtime.convert(RULE, "splunk", profile="splunk_sysmon", output_format="savedsearches_conf")
    assert query
    assert "search =" in query or "[" in query


@pytest.mark.skipif(
    not pysigma_runtime.supports("sentinel", "kql"),
    reason="pySigma kusto backend not installed",
)
def test_pysigma_sentinel_kql():
    query, _ = pysigma_runtime.convert(RULE, "sentinel", profile=None, output_format="kql")
    assert query


@pytest.mark.skipif(
    not pysigma_runtime.supports("elastic", "lucene"),
    reason="pySigma elasticsearch backend not installed",
)
def test_pysigma_elastic_lucene():
    query, _ = pysigma_runtime.convert(RULE, "elastic", profile=None, output_format="lucene")
    assert query


def test_engine_chain_prefers_pysigma_when_available(monkeypatch, tmp_path):
    """engine._attempt_chain should report backend='pysigma' when available,
    else 'builtin' — both must yield a query."""
    from app.services.generator import engine

    query, warnings, backend = engine._attempt_chain(RULE, "splunk", "splunk_sysmon", "spl")
    assert query
    if PYSIGMA_AVAILABLE:
        assert backend == "pysigma"
    else:
        assert backend == "builtin"


def test_engine_builtin_mode_forces_builtin(monkeypatch):
    from app.core.settings import get_settings
    from app.services.generator import engine

    get_settings.cache_clear()
    monkeypatch.setenv("GENERATOR_BACKEND", "builtin")
    get_settings.cache_clear()
    try:
        query, warnings, backend = engine._attempt_chain(RULE, "splunk", "splunk_sysmon", "spl")
        assert query
        assert backend == "builtin"
    finally:
        monkeypatch.delenv("GENERATOR_BACKEND", raising=False)
        get_settings.cache_clear()


def test_available_targets_reports_installed():
    available = pysigma_runtime.available_targets()
    # Whatever is installed, the structure must be target -> list[str].
    assert isinstance(available, dict)
    for tgt, fmts in available.items():
        assert isinstance(fmts, list)
