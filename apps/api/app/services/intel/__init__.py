"""Threat Intelligence module.

A mature, unified replacement for the standalone Ioc-intel,
useragent-intel, and threat-intelligence projects: config-driven
collectors, normalized + scored indicators and User-Agents, seeded with
real feed snapshots, served through /api/intel and the web Threat Intel
section.
"""

from app.services.intel import ingest, scoring, seed, service  # noqa: F401
