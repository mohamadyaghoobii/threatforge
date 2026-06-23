"""Live threat-intel collectors.

Each collector is config-driven, uses a short timeout, and returns an
empty list on any failure (network, auth, parse) so a refresh never
raises — the seed data remains and partial results still ingest.
"""
