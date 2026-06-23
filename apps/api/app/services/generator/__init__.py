"""MetaSec Security Center Generator V2.

Comprehensive query generator that turns normalized detection rules into
SIEM-native artifacts (queries + schedules + metadata) across many targets,
profiles, and output formats.

Public entry points:

- ``engine.convert``           — single rule -> structured result
- ``engine.convert_bulk``      — many rules x many (target, profile, format)
- ``profiles.list_profiles``   — discover profiles loaded from configs
- ``targets.target_catalog``   — full target/profile/format catalog
- ``warnings.WARNING_CODES``   — structured warning code catalog

See ``docs/design/05-generator-v2.md`` for the full spec.
"""

from app.services.generator import engine, profiles, targets, warnings  # noqa: F401
