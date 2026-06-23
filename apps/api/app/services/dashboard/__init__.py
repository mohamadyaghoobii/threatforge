"""Dashboard generator — builds importable SIEM dashboards from a scope of
use cases / techniques / tactics, reusing the Generator V2 engine for the
per-panel queries. See docs/design/03-dashboard-generator.md."""

from app.services.dashboard import service  # noqa: F401
