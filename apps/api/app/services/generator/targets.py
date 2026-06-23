"""Target catalog for the generator.

A *target* is a SIEM (Splunk, Sentinel, Elastic, ...). Each target advertises
its known output formats and the profiles that have been loaded for it.

This is the structured catalog returned by ``GET /api/generator/targets``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detectionforge_rule_engine.converters import normalize_target as legacy_normalize_target

from app.services.generator.profiles import list_profiles


@dataclass
class FormatSpec:
    id: str
    name: str
    description: str
    support_level: str = "fallback"  # fallback | pysigma | sigma_cli | native
    content_type: str = "text/plain"
    file_extension: str = ".txt"


@dataclass
class TargetSpec:
    id: str
    name: str
    description: str
    formats: list[FormatSpec] = field(default_factory=list)
    aliases: tuple[str, ...] = ()


# Static catalog of (target, format) advertised support.
# Profiles live alongside this — each target's profile list comes from YAML.
TARGETS: dict[str, TargetSpec] = {
    "splunk": TargetSpec(
        id="splunk",
        name="Splunk",
        description="Splunk SPL family",
        aliases=(),
        formats=[
            FormatSpec("spl", "Splunk SPL", "Bare SPL search string", file_extension=".spl"),
            FormatSpec("savedsearches_conf", "savedsearches.conf", "Full Splunk savedsearch stanza", content_type="text/plain", file_extension=".conf"),
            FormatSpec("datamodel_tstats", "tstats (CIM)", "tstats search against accelerated CIM datamodel", file_extension=".spl"),
            FormatSpec("ess_notable", "ES notable", "Enterprise Security notable event parameters", file_extension=".conf"),
            FormatSpec("risk_based_alert", "Risk-Based Alert", "RBA-ready savedsearch with risk_object/threat_object", file_extension=".conf"),
            FormatSpec("dashboard_panel", "Dashboard panel", "Splunk Simple XML <panel> fragment", content_type="application/xml", file_extension=".xml"),
        ],
    ),
    "sentinel": TargetSpec(
        id="sentinel",
        name="Microsoft Sentinel",
        description="Microsoft Sentinel / Defender XDR KQL",
        aliases=("kql", "sentinel-kql", "kusto"),
        formats=[
            FormatSpec("kql", "KQL", "Bare KQL", file_extension=".kql"),
            FormatSpec("analytic_rule_arm", "Analytic rule (ARM)", "Microsoft.SecurityInsights/alertRules ARM template", content_type="application/json", file_extension=".json"),
            FormatSpec("hunting_query_yaml", "Hunting query (YAML)", "Sentinel hunting query YAML", file_extension=".yaml"),
            FormatSpec("workbook_panel", "Workbook panel", "Workbook tile JSON", content_type="application/json", file_extension=".json"),
        ],
    ),
    "elastic": TargetSpec(
        id="elastic",
        name="Elastic",
        description="Elastic Security / Kibana KQL family",
        aliases=("elasticsearch", "lucene"),
        formats=[
            FormatSpec("kql", "Kibana Query Language", "KQL", file_extension=".kql"),
            FormatSpec("eql", "Event Query Language", "EQL", file_extension=".eql"),
            FormatSpec("lucene", "Lucene query string", "Lucene", file_extension=".txt"),
            FormatSpec("esql", "ES|QL", "Elastic ES|QL", file_extension=".esql"),
            FormatSpec("detection_rule_ndjson", "Detection rule (NDJSON)", "Kibana Security detection rule line", content_type="application/x-ndjson", file_extension=".ndjson"),
        ],
    ),
    "opensearch": TargetSpec(
        id="opensearch",
        name="OpenSearch",
        description="OpenSearch / Wazuh query family",
        formats=[
            FormatSpec("kql", "OpenSearch KQL", "KQL-style query", file_extension=".kql"),
            FormatSpec("dsl", "OpenSearch DSL", "JSON query DSL", content_type="application/json", file_extension=".json"),
            FormatSpec("detection_rule_ndjson", "Detection rule (NDJSON)", "Detection rule line", content_type="application/x-ndjson", file_extension=".ndjson"),
        ],
    ),
    "qradar": TargetSpec(
        id="qradar",
        name="IBM QRadar",
        description="QRadar AQL + custom rule XML",
        aliases=("aql",),
        formats=[
            FormatSpec("aql", "AQL", "Ariel Query Language", file_extension=".aql"),
            FormatSpec("custom_rule_xml", "Custom rule (XML)", "QRadar custom rule XML", content_type="application/xml", file_extension=".xml"),
            FormatSpec("building_block_xml", "Building block (XML)", "QRadar building block XML", content_type="application/xml", file_extension=".xml"),
            FormatSpec("ariel_search_json", "Ariel search (JSON)", "Saved Ariel search payload", content_type="application/json", file_extension=".json"),
        ],
    ),
    "chronicle": TargetSpec(
        id="chronicle",
        name="Google Chronicle",
        description="Chronicle UDM Search + YARA-L 2.0",
        formats=[
            FormatSpec("udm_search", "UDM Search", "Chronicle UDM Search query", file_extension=".udm"),
            FormatSpec("yara_l_rule", "YARA-L 2.0", "Chronicle YARA-L rule", file_extension=".yaral"),
            FormatSpec("retrohunt", "Retrohunt", "Retrohunt payload", content_type="application/json", file_extension=".json"),
        ],
    ),
    "logscale": TargetSpec(
        id="logscale",
        name="CrowdStrike LogScale",
        description="Falcon LogScale (Humio) query family",
        aliases=("humio", "crowdstrike_logscale"),
        formats=[
            FormatSpec("query", "LogScale query", "Bare LogScale search", file_extension=".lsq"),
            FormatSpec("alert_yaml", "Alert (YAML)", "LogScale alert YAML", file_extension=".yaml"),
            FormatSpec("dashboard_widget", "Dashboard widget", "Dashboard widget JSON", content_type="application/json", file_extension=".json"),
        ],
    ),
    "sumologic": TargetSpec(
        id="sumologic",
        name="Sumo Logic",
        description="Sumo Logic / CSE",
        formats=[
            FormatSpec("query", "Sumo query", "Sumo search query", file_extension=".sumo"),
            FormatSpec("cse_rule_yaml", "CSE rule (YAML)", "Cloud SIEM Enterprise rule", file_extension=".yaml"),
        ],
    ),
    "devo": TargetSpec(
        id="devo",
        name="Devo",
        description="Devo LINQ + alert definitions",
        formats=[
            FormatSpec("linq", "Devo LINQ", "Devo LINQ query", file_extension=".linq"),
            FormatSpec("alert_definition_json", "Alert definition (JSON)", "Devo alert definition JSON", content_type="application/json", file_extension=".json"),
        ],
    ),
    "wazuh": TargetSpec(
        id="wazuh",
        name="Wazuh",
        description="Wazuh rule XML",
        formats=[
            FormatSpec("rule_xml", "Wazuh rule (XML)", "Wazuh rule XML", content_type="application/xml", file_extension=".xml"),
            FormatSpec("detection_rule_ndjson", "Detection rule (NDJSON)", "OpenSearch Security Analytics detection rule", content_type="application/x-ndjson", file_extension=".ndjson"),
        ],
    ),
}


def normalize_target(value: str) -> str:
    """Map an external/alias name to a canonical target id."""
    if not value:
        return value
    clean = value.strip().lower()
    if clean in TARGETS:
        return clean
    for target in TARGETS.values():
        if clean in target.aliases:
            return target.id
    return legacy_normalize_target(clean)


def _format_support_level(target_id: str, fmt_id: str, declared: str) -> str:
    """Upgrade a format's support level to 'pysigma' when a backend exists."""
    try:
        from app.services.generator.backends import pysigma_runtime

        if pysigma_runtime.supports(target_id, fmt_id):
            return "pysigma"
    except Exception:
        pass
    return declared


def list_targets() -> list[dict]:
    """Return the full catalog: target × profiles × formats."""
    out: list[dict] = []
    profiles_by_target: dict[str, list[dict]] = {}
    for profile in list_profiles():
        profiles_by_target.setdefault(profile.target, []).append(
            {
                "id": profile.id,
                "name": profile.name,
                "description": profile.description,
                "audience": profile.audience,
                "field_mapping_pack": profile.field_mapping_pack,
                "pysigma_pipeline": profile.pysigma_pipeline,
                "output_formats": profile.output_formats,
            }
        )
    for target in TARGETS.values():
        out.append(
            {
                "id": target.id,
                "name": target.name,
                "description": target.description,
                "aliases": list(target.aliases),
                "formats": [
                    {
                        "id": fmt.id,
                        "name": fmt.name,
                        "description": fmt.description,
                        "support_level": _format_support_level(target.id, fmt.id, fmt.support_level),
                        "content_type": fmt.content_type,
                        "file_extension": fmt.file_extension,
                    }
                    for fmt in target.formats
                ],
                "profiles": profiles_by_target.get(target.id, []),
            }
        )
    return out
