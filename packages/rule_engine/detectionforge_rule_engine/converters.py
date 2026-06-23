from typing import Any

TARGETS = {
    "splunk": "Splunk SPL",
    "sentinel": "Microsoft Sentinel KQL",
    "kusto": "Microsoft Sentinel KQL",
    "elastic": "Elastic KQL",
    "opensearch": "OpenSearch Query String",
    "qradar": "QRadar AQL",
    "chronicle": "Google Chronicle UDM Search",
    "logscale": "CrowdStrike LogScale",
}

FIELD_MAPPINGS = {
    "splunk": {
        "EventID": "EventCode",
        "event_id": "EventCode",
        "Image": "Image",
        "CommandLine": "CommandLine",
        "ParentImage": "ParentImage",
        "ParentCommandLine": "ParentCommandLine",
        "User": "User",
        "TargetUserName": "TargetUserName",
        "ComputerName": "host",
        "UtcTime": "_time",
    },
    "sentinel": {
        "EventID": "EventID",
        "event_id": "EventID",
        "Image": "ProcessCommandLine",
        "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFolderPath",
        "ParentCommandLine": "InitiatingProcessCommandLine",
        "User": "AccountName",
        "TargetUserName": "TargetAccount",
        "ComputerName": "DeviceName",
    },
    "elastic": {
        "EventID": "event.code",
        "event_id": "event.code",
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line",
        "User": "user.name",
        "TargetUserName": "user.target.name",
        "ComputerName": "host.name",
    },
    "opensearch": {
        "EventID": "event.code",
        "event_id": "event.code",
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line",
        "User": "user.name",
        "TargetUserName": "user.target.name",
        "ComputerName": "host.name",
    },
    "qradar": {
        "EventID": "qid",
        "event_id": "qid",
        "Image": "Process Path",
        "CommandLine": "Command",
        "ParentImage": "Parent Process Path",
        "ParentCommandLine": "Parent Command",
        "User": "Username",
        "TargetUserName": "Username",
        "ComputerName": "Hostname",
    },
    "chronicle": {
        "EventID": "metadata.product_event_type",
        "event_id": "metadata.product_event_type",
        "Image": "target.process.file.full_path",
        "CommandLine": "target.process.command_line",
        "ParentImage": "principal.process.file.full_path",
        "ParentCommandLine": "principal.process.command_line",
        "User": "principal.user.userid",
        "TargetUserName": "target.user.userid",
        "ComputerName": "principal.hostname",
    },
    "logscale": {
        "EventID": "EventID",
        "event_id": "EventID",
        "Image": "Image",
        "CommandLine": "CommandLine",
        "ParentImage": "ParentImage",
        "ParentCommandLine": "ParentCommandLine",
        "User": "User",
        "TargetUserName": "TargetUserName",
        "ComputerName": "ComputerName",
    },
}

BASES = {
    "splunk": {
        "sysmon": "index=sysmon",
        "security": "index=wineventlog",
        "powershell": "index=wineventlog",
        "process_creation": "index=sysmon",
        "default": "index=main",
    },
    "sentinel": {
        "sysmon": "Event | where Source == \"Microsoft-Windows-Sysmon\"",
        "security": "SecurityEvent",
        "powershell": "WindowsEvent | where Provider == \"Microsoft-Windows-PowerShell\"",
        "process_creation": "DeviceProcessEvents",
        "default": "SecurityEvent",
    },
    "elastic": {
        "sysmon": "event.provider: \"Microsoft-Windows-Sysmon\"",
        "security": "event.module: \"windows\"",
        "powershell": "event.provider: \"Microsoft-Windows-PowerShell\"",
        "process_creation": "event.category: \"process\"",
        "default": "*",
    },
    "opensearch": {
        "sysmon": "event.provider: \"Microsoft-Windows-Sysmon\"",
        "security": "event.module: \"windows\"",
        "powershell": "event.provider: \"Microsoft-Windows-PowerShell\"",
        "process_creation": "event.category: \"process\"",
        "default": "*",
    },
    "qradar": {
        "default": "SELECT * FROM events WHERE",
    },
    "chronicle": {
        "default": "metadata.event_type != \"\"",
    },
    "logscale": {
        "sysmon": "#repo=sysmon",
        "security": "#repo=wineventlog",
        "powershell": "#repo=wineventlog",
        "process_creation": "#repo=sysmon",
        "default": "*",
    },
}

SPLUNK_PROFILE_BASES = {
    "default_splunk_windows": "index=wineventlog OR index=sysmon",
    "splunk_sysmon": "index=sysmon",
    "splunk_windows_security": "index=wineventlog sourcetype=WinEventLog:Security",
    "splunk_cim_endpoint": "index=* tag=process tag=endpoint",
}


def supported_targets() -> list[dict[str, Any]]:
    return [
        {
            "id": "splunk",
            "name": "Splunk SPL",
            "support_level": "built_in_fallback_and_sigma_cli",
            "profiles": [
                {"id": "default_splunk_windows", "name": "Default Splunk Windows"},
                {"id": "splunk_sysmon", "name": "Splunk Sysmon"},
                {"id": "splunk_windows_security", "name": "Splunk Windows Security"},
                {"id": "splunk_cim_endpoint", "name": "Splunk CIM Endpoint"},
            ],
            "formats": ["default", "savedsearches"],
        },
        {
            "id": "sentinel",
            "name": "Microsoft Sentinel KQL",
            "support_level": "built_in_review_fallback_and_sigma_cli",
            "profiles": [
                {"id": "sentinel_defender", "name": "Microsoft Defender tables"},
                {"id": "sentinel_security_event", "name": "SecurityEvent"},
            ],
            "formats": ["default"],
        },
        {
            "id": "elastic",
            "name": "Elastic KQL",
            "support_level": "built_in_review_fallback_and_sigma_cli",
            "profiles": [
                {"id": "elastic_ecs_windows", "name": "Elastic ECS Windows"},
            ],
            "formats": ["default"],
        },
        {
            "id": "opensearch",
            "name": "OpenSearch Query String",
            "support_level": "built_in_review_fallback_and_sigma_cli",
            "profiles": [
                {"id": "opensearch_windows", "name": "OpenSearch Windows"},
            ],
            "formats": ["default"],
        },
        {
            "id": "qradar",
            "name": "QRadar AQL",
            "support_level": "built_in_review_fallback_and_sigma_cli",
            "profiles": [
                {"id": "qradar_windows", "name": "QRadar Windows"},
            ],
            "formats": ["default"],
        },
        {
            "id": "chronicle",
            "name": "Google Chronicle UDM Search",
            "support_level": "review_fallback",
            "profiles": [
                {"id": "chronicle_udm_windows", "name": "Chronicle UDM Windows"},
            ],
            "formats": ["default"],
        },
        {
            "id": "logscale",
            "name": "CrowdStrike LogScale",
            "support_level": "review_fallback",
            "profiles": [
                {"id": "logscale_windows", "name": "LogScale Windows"},
            ],
            "formats": ["default"],
        },
    ]


def normalize_target(target: str) -> str:
    clean = target.strip().lower()
    aliases = {
        "kql": "sentinel",
        "sentinel-kql": "sentinel",
        "elasticsearch": "elastic",
        "lucene": "elastic",
        "aql": "qradar",
        "humio": "logscale",
        "crowdstrike_logscale": "logscale",
    }
    return aliases.get(clean, clean)


def _quote(value: Any) -> str:
    text = str(value).replace('"', '\\"')
    return f'"{text}"'


def _field_name(name: str, target: str) -> str:
    base = name.split("|")[0]
    mapping = FIELD_MAPPINGS.get(target) or {}
    return mapping.get(base, base)


def _modifiers(name: str) -> list[str]:
    return name.split("|")[1:] if "|" in name else []


def _base_key(logsource: dict[str, Any]) -> str:
    service = str(logsource.get("service") or "").lower()
    category = str(logsource.get("category") or "").lower()
    if service:
        return service
    if category:
        return category
    return "default"


def _base_query(logsource: dict[str, Any], target: str, profile: str | None) -> str:
    key = _base_key(logsource)
    if target == "splunk" and profile in SPLUNK_PROFILE_BASES:
        return SPLUNK_PROFILE_BASES[profile]
    bases = BASES.get(target) or BASES["elastic"]
    return bases.get(key) or bases.get("default") or "*"


def _contains_value(value: Any) -> str:
    text = str(value)
    if text.startswith("*") or text.endswith("*"):
        return text
    return f"*{text}*"


def _value_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _splunk_clause(field: str, value: Any, modifiers: list[str]) -> str:
    mapped = _field_name(field, "splunk")
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        candidate = item
        if "contains" in modifiers:
            candidate = _contains_value(item)
        elif "startswith" in modifiers:
            candidate = f"{item}*"
        elif "endswith" in modifiers:
            candidate = f"*{item}"
        clauses.append(f"{mapped}={_quote(candidate)}")
    return clauses[0] if len(clauses) == 1 else "(" + " OR ".join(clauses) + ")"


def _sentinel_clause(field: str, value: Any, modifiers: list[str]) -> str:
    mapped = _field_name(field, "sentinel")
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        if isinstance(item, int):
            clauses.append(f"{mapped} == {item}")
        elif "contains" in modifiers:
            clauses.append(f"{mapped} contains {_quote(item)}")
        elif "startswith" in modifiers:
            clauses.append(f"{mapped} startswith {_quote(item)}")
        elif "endswith" in modifiers:
            clauses.append(f"{mapped} endswith {_quote(item)}")
        else:
            clauses.append(f"{mapped} == {_quote(item)}")
    return clauses[0] if len(clauses) == 1 else "(" + " or ".join(clauses) + ")"


def _kql_clause(field: str, value: Any, modifiers: list[str], target: str) -> str:
    mapped = _field_name(field, target)
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        candidate = item
        if "contains" in modifiers:
            candidate = _contains_value(item)
        elif "startswith" in modifiers:
            candidate = f"{item}*"
        elif "endswith" in modifiers:
            candidate = f"*{item}"
        clauses.append(f"{mapped}: {_quote(candidate)}")
    return clauses[0] if len(clauses) == 1 else "(" + " OR ".join(clauses) + ")"


def _qradar_clause(field: str, value: Any, modifiers: list[str]) -> str:
    mapped = _field_name(field, "qradar")
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        if isinstance(item, int):
            clauses.append(f'"{mapped}" = {item}')
        elif "contains" in modifiers:
            clauses.append(f'"{mapped}" ILIKE {_quote("%" + str(item) + "%")}')
        elif "startswith" in modifiers:
            clauses.append(f'"{mapped}" ILIKE {_quote(str(item) + "%")}')
        elif "endswith" in modifiers:
            clauses.append(f'"{mapped}" ILIKE {_quote("%" + str(item))}')
        else:
            clauses.append(f'"{mapped}" = {_quote(item)}')
    return clauses[0] if len(clauses) == 1 else "(" + " OR ".join(clauses) + ")"


def _chronicle_clause(field: str, value: Any, modifiers: list[str]) -> str:
    mapped = _field_name(field, "chronicle")
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        if "contains" in modifiers:
            clauses.append(f"{mapped} = /.*{item}.*/")
        elif "startswith" in modifiers:
            clauses.append(f"{mapped} = /{item}.*/")
        elif "endswith" in modifiers:
            clauses.append(f"{mapped} = /.*{item}/")
        else:
            clauses.append(f"{mapped} = {_quote(item)}")
    return clauses[0] if len(clauses) == 1 else "(" + " or ".join(clauses) + ")"


def _logscale_clause(field: str, value: Any, modifiers: list[str]) -> str:
    mapped = _field_name(field, "logscale")
    values = _value_list(value)
    clauses: list[str] = []
    for item in values:
        candidate = item
        if "contains" in modifiers:
            candidate = f"*{item}*"
        elif "startswith" in modifiers:
            candidate = f"{item}*"
        elif "endswith" in modifiers:
            candidate = f"*{item}"
        clauses.append(f"{mapped}={_quote(candidate)}")
    return clauses[0] if len(clauses) == 1 else "(" + " OR ".join(clauses) + ")"


def _field_clause(name: str, value: Any, target: str) -> str:
    field = name.split("|")[0]
    modifiers = _modifiers(name)
    if target == "splunk":
        return _splunk_clause(field, value, modifiers)
    if target == "sentinel":
        return _sentinel_clause(field, value, modifiers)
    if target in {"elastic", "opensearch"}:
        return _kql_clause(field, value, modifiers, target)
    if target == "qradar":
        return _qradar_clause(field, value, modifiers)
    if target == "chronicle":
        return _chronicle_clause(field, value, modifiers)
    if target == "logscale":
        return _logscale_clause(field, value, modifiers)
    return _kql_clause(field, value, modifiers, "elastic")


def _selection_clause(selection: dict[str, Any], target: str) -> str:
    parts: list[str] = []
    for key, value in selection.items():
        if isinstance(value, dict):
            nested = _selection_clause(value, target)
            if nested:
                parts.append(nested)
        else:
            parts.append(_field_clause(str(key), value, target))
    joiner = " and " if target in {"sentinel", "chronicle"} else " AND "
    return joiner.join(parts)


def _extract_selections(detection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {key: value for key, value in detection.items() if key != "condition" and isinstance(value, dict)}


def _condition_names(condition: str, selections: dict[str, dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for name in selections:
        if name in condition:
            hits.append(name)
    return hits


def _combine(condition: str | None, selection_queries: dict[str, str], target: str, warnings: list[str]) -> str:
    if not selection_queries:
        return ""
    join_and = " and " if target in {"sentinel", "chronicle"} else " AND "
    join_or = " or " if target in {"sentinel", "chronicle"} else " OR "
    if not condition:
        return next(iter(selection_queries.values()))
    lower = condition.lower().strip()
    if lower.startswith("1 of "):
        prefix = condition.split("of", 1)[1].strip().replace("*", "")
        values = [query for name, query in selection_queries.items() if name.startswith(prefix)] or list(selection_queries.values())
        return "(" + join_or.join(values) + ")"
    if lower.startswith("all of "):
        prefix = condition.split("of", 1)[1].strip().replace("*", "")
        values = [query for name, query in selection_queries.items() if name.startswith(prefix)] or list(selection_queries.values())
        return "(" + join_and.join(values) + ")"
    if condition.strip() in selection_queries:
        return selection_queries[condition.strip()]
    names = _condition_names(condition, {name: {} for name in selection_queries})
    if not names:
        warnings.append("Complex Sigma condition was not fully parsed. The fallback used all simple selections.")
        return "(" + join_and.join(selection_queries.values()) + ")"
    if " or " in lower and " and " not in lower:
        return "(" + join_or.join(selection_queries[name] for name in names) + ")"
    if " and " in lower and " or " not in lower:
        return "(" + join_and.join(selection_queries[name] for name in names) + ")"
    warnings.append("Mixed boolean Sigma condition was simplified. Review the query before production use.")
    return "(" + join_and.join(selection_queries[name] for name in names) + ")"


def build_query(rule: dict[str, Any], target: str, profile: str | None = None, output_format: str = "default") -> tuple[str, list[str]]:
    normalized_target = normalize_target(target)
    warnings: list[str] = []
    if normalized_target not in TARGETS:
        normalized_target = "elastic"
        warnings.append(f"Unsupported target was mapped to Elastic-style syntax: {target}")
    if normalized_target in {"chronicle", "logscale", "qradar", "sentinel", "elastic", "opensearch"}:
        warnings.append("Fallback conversion is best-effort. Validate field names, indexes, sourcetypes, and syntax in your SIEM before production.")
    logsource = rule.get("logsource") or {}
    detection = rule.get("detection") or {}
    base = _base_query(logsource, normalized_target, profile)
    selections = _extract_selections(detection)
    if not selections:
        warnings.append("No simple Sigma selection was found. The generated query only contains a base selector.")
        return base, warnings
    selection_queries = {name: _selection_clause(value, normalized_target) for name, value in selections.items()}
    condition = detection.get("condition") if isinstance(detection.get("condition"), str) else None
    combined = _combine(condition, selection_queries, normalized_target, warnings)
    if normalized_target == "sentinel":
        if "| where" in base:
            query = f"{base} | where {combined}"
        else:
            query = f"{base}\n| where {combined}"
    elif normalized_target == "qradar":
        query = f"{base} {combined}"
    elif normalized_target == "chronicle":
        query = f"{base}\nand {combined}"
    elif normalized_target == "logscale":
        query = f"{base} {combined}"
    elif normalized_target == "splunk" and output_format == "savedsearches":
        title = str(rule.get("title") or "MetaSec Security Center Generated Search")
        search = f"{base} {combined}".strip()
        query = f"[{title}]\nsearch = {search}\ndisabled = 1\ncron_schedule = */15 * * * *"
    else:
        query = f"{base} {combined}".strip()
    return query, warnings
