from detectionforge_rule_engine import build_splunk_query, normalize_rule, parse_rule_yaml


def test_parse_and_normalize_sigma_rule():
    raw = """
title: Suspicious PowerShell Encoded Command
id: 11111111-1111-1111-1111-111111111111
status: test
description: Detects encoded PowerShell commands
references:
  - https://example.com
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - " -enc "
      - " -encodedcommand "
  condition: selection
falsepositives:
  - Administrative scripts
level: high
"""
    parsed = parse_rule_yaml(raw)
    normalized = normalize_rule(parsed)
    assert normalized.title == "Suspicious PowerShell Encoded Command"
    assert "Execution" in normalized.mitre.tactics
    assert "T1059.001" in normalized.mitre.techniques
    assert normalized.quality_score >= 80


def test_splunk_fallback_query():
    rule = {
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": " -enc "},
            "condition": "selection",
        },
    }
    query, warnings = build_splunk_query(rule)
    assert "index=sysmon" in query
    assert "CommandLine" in query
    assert warnings == []
