from detectionforge_rule_engine import build_splunk_query, normalize_rule, parse_rule_yaml

raw = """
title: Suspicious PowerShell Encoded Command
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: " -enc "
  condition: selection
level: high
"""

parsed = parse_rule_yaml(raw)
normalized = normalize_rule(parsed)
query, warnings = build_splunk_query(parsed.raw)
print(normalized.model_dump())
print(query)
print(warnings)
