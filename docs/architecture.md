# DetectionForge Architecture

DetectionForge is split into four core areas:

1. Rule source ingestion
2. Rule normalization and enrichment
3. SIEM conversion
4. Use case presentation and export

## Data flow

```text
Repository sync
  -> YAML discovery
  -> Raw rule import
  -> Parser
  -> Normalizer
  -> MITRE enrichment
  -> Quality scoring
  -> Conversion
  -> API
  -> Web portal
```

## Core principles

External rules are read-only.
Normalized rules are internal representations.
Canonical use cases group several rule variants.
Conversion profiles keep SIEM and organization-specific mappings outside the rule body.
Generated queries are artifacts and should be versioned.
