from detectionforge_rule_engine.models import NormalizedRule, ParsedRule
from detectionforge_rule_engine.mitre import extract_mitre
from detectionforge_rule_engine.quality import calculate_quality_score


def normalize_rule(rule: ParsedRule) -> NormalizedRule:
    logsource = rule.logsource or {}
    mitre = extract_mitre(rule.tags)
    return NormalizedRule(
        title=rule.title,
        external_rule_id=rule.rule_id,
        description=rule.description,
        status=rule.status,
        severity=rule.level,
        platform=logsource.get("product"),
        product=logsource.get("product"),
        service=logsource.get("service"),
        category=logsource.get("category"),
        tags=rule.tags,
        mitre=mitre,
        logsource=logsource,
        detection=rule.detection,
        falsepositives=rule.falsepositives,
        references=rule.references,
        quality_score=calculate_quality_score(rule),
    )
