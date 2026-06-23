from detectionforge_rule_engine.models import ParsedRule
from detectionforge_rule_engine.mitre import extract_mitre


def calculate_quality_score(rule: ParsedRule) -> int:
    score = 0
    mitre = extract_mitre(rule.tags)
    if mitre.tactics or mitre.techniques:
        score += 15
    if rule.description:
        score += 10
    if rule.falsepositives:
        score += 10
    if rule.references:
        score += 10
    if rule.level:
        score += 10
    if rule.logsource:
        product = rule.logsource.get("product")
        service = rule.logsource.get("service")
        category = rule.logsource.get("category")
        if product:
            score += 5
        if service:
            score += 5
        if category:
            score += 5
    if rule.detection:
        score += 15
    if rule.rule_id:
        score += 5
    return min(score, 100)
