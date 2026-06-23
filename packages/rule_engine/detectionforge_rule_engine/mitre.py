import re
from detectionforge_rule_engine.models import MitreMapping

TACTIC_ALIASES = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)


def extract_mitre(tags: list[str]) -> MitreMapping:
    tactics: list[str] = []
    techniques: list[str] = []
    for tag in tags:
        clean = tag.strip().lower()
        if clean.startswith("attack."):
            suffix = clean.removeprefix("attack.")
            if suffix in TACTIC_ALIASES and TACTIC_ALIASES[suffix] not in tactics:
                tactics.append(TACTIC_ALIASES[suffix])
            match = TECHNIQUE_RE.match(clean)
            if match:
                technique = f"T{match.group(1)}"
                if match.group(2):
                    technique = f"{technique}.{match.group(2)}"
                if technique not in techniques:
                    techniques.append(technique)
    return MitreMapping(tactics=tactics, techniques=techniques, raw_tags=tags)
