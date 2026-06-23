from detectionforge_rule_engine.converters import supported_targets


def targets_catalog() -> list[dict]:
    return supported_targets()
