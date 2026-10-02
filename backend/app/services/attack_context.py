"""Small rule-based ATT&CK-style context mapping, not a full ATT&CK integration."""


RULES = {
    "phishing": ("Initial Access",),
    "credential_theft": ("Credential Access",),
    "credential theft": ("Credential Access",),
    "credential_access": ("Credential Access",),
    "malware": ("Execution", "Persistence"),
    "malware_download": ("Execution",),
    "command_and_control": ("Command and Control",),
    "command-and-control": ("Command and Control",),
    "c2": ("Command and Control",),
    "botnet": ("Command and Control",),
}


def map_attack_style_context(threat_type: str | None, tags: list[str] | None = None) -> dict:
    assertions = []
    if threat_type:
        assertions.append(("threat_type", threat_type))
    assertions.extend(("tag", str(tag)) for tag in (tags or []))

    matches = []
    tactics = []
    seen = set()
    for source_field, assertion in assertions:
        key = assertion.strip().lower().replace(" ", "_")
        rule_tactics = RULES.get(key) or RULES.get(assertion.strip().lower())
        if not rule_tactics:
            continue
        matches.append({
            "source_field": source_field,
            "assertion": assertion,
            "possible_tactics": list(rule_tactics),
        })
        for tactic in rule_tactics:
            if tactic not in seen:
                seen.add(tactic)
                tactics.append(tactic)

    return {
        "mapping_type": "rule-based ATT&CK-style context mapping",
        "tactics": tactics,
        "matches": matches,
        "technique_ids": [],
        "limitation": "Possible tactic context only; no technique IDs or complete MITRE ATT&CK integration are provided.",
    }
