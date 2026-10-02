from app.services.attack_context import map_attack_style_context


def test_common_threat_tags_map_to_tactic_categories_without_technique_ids():
    context = map_attack_style_context("phishing", ["credential theft", "C2"])
    assert context["mapping_type"] == "rule-based ATT&CK-style context mapping"
    assert set(context["tactics"]) == {"Initial Access", "Credential Access", "Command and Control"}
    assert context["technique_ids"] == []


def test_unknown_threat_context_is_preserved_without_invented_mapping():
    context = map_attack_style_context("unmapped future category", [])
    assert context["tactics"] == []
    assert context["matches"] == []
