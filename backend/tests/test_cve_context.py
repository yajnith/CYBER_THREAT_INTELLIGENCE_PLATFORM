from app.services.cve_context import build_cve_context


def test_cve_identifier_parsing_does_not_invent_cvss():
    context = build_cve_context("CVE-2024-12345")
    assert context["identifier_valid"] is True
    assert context["cve"] == "CVE-2024-12345"
    assert context["year"] == 2024
    assert context["numeric_identifier"] == 12345
    assert context["cvss_available"] is False
    assert context["cvss_score"] is None


def test_malformed_cve_has_unavailable_context():
    context = build_cve_context("CVE-2024-nope")
    assert context["identifier_valid"] is False
    assert context["cvss_available"] is False
    assert context["cvss_score"] is None
