"""Local CVE identifier parsing; no NVD/CVSS feed or live lookup is used."""

import re


CVE_PATTERN = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


def build_cve_context(value: str) -> dict:
    normalized = value.strip().upper()
    if not normalized.startswith("CVE-"):
        normalized = f"CVE-{normalized}"

    match = CVE_PATTERN.fullmatch(normalized)
    if not match:
        return {
            "cve": normalized,
            "identifier_valid": False,
            "year": None,
            "numeric_identifier": None,
            "cvss_available": False,
            "cvss_score": None,
            "enrichment_source": "Local identifier parsing only; no CVE/CVSS database queried.",
        }

    year_text, numeric_text = match.groups()
    return {
        "cve": normalized,
        "identifier_valid": True,
        "year": int(year_text),
        "numeric_identifier": int(numeric_text),
        "numeric_identifier_text": numeric_text,
        "cvss_available": False,
        "cvss_score": None,
        "enrichment_source": "Local identifier parsing only; no CVE/CVSS database queried.",
    }
