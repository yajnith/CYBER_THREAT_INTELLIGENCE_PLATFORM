import re
from urllib.parse import urlparse


def enrich_ioc(indicator_type: str, value: str) -> dict:
    """
    Extract basic, deterministic characteristics from an IOC.
    """

    value = value.strip()

    enrichment = {
        "length": len(value),
        "has_digits": any(char.isdigit() for char in value),
        "has_special_characters": bool(
            re.search(r"[^a-zA-Z0-9]", value)
        ),
    }

    if indicator_type == "domain":
        domain = value.lower()

        parts = domain.split(".")

        enrichment["tld"] = (
            f".{parts[-1]}" if len(parts) > 1 else None
        )

        enrichment["has_subdomain"] = len(parts) > 2

        enrichment["label_count"] = len(parts)

    elif indicator_type == "url":
        parsed = urlparse(value)

        enrichment["scheme"] = parsed.scheme
        enrichment["hostname"] = parsed.hostname
        enrichment["has_path"] = bool(parsed.path)
        enrichment["has_query"] = bool(parsed.query)

    elif indicator_type in {
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
    }:
        enrichment["hash_length"] = len(
            value.replace(" ", "")
        )

    elif indicator_type in {"ipv4", "ipv6"}:
        enrichment["ip_version"] = (
            4 if indicator_type == "ipv4" else 6
        )

    elif indicator_type == "email":
        parts = value.split("@")

        if len(parts) == 2:
            enrichment["username"] = parts[0]
            enrichment["domain"] = parts[1].lower()

    return enrichment