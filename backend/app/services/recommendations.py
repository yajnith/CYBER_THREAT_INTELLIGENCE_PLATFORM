"""Deterministic analyst guidance; this module never performs defensive actions."""


def generate_mitigation_recommendations(
    indicator_type: str,
    value: str,
    *,
    threat_type: str | None = None,
    severity: str | None = None,
    confidence: int | None = None,
    risk_level: str | None = None,
    risk_score: int | None = None,
    tags: list[str] | None = None,
    enrichment: dict | None = None,
    source_count: int = 0,
) -> list[dict[str, str]]:
    """Return concise, explainable follow-up actions for an analyst."""
    del value  # The raw IOC is intentionally not interpolated into advice.
    kind = str(indicator_type).lower()
    threat = (threat_type or "").strip().lower().replace("-", "_")
    tag_set = {str(tag).strip().lower().replace("-", "_") for tag in (tags or [])}
    host = (enrichment or {}).get("hostname") or (enrichment or {}).get("domain")

    priority = "high" if risk_level in {"high", "critical"} else "medium" if risk_level == "medium" else "low"
    context_parts = []
    if threat_type:
        context_parts.append(f"reported threat context '{threat_type}'")
    if severity:
        context_parts.append(f"severity '{severity}'")
    if risk_level:
        context_parts.append(f"deterministic CTIP risk level '{risk_level}' (score {risk_score})")
    if source_count:
        context_parts.append(f"{source_count} observed source(s)")
    evidence = "; ".join(context_parts) or "the available IOC record"

    recommendations: list[dict[str, str]] = []

    def add(recommendation: str, reason: str) -> None:
        recommendations.append({
            "recommendation": recommendation,
            "reason": reason,
            "priority": priority,
        })

    if kind == "url":
        add("Review proxy and DNS logs for requests to this URL and related host activity.",
            f"The IOC is a URL; {evidence}.")
        add("Consider blocking the URL or its host after analyst validation.",
            f"Blocking can limit repeat access when the URL is confirmed malicious; {evidence}.")
        add("Inspect affected endpoints and investigate possible credential exposure.",
            "The URL may be used for phishing or payload delivery; verify endpoint and identity telemetry.")
    elif kind == "domain":
        host_label = f" ({host})" if host else ""
        add("Review DNS queries and recent endpoint connections for this domain.",
            f"The IOC is a domain{host_label}; {evidence}.")
        add("Check associated URLs and consider domain blocking after validation.",
            f"A domain-level control may reduce access to related infrastructure; {evidence}.")
    elif kind in {"hash_md5", "hash_sha1", "hash_sha256"}:
        add("Search endpoint telemetry for files matching this hash.",
            f"The IOC is a file hash; {evidence}.")
        add("Quarantine matching files after confirming the detection and inspect affected hosts.",
            "Hash matches can identify the same file across endpoints; validate the match before containment.")
        add("Review affected hosts for persistence and related process activity.",
            "Malware-related file activity may have follow-on behavior that the hash alone does not describe.")
    elif kind in {"ipv4", "ipv6"}:
        add("Review inbound and outbound firewall, proxy, and flow records for this IP.",
            f"The IOC is an IP address; {evidence}.")
        add("Consider blocking the IP after validating business impact and observed activity.",
            "A network block may disrupt legitimate traffic if the indicator is shared or stale.")
    elif kind == "cve":
        add("Identify exposed assets running the affected product and verify patch status.",
            f"The IOC identifies a CVE; {evidence}. No CVSS score is available from local CTIP data.")
        add("Prioritize remediation using verified exposure and the organization's change process.",
            "This local CVE context parses the identifier only and does not supply severity or exploitability data.")
    else:
        add("Validate the indicator against related telemetry and document the investigation outcome.",
            f"The IOC type is '{kind}'; {evidence}.")

    if threat in {"phishing", "credential_theft", "credential_access"} or tag_set.intersection(
        {"phishing", "credential_theft", "credential_access"}
    ):
        add("Review authentication logs and investigate possible credential exposure.",
            "The reported threat type or tags indicate phishing or credential-theft context.")
    elif threat in {"command_and_control", "c2", "botnet"} or "c2" in tag_set:
        add("Correlate observed connections with endpoint process and network telemetry.",
            "The reported threat type or tags indicate command-and-control context.")

    if confidence is not None and confidence < 50:
        add("Validate this indicator with additional evidence before taking containment action.",
            f"The stored confidence is {confidence}; low-confidence indicators warrant corroboration.")

    return recommendations
