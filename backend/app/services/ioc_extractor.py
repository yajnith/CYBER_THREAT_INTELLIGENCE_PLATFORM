"""Dependency-free IOC extraction using regular expressions and validation."""

import ipaddress
import re


EXTRACTION_METHOD = "rule-based IOC extraction"
PATTERNS = (
    ("url", re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)),
    ("email", re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+", re.IGNORECASE)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)),
    ("hash_sha256", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")),
    ("hash_sha1", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")),
    ("hash_md5", re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")),
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    ("domain", re.compile(r"(?<![\w@.-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![\w.-])", re.IGNORECASE)),
)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


def extract_iocs(text: str) -> list[dict]:
    """Return typed candidates with end-exclusive offsets into *text*.

    URL and email spans take precedence over embedded domain matches; IPv4
    candidates are validated with the standard library before being returned.
    """
    if not isinstance(text, str):
        raise TypeError("IOC extraction input must be text")

    candidates = []
    for indicator_type, pattern in PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            value = match.group(0)
            if indicator_type == "url":
                value = value.rstrip(TRAILING_URL_PUNCTUATION)
                end = start + len(value)
                if not value:
                    continue
            if indicator_type == "ipv4":
                try:
                    ipaddress.IPv4Address(value)
                except ipaddress.AddressValueError:
                    continue
            candidates.append({
                "indicator_type": indicator_type,
                "value": value,
                "start": start,
                "end": end,
                "extraction_method": EXTRACTION_METHOD,
            })

    candidates.sort(key=lambda item: (item["start"], item["end"] - item["start"]))
    accepted = []
    for candidate in candidates:
        if any(
            candidate["start"] < existing["end"]
            and candidate["end"] > existing["start"]
            and existing["indicator_type"] in {"url", "email"}
            for existing in accepted
        ):
            continue
        if any(
            candidate["start"] == existing["start"]
            and candidate["end"] == existing["end"]
            and candidate["indicator_type"] == existing["indicator_type"]
            for existing in accepted
        ):
            continue
        accepted.append(candidate)
    return sorted(accepted, key=lambda item: (item["start"], item["end"]))
