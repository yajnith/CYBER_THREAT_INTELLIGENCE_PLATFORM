"""Fetch a recent ThreatFox Community API export using its documented API."""

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from research_data.threatfox.normalize import DATA_DIR, RAW_FILE, TYPES_FILE
from research_data.threatfox.profile import build_profile
from research_data.threatfox.normalize import normalize_file


API_URL = "https://threatfox-api.abuse.ch/api/v1/"
METADATA_FILE = DATA_DIR / "metadata.json"
NORMALIZED_FILE = DATA_DIR / "threatfox_normalized.json"
TIMEOUT_SECONDS = 60


def request_api(auth_key: str, payload: dict) -> dict:
    request = Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CTIP-research-data-preparation/1.0",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        raise RuntimeError(f"ThreatFox API request failed: {error}") from error
    if not isinstance(result, dict):
        raise RuntimeError("ThreatFox API returned a non-object JSON response.")
    return result


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    with temporary_path.open("w", encoding="utf-8") as file:
        json.dump(value, file, indent=2, ensure_ascii=False)
    temporary_path.replace(path)


def fetch(days: int = 7, auth_key: str | None = None) -> dict:
    if not 1 <= days <= 7:
        raise ValueError("ThreatFox get_iocs supports days from 1 through 7.")

    key = auth_key or os.environ.get("THREATFOX_AUTH_KEY")
    if not key:
        raise RuntimeError(
            "THREATFOX_AUTH_KEY is required. Obtain a free Auth-Key through "
            "the abuse.ch authentication portal and set it as an environment variable."
        )

    raw_response = request_api(key, {"query": "get_iocs", "days": days})
    types_response = request_api(key, {"query": "types"})
    if raw_response.get("query_status") not in {"ok", "no_result"}:
        raise RuntimeError(
            f"ThreatFox get_iocs returned status {raw_response.get('query_status')!r}."
        )
    if types_response.get("query_status") != "ok":
        raise RuntimeError(
            f"ThreatFox types query returned status {types_response.get('query_status')!r}."
        )

    collected_at = datetime.now(timezone.utc).isoformat()
    write_json(RAW_FILE, raw_response)
    write_json(TYPES_FILE, types_response)
    normalized, quality = normalize_file()
    profile = build_profile(
        raw_response,
        normalized,
        quality,
        collection_timestamp=collected_at,
        days_requested=days,
    )
    write_json(METADATA_FILE, profile)
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch recent IOCs from the documented ThreatFox Community API."
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        choices=range(1, 8),
        help="Look back 1 to 7 days by first_seen (default: 7).",
    )
    args = parser.parse_args()
    profile = fetch(days=args.days)
    print(f"Raw records: {profile['raw_record_count']}")
    print(f"Normalized records: {profile['normalized_record_count']}")
    print(f"Duplicate IOC values: {profile['duplicate_counts']['duplicate_iocs']}")
    print(f"Metadata: {METADATA_FILE}")


if __name__ == "__main__":
    main()
