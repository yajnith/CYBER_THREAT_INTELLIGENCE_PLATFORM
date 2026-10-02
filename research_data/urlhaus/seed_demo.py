"""Seed a bounded, deterministic URLhaus subset into the local CTIP demo DB.

Records are loaded from the existing normalized research artifact and are
processed through ``process_ioc``. URLhaus ``date_added`` and ``last_online``
are retained in CTIP's existing first/last-seen and observation timestamp
columns; they are source timestamps, not the current import time.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from dotenv import load_dotenv
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


ROOT = Path(__file__).resolve().parents[2]
NORMALIZED_FILE = Path(__file__).with_name("urlhaus_normalized.json")
DEFAULT_LIMIT = 50
DEMO_DATABASE_NAME = "ctip"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

sys.path.insert(0, str(ROOT / "backend"))
load_dotenv(ROOT / "backend" / ".env")

from app.database.database import DATABASE_URL, SessionLocal, engine  # noqa: E402
from app.database.models import IOC, IOCObservation  # noqa: E402
from app.schemas.ioc import IOCCreate  # noqa: E402
from app.services.ioc_service import process_ioc  # noqa: E402


def _host(record: dict[str, Any]) -> str:
    value = record.get("url")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Normalized URLhaus record requires a non-empty URL.")
    host = urlsplit(value.strip()).hostname
    if not host:
        raise ValueError(f"URLhaus record has no URL host: {value!r}")
    return host.lower()


def _stable_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(record.get("date_added") or ""),
        str(record.get("urlhaus_id") or ""),
        str(record.get("url") or "").casefold(),
        str(record.get("url") or ""),
    )


def select_representative_records(
    records: list[dict[str, Any]], limit: int = DEFAULT_LIMIT
) -> list[dict[str, Any]]:
    """Choose stable records favoring distinct hosts and tag/status diversity.

    Selection is greedy and deterministic: at each step it prefers a host not
    already selected, then records adding unseen tags, then a less represented
    URL status and reporter. Stable source fields break all remaining ties.
    No random sampling or source fields are synthesized.
    """
    if limit < 1:
        raise ValueError("Selection limit must be at least 1.")
    if not records:
        return []

    remaining = sorted(records, key=_stable_key)
    for record in remaining:
        _host(record)

    selected: list[dict[str, Any]] = []
    hosts: set[str] = set()
    tags: set[str] = set()
    status_counts: Counter[str] = Counter()
    reporter_counts: Counter[str] = Counter()

    while remaining and len(selected) < limit:
        def rank(record: dict[str, Any]) -> tuple[Any, ...]:
            host = _host(record)
            record_tags = {
                str(tag).strip()
                for tag in (record.get("tags") or [])
                if str(tag).strip()
            }
            status = str(record.get("url_status") or "")
            reporter = str(record.get("reporter") or "")
            return (
                0 if host not in hosts else 1,
                -len(record_tags - tags),
                status_counts[status],
                reporter_counts[reporter],
                _stable_key(record),
            )

        choice = min(remaining, key=rank)
        remaining.remove(choice)
        selected.append(choice)
        hosts.add(_host(choice))
        tags.update(str(tag).strip() for tag in (choice.get("tags") or []) if str(tag).strip())
        status_counts[str(choice.get("url_status") or "")] += 1
        reporter_counts[str(choice.get("reporter") or "")] += 1

    return selected


def parse_source_timestamp(value: Any) -> datetime | None:
    """Parse timestamps present in normalized URLhaus records without guessing."""
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"Expected URLhaus timestamp text, got {type(value).__name__}.")
    text = value.strip()
    if text.endswith(" UTC"):
        text = text[:-4] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"Invalid URLhaus timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def build_ioc(record: dict[str, Any]) -> tuple[IOCCreate, datetime | None, datetime | None]:
    """Map actual source fields to CTIP's existing IOC ingestion schema.

    URLhaus has no confidence or severity fields, so ``IOCCreate``'s existing
    neutral defaults (50 confidence, medium severity) remain in effect.
    """
    _host(record)
    raw_tags = record.get("tags")
    if raw_tags is None:
        tags: list[str] = []
    elif isinstance(raw_tags, list):
        tags = [str(tag).strip() for tag in raw_tags if str(tag).strip()]
    else:
        raise ValueError("Normalized URLhaus tags must be a list or null.")

    ioc = IOCCreate(
        indicator_type="url",
        value=record["url"].strip(),
        source="URLhaus",
        threat_type=record.get("threat"),
        tags=tags,
    )
    date_added = parse_source_timestamp(record.get("date_added"))
    last_online = parse_source_timestamp(record.get("last_online"))
    return ioc, date_added, last_online


def load_normalized_records(path: Path = NORMALIZED_FILE) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(
            f"Normalized URLhaus artifact not found: {path}. "
            "Run the existing URLhaus normalization workflow first."
        )
    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("Normalized URLhaus artifact must contain an array of objects.")
    return records


def validate_demo_database_url(database_url: str) -> None:
    """Limit demo seeding/reset to the checked local development database."""
    parsed = make_url(database_url)
    if parsed.host not in LOOPBACK_HOSTS or parsed.database != DEMO_DATABASE_NAME:
        raise RuntimeError(
            "Refusing demo seed/reset: the utility is limited to the local "
            f"'{DEMO_DATABASE_NAME}' database on loopback."
        )


def reset_demo_database(db: Session, database_url: str = DATABASE_URL) -> int:
    validate_demo_database_url(database_url)
    observations = db.query(IOCObservation).delete(synchronize_session=False)
    db.query(IOC).delete(synchronize_session=False)
    db.commit()
    return observations


def seed_records(records: list[dict[str, Any]], db: Session, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    selected = select_representative_records(records, limit)
    new_count = 0
    for source_record in selected:
        ioc, date_added, last_online = build_ioc(source_record)
        result = process_ioc(ioc, db)
        new_count += int(result["is_new"])
        stored_ioc = result["ioc"]

        # The existing operational schema has temporal fields but no separate
        # URLhaus payload columns. Preserve the source's actual report times in
        # those temporal fields and the observation; do not use import time.
        if date_added is not None:
            stored_ioc.first_seen = date_added
            if last_online is not None:
                stored_ioc.last_seen = last_online
            observation = (
                db.query(IOCObservation)
                .filter(
                    IOCObservation.ioc_id == stored_ioc.id,
                    IOCObservation.source == "URLhaus",
                )
                .order_by(IOCObservation.id.desc())
                .first()
            )
            if observation is not None:
                observation.observed_at = date_added
            db.commit()

    source_counts = Counter(str(record.get("url_status") or "unknown") for record in selected)
    tag_values = {str(tag).strip() for record in selected for tag in (record.get("tags") or []) if str(tag).strip()}
    return {
        "source": "URLhaus",
        "records_processed": len(selected),
        "new_iocs": new_count,
        "existing_iocs": len(selected) - new_count,
        "observations_created": len(selected),
        "distinct_hosts": len({_host(record) for record in selected}),
        "url_status_distribution": dict(sorted(source_counts.items())),
        "distinct_tags": len(tag_values),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Number of deterministic records (default: 50).")
    parser.add_argument(
        "--reset-demo-db",
        action="store_true",
        help="Clear IOC and observation rows in the local loopback 'ctip' DB before seeding.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report selected-record statistics without database changes.")
    args = parser.parse_args()
    if args.dry_run and args.reset_demo_db:
        parser.error("--dry-run cannot be combined with --reset-demo-db")
    if args.limit > 100:
        parser.error("--limit cannot exceed 100 for this bounded demo seed")

    records = load_normalized_records()
    selected = select_representative_records(records, args.limit)
    if args.dry_run:
        summary = {
            "source": "URLhaus",
            "normalized_input_records": len(records),
            "records_selected": len(selected),
            "distinct_hosts": len({_host(record) for record in selected}),
            "url_status_distribution": dict(sorted(Counter(str(record.get("url_status") or "unknown") for record in selected).items())),
            "distinct_tags": len({str(tag).strip() for record in selected for tag in (record.get("tags") or []) if str(tag).strip()}),
        }
        print(json.dumps(summary, indent=2))
        return

    validate_demo_database_url(DATABASE_URL)
    # The app's default engine logs full SQL parameters. Keep seed output to the
    # concise result summary so the demo command does not dump IOC values.
    engine.echo = False
    db = SessionLocal()
    try:
        deleted_observations = reset_demo_database(db) if args.reset_demo_db else 0
        result = seed_records(selected, db, args.limit)
        result["reset_performed"] = args.reset_demo_db
        result["prior_observations_removed"] = deleted_observations
        result["normalized_source_artifact"] = str(NORMALIZED_FILE.relative_to(ROOT))
        print(json.dumps(result, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
