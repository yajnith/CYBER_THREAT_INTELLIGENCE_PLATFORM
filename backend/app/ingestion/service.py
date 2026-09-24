from pathlib import Path

from sqlalchemy.orm import Session

from app.ingestion.parsers import load_json_feed
from app.services.ioc_service import process_ioc


def ingest_json_feed(
    file_path: str | Path,
    db: Session,
) -> dict:
    records = load_json_feed(file_path)

    results = []

    for ioc in records:
        result = process_ioc(ioc, db)
        results.append(result)

    return {
        "source_file": str(file_path),
        "count": len(results),
        "results": results,
    }
