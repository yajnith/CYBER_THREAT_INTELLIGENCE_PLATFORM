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
    new_ioc_count = 0

    for ioc in records:
        result = process_ioc(ioc, db)
        results.append(result)
        new_ioc_count += int(result["is_new"])

    return {
        "source_file": str(file_path),
        "count": len(results),
        "new_ioc_count": new_ioc_count,
        "existing_ioc_count": len(results) - new_ioc_count,
        "observation_count": len(results),
        "errors": [],
        "results": results,
    }
