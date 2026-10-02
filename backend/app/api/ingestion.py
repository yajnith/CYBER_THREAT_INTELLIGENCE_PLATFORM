import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.ingestion.service import ingest_json_feed


router = APIRouter(
    prefix="/api/v1/ingestion",
    tags=["Threat Intelligence - Ingestion"],
)

FEED_DIR = Path(__file__).resolve().parents[2] / "feeds"
FEED_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


@router.post("/feeds/{feed_id}")
def ingest_feed(
    feed_id: str,
    db: Session = Depends(get_db),
):
    """Ingest a named JSON feed from the project-local feeds directory."""
    if not FEED_ID_PATTERN.fullmatch(feed_id):
        raise HTTPException(
            status_code=400,
            detail="Feed ID may contain only letters, numbers, '_' and '-'.",
        )

    feed_path = (FEED_DIR / f"{feed_id}.json").resolve()
    if feed_path.parent != FEED_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid feed path.")
    if not feed_path.is_file():
        raise HTTPException(status_code=404, detail="CTI feed not found.")

    try:
        summary = ingest_json_feed(feed_path, db)
    except (ValueError, OSError) as error:
        raise HTTPException(
            status_code=422,
            detail=f"Unable to ingest feed '{feed_id}': {error}",
        ) from error

    return {
        "feed_id": feed_id,
        "source_file": feed_path.name,
        "records_processed": summary["count"],
        "new_iocs": summary["new_ioc_count"],
        "existing_iocs": summary["existing_ioc_count"],
        "observations_created": summary["observation_count"],
        "errors": summary["errors"],
    }
