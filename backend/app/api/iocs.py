from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException

from app.normalization.ioc_normalizer import normalize_ioc
from app.schemas.ioc import IOCCreate


router = APIRouter(
    prefix="/api/v1/iocs",
    tags=["Threat Intelligence - IOCs"]
)


ioc_database = []
next_id = 1


@router.post("")
def create_ioc(ioc: IOCCreate):
    global next_id

    normalized = normalize_ioc(ioc)

    record = {
        "id": next_id,
        **normalized,
        "created_at": datetime.now(timezone.utc),
    }

    ioc_database.append(record)

    next_id += 1

    return record


@router.get("")
def get_iocs():
    return {
        "count": len(ioc_database),
        "data": ioc_database
    }


@router.get("/{ioc_id}")
def get_ioc(ioc_id: int):

    for ioc in ioc_database:
        if ioc["id"] == ioc_id:
            return ioc

    raise HTTPException(
        status_code=404,
        detail="IOC not found"
    )