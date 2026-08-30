from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import IOC
from app.normalization.ioc_normalizer import normalize_ioc
from app.schemas.ioc import IOCCreate

router = APIRouter(
    prefix="/api/v1/iocs",
    tags=["Threat Intelligence - IOCs"]
)


@router.post("")
def create_ioc(
    ioc: IOCCreate,
    db: Session = Depends(get_db)
):
    normalized = normalize_ioc(ioc)

    record = IOC(**normalized)

    db.add(record)
    db.commit()
    db.refresh(record)

    return record


@router.get("")
def get_iocs(
    db: Session = Depends(get_db)
):
    records = db.query(IOC).all()

    return {
        "count": len(records),
        "data": records
    }


@router.get("/{ioc_id}")
def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db)
):
    record = (
        db.query(IOC)
        .filter(IOC.id == ioc_id)
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="IOC not found"
        )

    return record