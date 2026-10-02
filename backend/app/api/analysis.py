from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.ioc_extractor import EXTRACTION_METHOD, extract_iocs


router = APIRouter(prefix="/api/v1/analysis", tags=["Analyst Tools"])


class ExtractionRequest(BaseModel):
    text: str = Field(min_length=1, max_length=100_000)


@router.post("/extract-iocs")
def extract_iocs_from_text(request: ExtractionRequest):
    candidates = extract_iocs(request.text)
    return {
        "method": EXTRACTION_METHOD,
        "count": len(candidates),
        "candidates": candidates,
    }
