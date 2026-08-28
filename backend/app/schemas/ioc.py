from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CVE = "cve"
    EMAIL = "email"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOCBase(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(..., min_length=1)

    source: str = Field(..., min_length=1)

    threat_type: Optional[str] = None

    confidence: int = Field(
        default=50,
        ge=0,
        le=100
    )

    severity: Severity = Severity.MEDIUM

    tags: List[str] = []


class IOCCreate(IOCBase):
    pass


class IOCResponse(IOCBase):
    id: int
    created_at: datetime


class IOCNormalized(IOCResponse):
    normalized_value: str