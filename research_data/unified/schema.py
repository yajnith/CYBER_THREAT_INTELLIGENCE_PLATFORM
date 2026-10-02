"""Validation models for the proposed unified CTI research schema.

These models validate synthetic schema examples only. They do not ingest or
merge either source dataset.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


IOCType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "cve",
    "email",
    "ip:port",
]
SourceName = Literal["urlhaus", "threatfox"]


class URLhausFields(BaseModel):
    """Fields in the existing URLhaus normalized record schema."""

    model_config = ConfigDict(extra="forbid")

    urlhaus_id: str | None = None
    url: str | None = None
    date_added: str | None = None
    url_status: str | None = None
    last_online: str | None = None
    threat: str | None = None
    tags: list[str] | None = None
    urlhaus_link: str | None = None
    reporter: str | None = None


class ThreatFoxFields(BaseModel):
    """Fields in the implemented ThreatFox normalizer's output schema."""

    model_config = ConfigDict(extra="forbid")

    threatfox_id: str | None = None
    ioc: str | None = None
    ioc_type: str | None = None
    ioc_type_description: str | None = None
    threat_type: str | None = None
    threat_type_description: str | None = None
    malware_family: str | None = None
    malware_printable: str | None = None
    malware_alias: str | None = None
    malware_malpedia: str | None = None
    confidence_level: int | None = Field(default=None, ge=0, le=100)
    first_seen: str | None = None
    last_seen: str | None = None
    reporter: str | None = None
    reference: str | None = None
    tags: list[str] | None = None
    additional_fields: dict[str, object] = Field(default_factory=dict)


class SourceObservation(BaseModel):
    """One source's assertion and provenance for a unified IOC entity."""

    model_config = ConfigDict(extra="forbid")

    source: SourceName
    source_record_id: str | None = None
    source_reference: str | None = None
    reporter: str | None = None
    source_ioc_value: str | None = None
    threat_type: str | None = None
    malware_family: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    observation_timestamp: str | None = None
    urlhaus: URLhausFields | None = None
    threatfox: ThreatFoxFields | None = None
    additional_fields: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def source_fields_match_source(self):
        if self.source == "urlhaus" and self.threatfox is not None:
            raise ValueError("ThreatFox fields require source='threatfox'.")
        if self.source == "threatfox" and self.urlhaus is not None:
            raise ValueError("URLhaus fields require source='urlhaus'.")
        return self


class UnifiedResearchRecord(BaseModel):
    """One typed IOC entity with one or more separately preserved assertions."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    ioc_value: str = Field(min_length=1)
    normalized_ioc_value: str = Field(min_length=1)
    ioc_type: IOCType
    source_observations: list[SourceObservation] = Field(min_length=1)
