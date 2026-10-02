"""Build transparent correlation and threat-context summaries.

This module summarizes resolved research entities; it does not resolve IOC
identity, choose a source assertion as truth, score risk, or predict outcomes.
All source observations remain attached to ``CorrelationSummary.entity``.

``context_richness`` is the count of these six available evidence dimensions:
at least one threat type, at least one malware family, at least one confidence
value, at least one tag, at least one parseable timestamp, and support from more
than one source. It is a descriptive count (0 through 6), not a risk or AI
score. Context values remain separately available on each original source
observation.

Timestamp aggregation reads only ``first_seen``, ``last_seen``, and
``observation_timestamp``. URLhaus ``date_added`` and ``last_online`` remain
source-specific context and are not reinterpreted as seen timestamps. Naive
and timezone-aware timestamp values are not mixed for chronological bounds;
when both occur, bounds/span are left null and ``timestamp_timezone_conflict``
is true. Naive timestamps can be compared with other naive timestamps only.
"""

from collections import defaultdict
from datetime import datetime, timezone
from statistics import mean
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from research_data.unified.schema import (
    IOCType,
    UnifiedResearchRecord,
)


Agreement = bool | None


class CorrelationSummary(BaseModel):
    """A deterministic summary plus the unflattened source evidence."""

    model_config = ConfigDict(extra="forbid")

    entity: UnifiedResearchRecord
    ioc_type: IOCType
    normalized_ioc_value: str
    observation_count: int
    source_record_count: int
    observations_without_record_id: int
    source_count: int
    source_names: list[str]
    multi_source: bool
    threat_types: list[str]
    threat_type_count: int
    malware_families: list[str]
    malware_family_count: int
    aggregated_tags: list[str]
    shared_tags: list[str]
    observations_with_threat_context: int
    confidence_by_source: dict[str, list[int]]
    confidence_observation_count: int
    confidence_min: int | None
    confidence_max: int | None
    confidence_mean: float | None
    threat_type_agreement: Agreement
    malware_family_agreement: Agreement
    confidence_agreement: Agreement
    earliest_timestamp: str | None
    latest_timestamp: str | None
    temporal_span_seconds: float | None
    observations_with_timestamps: int
    unparseable_timestamp_count: int
    timestamp_timezone_conflict: bool
    context_dimensions: list[
        Literal[
            "threat_type",
            "malware_family",
            "confidence",
            "tags",
            "temporal",
            "source_diversity",
        ]
    ]
    context_richness: int


def _timestamp_value(value: str) -> tuple[datetime | None, bool | None]:
    """Parse supported ISO-like timestamps and report whether they are zoned."""

    normalized = value.strip()
    if not normalized:
        return None, None
    if normalized.endswith(" UTC"):
        normalized = f"{normalized[:-4]}+00:00"
    elif normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None, None

    is_zoned = parsed.tzinfo is not None and parsed.utcoffset() is not None
    if is_zoned:
        parsed = parsed.astimezone(timezone.utc)
    return parsed, is_zoned


def _agreement(values: list[object]) -> Agreement:
    """Return equality only when two or more observations provide a value."""

    if len(values) < 2:
        return None
    return all(value == values[0] for value in values[1:])


def correlate_entity(entity: UnifiedResearchRecord) -> CorrelationSummary:
    """Calculate deterministic features for one resolved IOC entity."""

    if not isinstance(entity, UnifiedResearchRecord):
        raise ValueError("Correlation expects a UnifiedResearchRecord entity.")
    try:
        entity = UnifiedResearchRecord.model_validate(entity.model_dump())
    except ValidationError as error:
        raise ValueError(f"Invalid unified research entity: {error}") from error

    observations = entity.source_observations
    source_names = sorted({observation.source for observation in observations})
    threat_types = sorted({
        observation.threat_type.strip()
        for observation in observations
        if observation.threat_type and observation.threat_type.strip()
    })
    malware_families = sorted({
        observation.malware_family.strip()
        for observation in observations
        if observation.malware_family and observation.malware_family.strip()
    })

    tag_sets = [
        set(observation.tags or [])
        for observation in observations
        if observation.tags
    ]
    aggregated_tags = sorted(set().union(*tag_sets)) if tag_sets else []
    shared_tags = sorted(set.intersection(*tag_sets)) if tag_sets else []

    context_observations = sum(
        bool(
            (observation.threat_type and observation.threat_type.strip())
            or (observation.malware_family and observation.malware_family.strip())
            or observation.confidence is not None
            or observation.tags
        )
        for observation in observations
    )

    confidence_by_source: dict[str, list[int]] = defaultdict(list)
    confidence_values: list[int] = []
    for observation in observations:
        if observation.confidence is not None:
            confidence_by_source[observation.source].append(observation.confidence)
            confidence_values.append(observation.confidence)
    sorted_confidence_by_source = {
        source: confidence_by_source[source]
        for source in sorted(confidence_by_source)
    }

    raw_timestamps_by_observation: list[list[str]] = []
    parsed_timestamps: list[tuple[str, datetime, bool]] = []
    unparseable_timestamp_count = 0
    for observation in observations:
        available: list[str] = []
        for value in (
            observation.first_seen,
            observation.last_seen,
            observation.observation_timestamp,
        ):
            if not value or not value.strip():
                continue
            available.append(value)
            parsed, is_zoned = _timestamp_value(value)
            if parsed is None or is_zoned is None:
                unparseable_timestamp_count += 1
            else:
                parsed_timestamps.append((value, parsed, is_zoned))
        raw_timestamps_by_observation.append(available)

    observations_with_timestamps = sum(bool(values) for values in raw_timestamps_by_observation)
    timezone_modes = {is_zoned for _, _, is_zoned in parsed_timestamps}
    timestamp_timezone_conflict = len(timezone_modes) > 1
    earliest_timestamp = None
    latest_timestamp = None
    temporal_span_seconds = None
    if parsed_timestamps and not timestamp_timezone_conflict:
        earliest = min(parsed_timestamps, key=lambda item: item[1])
        latest = max(parsed_timestamps, key=lambda item: item[1])
        earliest_timestamp = earliest[0]
        latest_timestamp = latest[0]
        temporal_span_seconds = round(
            (latest[1] - earliest[1]).total_seconds(),
            3,
        )

    context_dimensions: list[str] = []
    if threat_types:
        context_dimensions.append("threat_type")
    if malware_families:
        context_dimensions.append("malware_family")
    if confidence_values:
        context_dimensions.append("confidence")
    if aggregated_tags:
        context_dimensions.append("tags")
    if parsed_timestamps:
        context_dimensions.append("temporal")
    if len(source_names) > 1:
        context_dimensions.append("source_diversity")

    return CorrelationSummary(
        entity=entity,
        ioc_type=entity.ioc_type,
        normalized_ioc_value=entity.normalized_ioc_value,
        observation_count=len(observations),
        source_record_count=sum(
            observation.source_record_id is not None
            for observation in observations
        ),
        observations_without_record_id=sum(
            observation.source_record_id is None
            for observation in observations
        ),
        source_count=len(source_names),
        source_names=source_names,
        multi_source=len(source_names) > 1,
        threat_types=threat_types,
        threat_type_count=len(threat_types),
        malware_families=malware_families,
        malware_family_count=len(malware_families),
        aggregated_tags=aggregated_tags,
        shared_tags=shared_tags,
        observations_with_threat_context=context_observations,
        confidence_by_source=sorted_confidence_by_source,
        confidence_observation_count=len(confidence_values),
        confidence_min=min(confidence_values) if confidence_values else None,
        confidence_max=max(confidence_values) if confidence_values else None,
        confidence_mean=round(mean(confidence_values), 2) if confidence_values else None,
        threat_type_agreement=_agreement([
            observation.threat_type.strip()
            for observation in observations
            if observation.threat_type and observation.threat_type.strip()
        ]),
        malware_family_agreement=_agreement([
            observation.malware_family.strip()
            for observation in observations
            if observation.malware_family and observation.malware_family.strip()
        ]),
        confidence_agreement=_agreement(confidence_values),
        earliest_timestamp=earliest_timestamp,
        latest_timestamp=latest_timestamp,
        temporal_span_seconds=temporal_span_seconds,
        observations_with_timestamps=observations_with_timestamps,
        unparseable_timestamp_count=unparseable_timestamp_count,
        timestamp_timezone_conflict=timestamp_timezone_conflict,
        context_dimensions=context_dimensions,
        context_richness=len(context_dimensions),
    )


def correlate_entities(
    entities: list[UnifiedResearchRecord],
) -> list[CorrelationSummary]:
    """Calculate one correlation summary for each resolved entity."""

    return [correlate_entity(entity) for entity in entities]
