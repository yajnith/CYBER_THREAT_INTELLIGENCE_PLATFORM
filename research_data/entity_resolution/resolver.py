"""Resolve adapted research observations into typed IOC entities.

Resolution uses exactly ``(ioc_type, normalized_ioc_value)``. Every input
observation is retained, including repeated observations from the same source;
no observation deduplication policy is applied here. The first input record for
an identity supplies the entity's display ``ioc_value``. Source-specific values
remain available on each observation.
"""

from collections.abc import Iterable

from pydantic import ValidationError

from research_data.unified.schema import (
    SourceObservation,
    UnifiedResearchRecord,
)


def resolve_entities(
    records: Iterable[UnifiedResearchRecord],
) -> list[UnifiedResearchRecord]:
    """Group compatible source observations by typed IOC identity.

    Input order determines output entity order and observation order. The
    function accepts adapted records only; it does not normalize source data,
    fetch records, or correlate their threat assertions.
    """

    grouped: dict[tuple[str, str], list[UnifiedResearchRecord]] = {}
    for index, record in enumerate(records):
        if not isinstance(record, UnifiedResearchRecord):
            raise ValueError(
                "Entity resolution expects UnifiedResearchRecord objects; "
                f"item {index} is {type(record).__name__}."
            )

        try:
            # Revalidate serialized fields so even unchecked/mutated model
            # instances cannot silently introduce an unsupported IOC type.
            validated = UnifiedResearchRecord.model_validate(
                record.model_dump()
            )
        except ValidationError as error:
            raise ValueError(
                f"Invalid unified research record at index {index}: {error}"
            ) from error

        identity = (validated.ioc_type, validated.normalized_ioc_value)
        grouped.setdefault(identity, []).append(validated)

    entities: list[UnifiedResearchRecord] = []
    for (ioc_type, normalized_value), matching_records in grouped.items():
        first_record = matching_records[0]
        observations = [
            SourceObservation.model_validate(observation.model_dump())
            for record in matching_records
            for observation in record.source_observations
        ]
        entities.append(UnifiedResearchRecord(
            schema_version=first_record.schema_version,
            ioc_value=first_record.ioc_value,
            normalized_ioc_value=normalized_value,
            ioc_type=ioc_type,
            source_observations=observations,
        ))

    return entities
