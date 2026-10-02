"""Construct three-state research labels from independent outcome assertions.

This builder is deliberately separate from feature generation. It accepts typed
entity identities and adjudication records, never model feature dictionaries,
and emits one target row per typed identity. It is not run against the current
URLhaus data because no independently validated outcome records exist.
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from research_data.unified.schema import IOCType


HORIZON_DAYS = 7
OutcomeStatus = Literal["confirmed_harmful", "adjudicated_non_harmful"]
TargetValue = Literal["positive", "negative", "unknown"]


def _parse_aware_timestamp(value: str, field_name: str) -> datetime:
    """Parse an ISO timestamp and reject naive times to avoid ambiguous cutoffs."""

    normalized = value.strip()
    if normalized.endswith(" UTC"):
        normalized = f"{normalized[:-4]}+00:00"
    elif normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        result = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a valid ISO-8601 timestamp.") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone offset.")
    return result.astimezone(timezone.utc)


def _timestamp_string(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class EntityIdentity(BaseModel):
    """Typed entity key used to attach outcome evidence to a feature entity."""

    model_config = ConfigDict(extra="forbid")

    ioc_type: IOCType
    normalized_ioc_value: str = Field(min_length=1)

    @model_validator(mode="after")
    def require_nonblank_normalized_value(self):
        if not self.normalized_ioc_value.strip():
            raise ValueError("normalized_ioc_value must not be blank.")
        return self


class OutcomeAssertion(BaseModel):
    """One independently validated positive or non-harmful assertion.

    For harmful confirmation, ``confirmation_timestamp`` is required. For
    non-harmful adjudication, ``adjudication_timestamp`` is required and
    ``coverage_through`` establishes whether the full prediction horizon was
    observed. Assertions with ``independent_validation=False`` are retained as
    evidence but cannot produce labels.
    """

    model_config = ConfigDict(extra="forbid")

    assertion_id: str = Field(min_length=1)
    ioc_type: IOCType
    normalized_ioc_value: str = Field(min_length=1)
    outcome_status: OutcomeStatus
    independent_validation: bool
    source: str = Field(min_length=1)
    source_record_id: str | None = None
    source_reference: str | None = None
    confirmation_timestamp: str | None = None
    adjudication_timestamp: str | None = None
    coverage_through: str | None = None
    supersedes_assertion_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_status_timestamps(self):
        for field_name in ("assertion_id", "normalized_ioc_value", "source"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"{field_name} must not be blank.")
        if len(set(self.supersedes_assertion_ids)) != len(self.supersedes_assertion_ids):
            raise ValueError("supersedes_assertion_ids must be unique.")
        if self.assertion_id in self.supersedes_assertion_ids:
            raise ValueError("An assertion cannot supersede itself.")

        if self.outcome_status == "confirmed_harmful":
            if not self.confirmation_timestamp or self.adjudication_timestamp is not None:
                raise ValueError(
                    "confirmed_harmful requires confirmation_timestamp and forbids adjudication_timestamp."
                )
            _parse_aware_timestamp(self.confirmation_timestamp, "confirmation_timestamp")
        else:
            if not self.adjudication_timestamp or self.confirmation_timestamp is not None:
                raise ValueError(
                    "adjudicated_non_harmful requires adjudication_timestamp and forbids confirmation_timestamp."
                )
            adjudicated_at = _parse_aware_timestamp(
                self.adjudication_timestamp, "adjudication_timestamp"
            )
            if self.coverage_through is not None:
                coverage_through = _parse_aware_timestamp(
                    self.coverage_through, "coverage_through"
                )
                if coverage_through < adjudicated_at:
                    raise ValueError("coverage_through cannot precede adjudication_timestamp.")
        return self


def _identity_from_input(value: EntityIdentity | dict[str, Any], index: int) -> EntityIdentity:
    if isinstance(value, EntityIdentity):
        return value
    if not isinstance(value, dict):
        raise ValueError(f"Entity at index {index} must be an identity object or feature row.")
    payload = value.get("entity_identity", value)
    try:
        return EntityIdentity.model_validate(payload)
    except ValidationError as error:
        raise ValueError(f"Invalid entity identity at index {index}: {error}") from error


def _assertion_from_input(value: OutcomeAssertion | dict[str, Any], index: int) -> OutcomeAssertion:
    if isinstance(value, OutcomeAssertion):
        return value
    try:
        return OutcomeAssertion.model_validate(value)
    except ValidationError as error:
        raise ValueError(f"Invalid outcome assertion at index {index}: {error}") from error


def _candidate_reason(
    assertion: OutcomeAssertion,
    cutoff: datetime,
    horizon_end: datetime,
) -> tuple[bool, str]:
    if not assertion.independent_validation:
        return False, "not_independently_validated"
    if assertion.outcome_status == "confirmed_harmful":
        confirmed_at = _parse_aware_timestamp(
            assertion.confirmation_timestamp or "", "confirmation_timestamp"
        )
        if cutoff < confirmed_at <= horizon_end:
            return True, "confirmation_in_future_horizon"
        if confirmed_at <= cutoff:
            return False, "confirmation_at_or_before_cutoff"
        return False, "confirmation_after_horizon"

    adjudicated_at = _parse_aware_timestamp(
        assertion.adjudication_timestamp or "", "adjudication_timestamp"
    )
    coverage_complete = (
        assertion.coverage_through is not None
        and _parse_aware_timestamp(assertion.coverage_through, "coverage_through") >= horizon_end
    )
    if (cutoff <= adjudicated_at <= horizon_end) or coverage_complete:
        if coverage_complete:
            return True, "non_harmful_adjudication_with_complete_coverage"
        return True, "non_harmful_assertion_with_incomplete_coverage"
    return False, "non_harmful_assertion_not_relevant_to_horizon"


def _serialize_evidence(
    assertion: OutcomeAssertion,
    considered: bool,
    reason: str,
    superseded: bool,
) -> dict[str, Any]:
    evidence = assertion.model_dump(mode="json")
    evidence.update({
        "considered_for_target": considered,
        "decision_reason": reason,
        "superseded_by_explicit_adjudication": superseded,
    })
    return evidence


def _label_one_entity(
    identity: EntityIdentity,
    assertions: list[OutcomeAssertion],
    cutoff: datetime,
    horizon_end: datetime,
) -> dict[str, Any]:
    annotated = [
        (assertion, *_candidate_reason(assertion, cutoff, horizon_end))
        for assertion in assertions
    ]
    candidates = [item for item in annotated if item[1]]
    candidate_statuses = {item[0].outcome_status for item in candidates}
    conflict_detected = len(candidate_statuses) > 1
    superseded_ids = {
        assertion_id
        for assertion, _, _ in candidates
        for assertion_id in assertion.supersedes_assertion_ids
    }
    terminal = [
        item for item in candidates if item[0].assertion_id not in superseded_ids
    ]
    terminal_statuses = {item[0].outcome_status for item in terminal}
    unresolved_conflict = conflict_detected and (
        not terminal or len(terminal_statuses) > 1
    )

    target: TargetValue = "unknown"
    if not candidates:
        target_reason = "no_independent_qualifying_outcome_evidence"
    elif unresolved_conflict:
        target_reason = "unresolved_conflicting_assertions"
    elif terminal_statuses == {"confirmed_harmful"}:
        target = "positive"
        target_reason = "independent_harmful_confirmation_in_future_horizon"
    elif terminal_statuses == {"adjudicated_non_harmful"}:
        complete_coverage = any(
            assertion.coverage_through is not None
            and _parse_aware_timestamp(assertion.coverage_through, "coverage_through") >= horizon_end
            for assertion, _, _ in terminal
        )
        if complete_coverage:
            target = "negative"
            target_reason = "explicit_non_harmful_adjudication_with_full_horizon_coverage"
        else:
            target_reason = "negative_assertion_without_full_horizon_coverage"
    else:
        target_reason = "insufficient_or_superseded_outcome_evidence"

    evidence_rows: list[dict[str, Any]] = []
    for assertion, considered, reason in annotated:
        superseded = considered and assertion.assertion_id in superseded_ids
        if superseded:
            reason = "superseded_by_explicit_adjudication"
        evidence_rows.append(_serialize_evidence(assertion, considered, reason, superseded))
    evidence_rows.sort(key=lambda row: (
        row["assertion_id"],
        row["source"],
        row["outcome_status"],
        row.get("confirmation_timestamp") or row.get("adjudication_timestamp") or "",
        row.get("source_record_id") or "",
        row.get("source_reference") or "",
    ))

    conflict_resolution = None
    if conflict_detected:
        conflict_resolution = "unresolved"
        if not unresolved_conflict:
            conflict_resolution = "explicit_supersession"
    return {
        "schema_version": "1.0",
        "entity_identity": {
            "ioc_type": identity.ioc_type,
            "normalized_ioc_value": identity.normalized_ioc_value,
        },
        "prediction_window": {
            "cutoff_at": _timestamp_string(cutoff),
            "horizon_end": _timestamp_string(horizon_end),
            "horizon_days": HORIZON_DAYS,
        },
        "target": target,
        "target_reason": target_reason,
        "assertion_conflict_detected": conflict_detected,
        "conflict_resolution": conflict_resolution,
        "evidence_count": len(assertions),
        "outcome_evidence": evidence_rows,
    }


def build_targets(
    entities: list[EntityIdentity | dict[str, Any]],
    outcome_assertions: list[OutcomeAssertion | dict[str, Any]],
    cutoff_at: str | datetime,
) -> list[dict[str, Any]]:
    """Build one positive/negative/unknown target row per typed IOC identity.

    ``entities`` may contain ``EntityIdentity`` values or feature rows with an
    ``entity_identity`` object. Repeated identities collapse to one target row.
    Every matching outcome assertion remains in the resulting evidence list.
    Feature columns are neither accepted nor copied into target rows.
    """

    if not isinstance(entities, list):
        raise ValueError("entities must be a list.")
    if not isinstance(outcome_assertions, list):
        raise ValueError("outcome_assertions must be a list.")
    if isinstance(cutoff_at, datetime):
        if cutoff_at.tzinfo is None or cutoff_at.utcoffset() is None:
            raise ValueError("cutoff_at must include a timezone offset.")
        cutoff = cutoff_at.astimezone(timezone.utc)
    elif isinstance(cutoff_at, str):
        cutoff = _parse_aware_timestamp(cutoff_at, "cutoff_at")
    else:
        raise ValueError("cutoff_at must be a timezone-aware datetime or ISO timestamp.")
    horizon_end = cutoff + timedelta(days=HORIZON_DAYS)

    unique_entities: dict[tuple[str, str], EntityIdentity] = {}
    for index, value in enumerate(entities):
        identity = _identity_from_input(value, index)
        unique_entities.setdefault(
            (identity.ioc_type, identity.normalized_ioc_value), identity
        )

    grouped_assertions: dict[tuple[str, str], list[OutcomeAssertion]] = defaultdict(list)
    assertion_ids: dict[tuple[tuple[str, str], str], dict[str, Any]] = {}
    for index, value in enumerate(outcome_assertions):
        assertion = _assertion_from_input(value, index)
        key = (assertion.ioc_type, assertion.normalized_ioc_value)
        id_key = (key, assertion.assertion_id)
        payload = assertion.model_dump(mode="json")
        previous = assertion_ids.get(id_key)
        if previous is not None and previous != payload:
            raise ValueError(
                f"Conflicting records reuse assertion_id {assertion.assertion_id!r} for one IOC identity."
            )
        assertion_ids[id_key] = payload
        grouped_assertions[key].append(assertion)

    rows = [
        _label_one_entity(
            identity,
            grouped_assertions.get(key, []),
            cutoff,
            horizon_end,
        )
        for key, identity in sorted(unique_entities.items())
    ]
    return rows
