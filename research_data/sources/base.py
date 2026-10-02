"""Shared contract for research-source adapters."""

from abc import ABC, abstractmethod
from typing import Any

from research_data.unified.schema import UnifiedResearchRecord


class SourceAdapter(ABC):
    """Map one already-normalized source record to one unified record.

    An adapter never combines records. Its output contains exactly one source
    observation; later entity resolution may combine observations explicitly.
    """

    source_name: str

    @abstractmethod
    def adapt(self, record: dict[str, Any]) -> UnifiedResearchRecord:
        """Validate and map one normalized source record."""

    @staticmethod
    def require_mapping(record: Any, source_name: str) -> dict[str, Any]:
        if not isinstance(record, dict):
            raise ValueError(f"{source_name} record must be a JSON object.")
        return record
