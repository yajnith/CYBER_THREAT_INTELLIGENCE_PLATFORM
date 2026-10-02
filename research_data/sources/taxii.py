"""Integration contract for future TAXII 2.x collection.

This protocol does not implement a TAXII client, authentication, STIX parsing,
or network access. A concrete adapter requires server/collection configuration
and validated STIX handling.
"""

from datetime import datetime
from typing import Any, Iterable, Protocol, runtime_checkable


@runtime_checkable
class TaxiiSourceAdapter(Protocol):
    """Minimal source interface expected by a future TAXII adapter."""

    source_name: str

    def fetch_objects(
        self,
        collection_id: str,
        *,
        added_after: datetime | None = None,
    ) -> Iterable[dict[str, Any]]:
        """Fetch source objects for one configured collection."""

