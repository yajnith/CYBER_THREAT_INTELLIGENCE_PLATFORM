"""Adapter for the existing normalized URLhaus record format."""

from typing import Any

from research_data.sources.base import SourceAdapter
from research_data.unified.schema import (
    SourceObservation,
    UnifiedResearchRecord,
    URLhausFields,
)


class URLhausAdapter(SourceAdapter):
    source_name = "urlhaus"

    def adapt(self, record: dict[str, Any]) -> UnifiedResearchRecord:
        record = self.require_mapping(record, self.source_name)
        url = record.get("url")
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URLhaus record requires a non-empty 'url'.")

        normalized_url = url.strip()
        source_fields = {
            field: record.get(field)
            for field in URLhausFields.model_fields
            if field in record
        }
        additional_fields = {
            key: value
            for key, value in record.items()
            if key not in URLhausFields.model_fields
        }
        urlhaus_fields = URLhausFields.model_validate(source_fields)

        observation = SourceObservation(
            source=self.source_name,
            source_record_id=urlhaus_fields.urlhaus_id,
            source_reference=urlhaus_fields.urlhaus_link,
            reporter=urlhaus_fields.reporter,
            source_ioc_value=url,
            threat_type=urlhaus_fields.threat,
            tags=urlhaus_fields.tags,
            # URLhaus date_added/last_online are deliberately retained only in
            # the source-specific payload, not relabeled as first/last seen.
            urlhaus=urlhaus_fields,
            additional_fields=additional_fields,
        )

        return UnifiedResearchRecord(
            ioc_value=url,
            normalized_ioc_value=normalized_url,
            ioc_type="url",
            source_observations=[observation],
        )
