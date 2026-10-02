# Research-level correlation summaries

This module accepts resolved `UnifiedResearchRecord` entities and returns a
`CorrelationSummary` for each entity. It is deterministic and research-only;
it does not load datasets, modify PostgreSQL, perform resolution, rank IOCs, or
make predictions. Each result embeds the original entity and its separate
`source_observations`, preserving source record IDs, references, reporters,
timestamps, context assertions, and source-specific payloads.

## Features

- Identity: IOC type and normalized IOC value.
- Evidence: observation count, number of observations with source record IDs,
  observations lacking IDs, distinct source names/count, and `multi_source`.
- Threat context: sorted distinct threat types and malware families, distinct
  tag union, tags shared by every observation that supplies tags, and count of
  observations with at least one threat type, malware family, confidence, or
  tag.
- Confidence: all values grouped by source, observation count, minimum,
  maximum, mean (rounded to two decimal places), and agreement.
- Time: earliest/latest parseable `first_seen`, `last_seen`, or
  `observation_timestamp`, span in seconds, observations with timestamp text,
  and count of unparseable timestamp values. URLhaus `date_added` and
  `last_online` remain source-specific and are not treated as seen timestamps.
- Agreement: threat type, malware family, and confidence agreement is `true` or
  `false` when at least two observations provide that value; otherwise it is
  `null`. Tag sets are not treated as conflicting truth claims: the result
  reports their union and their intersection across observations with tags.
- Context richness: a descriptive count from 0 to 6. One dimension is present
  for each available category: threat type, malware family, confidence, tags,
  parseable temporal context, and multi-source support. `context_dimensions`
  lists exactly which categories contribute. This is not a risk score or AI
  score.

`source_record_count` counts observations with a non-null source record ID;
repeated IDs are still counted as separate observation rows. `source_count` is
the number of distinct source names. Confidence statistics use all non-null
observation-level confidence values without selecting a preferred source.

Timestamps are parsed only to derive chronological summaries; their original
text remains unchanged in the embedded entity. ISO `Z` and ` UTC` suffixes are
interpreted as UTC. Naive timestamps are comparable only with other naive
timestamps. If a record contains both timezone-aware and naive values, earliest,
latest, and span are left null and `timestamp_timezone_conflict` is set.

## API

```python
from research_data.correlation import correlate_entities, correlate_entity

summary = correlate_entity(resolved_entity)
summaries = correlate_entities(resolved_entities)
```

No URLhaus/ThreatFox dataset records are included here. Tests use small
synthetic in-memory observations only.
