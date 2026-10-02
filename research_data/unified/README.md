# Proposed unified CTI research schema

**Design only.** This directory defines a validation model and research plan;
it does not load, join, or merge URLhaus and ThreatFox data. ThreatFox has no
real acquired records in the current workspace, so this proposal is based only
on its implemented normalizer's field names and the source documentation already
captured in `research_data/threatfox/README.md`.

## Record shape

The entity identity is `(ioc_type, normalized_ioc_value)`. `ioc_value` is a
display value, not an identity key. Each entity contains one or more
`source_observations`; each observation retains a source name, source record ID,
source reference, reporter, raw source IOC value, and source-specific fields.
Threat assertions remain per observation so disagreement between feeds is not
flattened or overwritten.

| Group | Fields | Availability and handling |
| --- | --- | --- |
| Entity identity | `ioc_value`, `normalized_ioc_value`, `ioc_type` | Required. IOC type is part of the identity key. |
| Shared observation/provenance | `source`, `source_record_id`, `source_reference`, `reporter`, `source_ioc_value` | Source is required; IDs and reference fields may be absent. Keep each source assertion distinct. |
| Shared threat context | `threat_type`, `malware_family`, `confidence`, `tags` | Optional per source observation. Do not infer a value when the source does not provide it. |
| Shared temporal context | `first_seen`, `last_seen`, `observation_timestamp` | Optional source-reported values. Preserve source timestamps as supplied. |
| URLhaus fields | `urlhaus_id`, `url`, `date_added`, `url_status`, `last_online`, `threat`, `tags`, `urlhaus_link`, `reporter` | Kept under `source_observations[].urlhaus`. `threat` maps to the common threat assertion without dropping its source-specific copy. `date_added` is not silently relabeled as `first_seen`; `last_online` is not relabeled as `last_seen`. |
| ThreatFox fields | `threatfox_id`, `ioc`, source IOC type and description, threat type and description, malware family/printable/alias/Malpedia, confidence level, first/last seen, reporter, reference, tags, additional fields | Kept under `source_observations[].threatfox`. Common fields are projections; the source-specific values remain intact. |
| Extension/provenance | `source_observations[].additional_fields` | Retains source fields not yet represented in the stable source-specific models. |

Current URLhaus records provide a URL identifier/value, date added, online
status, last-online time, threat, tags, URLhaus reference, and reporter. They do
not provide confidence or a malware family in the existing normalized schema.
Current ThreatFox normalized records provide the fields listed in its nested
model. Unknown future ThreatFox IOC types must be reviewed against its published
type catalogue before the closed `IOCType` vocabulary is extended. The initial
vocabulary is the CTIP IOC schema plus the documented ThreatFox `ip:port` type.

`observation_timestamp` is null unless an observation time exists for that
individual record. Dataset collection time belongs in the source dataset
metadata, not copied onto every IOC as if it were an observation time.

## Later entity resolution (not implemented)

For records whose source types map to the same canonical type, consider them the
same candidate IOC entity only when both `normalized_ioc_value` **and**
`ioc_type` match. Different source names then add distinct source observations
to that entity. Keep source IDs, references, timestamps, tags, and context
separate; derive aggregates only as explicit downstream features.

The same text with different types must remain separate. For example, the text
`example.test` as a domain and as a URL is not the same typed indicator. Unknown
or non-equivalent source IOC types must not be coerced into a match. URL
normalization must preserve path/query case; only type-aware, documented
normalization should be used for comparisons.

## Proposed research feature groups

No target or model is defined in this milestone. These groups describe candidate
inputs only, not implemented features or results.

| Experiment | Candidate input families |
| --- | --- |
| A: IOC-only | IOC type and type-aware lexical/structural properties such as value length, character composition, URL components, domain labels, or hash length. No source multiplicity or threat context. |
| B: IOC + correlation | Experiment A plus source count, observation count, distinct reporter/source count, and explicitly defined cross-source agreement or temporal-overlap summaries. Preserve source identities for audit. |
| C: IOC + correlation + threat context | Experiment B plus source-reported threat types, malware-family context, tags, confidence, and source-specific temporal/status context. Keep conflicting assertions available rather than choosing one silently. |

Feature extraction must use only information available at the prediction
cutoff. Do not include a future outcome or fields calculated from that outcome.
URLhaus `threat` is single-class (`malware_download` in the existing profile)
and is not a supervised target. If `url_status` or a later status transition is
ever defined as an outcome, exclude the corresponding outcome/future status from
inputs. The current deterministic `risk_score` is a rule-based baseline, not
ground truth; compare it as a baseline rather than training against it as a
label. No labels are assigned here.

## Current data boundary

URLhaus remains a separate source dataset. ThreatFox acquisition requires
`THREATFOX_AUTH_KEY`, which is not configured; no ThreatFox records or profile
statistics are included. Do not instantiate multi-source records until a real
ThreatFox sample has been acquired and audited.
