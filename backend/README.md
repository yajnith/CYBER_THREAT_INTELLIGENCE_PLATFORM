# Local CTI feed ingestion demo

## Seed the URLhaus operational demo subset

The reproducible seed utility reads the existing
`research_data/urlhaus/urlhaus_normalized.json` artifact (14,354 real records),
selects 50 records deterministically, and sends each through the existing
`process_ioc()` pipeline. From the repository root, preview and then reset the
local demo IOC tables before seeding:

```powershell
python -m research_data.urlhaus.seed_demo --dry-run
python -m research_data.urlhaus.seed_demo --reset-demo-db --limit 50
```

`--reset-demo-db` only works when `DATABASE_URL` points to a loopback PostgreSQL
host and the database is named `ctip`. It deletes IOC and observation rows only;
research datasets, feed files, and automated test fixtures are untouched. Check
`backend/.env` before using the reset option. Running without reset is safe to
repeat: exact IOC identities are deduplicated by CTIP and new observations are
recorded.

Selection is stable and avoids random sampling. It prefers distinct URL hosts,
then new tags, a balanced URL status, and reporter diversity, with normalized
source fields as tie-breakers. The source is recorded as `URLhaus`; actual
threat type and tags are retained. Source `date_added` maps to the existing
CTIP first-seen and observation timestamp; when available, `last_online` maps
to CTIP last-seen. If `last_online` is missing, CTIP keeps its actual
import-observation time as last-seen rather than inferring a source timestamp.
The operational database has no URLhaus reporter, ID,
reference, or URL-status columns; those remain in the research artifact. The
URLhaus source has no confidence/severity labels, so existing CTIP defaults of
50 and `medium` drive deterministic risk display. These defaults are not
source-derived labels or CVSS values.

The dashboard identifies this as a historical **URLhaus demo subset**, not a
live feed. The full 14,354-record research dataset, 14,354 × 44 research feature
space, zero real supervised labels, and separate 600-sample synthetic benchmark
remain unchanged. Controlled JSON/CSV sample feeds remain available as a
secondary demonstration.

Configure PostgreSQL through `backend/.env` (`DATABASE_URL`), then start the
API from the `backend` directory using the project's installed dependencies:

```powershell
uvicorn app.main:app --reload
```

Place a JSON array or CSV in `backend/feeds/`. Each filename stem is the feed
ID; the API only reads `.json` and `.csv` files from that directory. CSV uses
IOC field names in the header; `indicator_type`, `value`, and `source` are
required. Optional fields are `threat_type`, `confidence`, `severity`, and
`tags`. Tags accept semicolons, or commas inside a quoted CSV cell. If a feed
ID has both JSON and CSV files, JSON is selected first. To ingest the JSON
sample feed from another terminal:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/ingestion/feeds/sample_cti_feed
```

The response reports processed records, new versus existing IOCs, and
observations created. Re-ingesting a feed reuses IOC records while recording
new observations. Invalid JSON is rejected with a parse error; invalid IOC
records include their record index and validation message. Arbitrary filesystem
paths are not accepted.

The `sample_cti_csv` feed contains the same reserved `.example` domain twice
from different demo source names to demonstrate CSV parsing and observation
deduplication. It is illustrative application demo input, not research data.

The sample feed contains an intentional repeated domain observation from a
second source. On an otherwise clean database its first run processes five
records, creates four IOC identities, records one duplicate/existing IOC and
creates five observations. A later run reports all five records as existing
and creates five additional observations. The example domains use the reserved
`.example` suffix and are controlled demo inputs, not research data.

## Research overview

The analyst UI's **Research & AI** view uses the read-only
`GET /api/v1/research/overview` endpoint. The endpoint reads the generated
profiles and benchmark artifacts under the repository's `research_data/`
directory; it does not access the production IOC database or alter IOC risk
scores. If generated (often Git-ignored) artifacts are missing, the endpoint
reports their availability and returns unavailable values instead of
reconstructing results.

URLhaus statistics are real dataset facts with unknown supervised targets.
Model metrics and feature-contribution views are explicitly from the controlled
synthetic benchmark only and are not predictions or validated performance for
real IOCs.

## Synopsis-aligned capabilities

| Capability | Status | Evidence / limitation |
|---|---|---|
| Local JSON/CSV CTI ingestion, normalization, and observations | IMPLEMENTED | Bounded feed API routes records through the existing IOC processing service. |
| IOC investigation and deterministic risk explanation | IMPLEMENTED | PostgreSQL detail, source observations, and severity/confidence formula. |
| Analyst mitigation guidance | IMPLEMENTED | Rule-based recommendations include reasons; no defensive action is executed. |
| CVE context | PARTIAL | Local identifier/year/number parsing; no NVD request or validated CVSS value. |
| ATT&CK-style context | PARTIAL | Rule-based tactic categories only; no invented technique IDs or full ATT&CK database. |
| Text IOC extraction | IMPLEMENTED | Dependency-free rule-based extraction; candidates require analyst validation. |
| Research ML and explainability | RESEARCH-VALIDATED | Synthetic benchmark and model-derived contributions only, not real URLhaus performance. |
| ThreatFox/TAXII/STIX/external telemetry | INTEGRATION-READY | ThreatFox requires a credential; TAXII is a contract only; full STIX/Wazuh/OpenSearch are not connected. |
| Real-label evaluation and production ML | FUTURE | No real validated outcome labels; production risk remains deterministic. |

## Additional analyst tools

`POST /api/v1/analysis/extract-iocs` accepts `{ "text": "..." }` and returns
typed IOC candidates with text offsets. It uses regex rules, not a transformer,
and does not create IOC records. IOC investigation includes rule-based
recommendations, a local CVE identifier parser, and a small ATT&CK-style tactic
mapping. Recommendations are guidance only. The research source package also
defines a `TaxiiSourceAdapter` contract; there is no live TAXII client or full
STIX serialization in this project.

See the repository's `DEMO_CHECKLIST.md` for the recommended end-to-end
evaluation flow and its data/label limitations.
