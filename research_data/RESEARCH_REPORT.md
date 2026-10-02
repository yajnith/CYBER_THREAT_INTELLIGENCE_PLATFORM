# CTIP research-data report

**Scope:** reproducible account of research assets and implementation status in
this repository. URLhaus values below come from its committed metadata and the
existing profile script. No ThreatFox records or multi-source results are
claimed.

## 1. Research objective

The research direction is **context-aware and explainable threat prioritization
using correlated CTI**.

The research question is: **Does combining IOC evidence from multiple sources
with contextual threat information improve threat prioritization?**

## 2. Research architecture

Planned pipeline, with current implementation status:

```text
Multi-source CTI [partial]
→ normalization [implemented]
→ entity resolution [pending across sources]
→ correlation [partial]
→ enrichment [implemented]
→ threat context [partial]
→ ML prioritization [pending]
→ explainability [partial: deterministic scoring rationale]
→ analyst dashboard [implemented]
→ evaluation [pending]
```

URLhaus is prepared as a separate research dataset. ThreatFox has an authenticated
acquisition workflow but no locally acquired records. The application supports
IOC ingestion and observation-based source correlation; neither this nor its
exact-value deduplication constitutes cross-source entity resolution.

## 3. URLhaus dataset

| Measure | Recorded value |
| --- | --- |
| Source | URLhaus recent URL export |
| Collection timestamp | 2026-09-25 17:01:23 +05:30 |
| Raw records | 14,354 |
| Normalized records | 14,354 |
| Unique URLs | 14,354 |
| Duplicate URLs | 0 |

The committed metadata identifies the input as a recent URL export. It does not
record the exact download URL, API request, or command, so this report does not
infer a more specific access method.

**Threat distribution:** `malware_download`: 14,354. This is single-class data
and is not a valid supervised target.

**URL status:** offline 12,624; online 1,730.

**Missing values:** `last_online`: 1,567; `url`, `date_added`, `url_status`,
`threat`, `tags`, and `reporter`: 0 each.

**Reporters and tags:** metadata records 95 unique reporters. Running the
existing `research_data/profile.py` against the local normalized snapshot
reported the most frequent reporters as `cesnet_certs` (3,669), `geenensp`
(2,870), `adliwahid` (1,936), `BlinkzSec` (1,624), and `abuse_ch` (1,011).
The same profile reported the leading tags as `elf` (5,354), `Mozi` (5,285),
`mirai` (5,079), `32-bit` (2,847), and `ua-wget` (2,582). Tags can co-occur;
these are per-tag record counts, not disjoint categories.

**Preprocessing recorded in metadata:** flattened the URLhaus ID to a record;
normalized field names; converted null tags to empty lists; verified URL
uniqueness. The normalized record fields are `urlhaus_id`, `url`, `date_added`,
`url_status`, `last_online`, `threat`, `tags`, `urlhaus_link`, and `reporter`.

Evidence: `research_data/urlhaus/metadata.json`,
`research_data/urlhaus/normalize.py`, and `research_data/profile.py`.

## 4. ThreatFox dataset

The documented Community API acquisition, normalization, and profiling workflow
exists under `research_data/threatfox/`. Acquisition requires
`THREATFOX_AUTH_KEY`; the local metadata currently says `not_collected` and has
no collection timestamp or measured counts. There are no local ThreatFox
statistics in this report. Fields in the ThreatFox normalizer and its
documentation are reference/schema information, not observations from a
collected dataset.

## 5. Unified schema

The design-only schema in `research_data/unified/schema.py` represents one typed
IOC entity with separate source observations:

- **Identity:** display IOC value, normalized IOC value, and IOC type.
- **Provenance:** source, source record ID, source reference, reporter, and
  source-reported IOC value.
- **Common optional context:** threat type, malware family, confidence, tags,
  first/last seen, and observation timestamp.
- **Source-specific fields:** URLhaus fields such as `date_added`, `url_status`,
  and `last_online`; ThreatFox fields such as malware aliases, type descriptions,
  confidence level, references, and additional returned fields.
- **Missing information:** optional fields remain null/absent; collection time
  belongs to dataset metadata and is not invented as a per-record observation.

The proposed future entity-resolution key is
`(ioc_type, normalized_ioc_value)`. Source observations remain distinct. The
schema has not been applied to or used to merge either dataset.

## 6. Research experiments

These are intended feature families, not trained models or measured results.

| Experiment | Intended feature families |
| --- | --- |
| A: IOC-only | IOC type and type-aware structural or lexical properties, such as value length, character composition, URL components, domain labels, and hash length. |
| B: IOC + correlation | Experiment A plus source/observation counts, reporter/source diversity, and explicitly defined cross-source agreement or temporal-overlap summaries. |
| C: IOC + correlation + threat context | Experiment B plus source-reported threat types, malware family, tags, confidence, and source-specific temporal/status context. |

## 7. Leakage and validity controls

- URLhaus `threat` is single-class (`malware_download`) and must not be used as
  a supervised target.
- Any future outcome or information only available after the prediction cutoff
  must not be an input feature. For example, if a URL status transition becomes
  an outcome, do not include that future status in the inputs.
- The deterministic `risk_score` is a rule-based baseline, not ground truth.
- Research exports remain under `research_data/`; they are not imported into
  the production IOC database by the research workflow. Keep test/database
  records separate from research corpora.
- Do not infer missing source fields, labels, or cross-source relationships.

## 8. Current implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| URLhaus research preparation | Implemented | `research_data/urlhaus/normalize.py`, `metadata.json`, and `research_data/profile.py` |
| ThreatFox acquisition/normalization workflow | Partially implemented | `research_data/threatfox/fetch.py`, `normalize.py`, `profile.py`; metadata says `not_collected` |
| Unified research schema | Design only | `research_data/unified/schema.py` and `README.md` |
| IOC ingestion and normalization | Implemented | `backend/app/ingestion/`, `backend/app/normalization/`, and IOC services |
| Exact IOC deduplication and observations | Implemented | `backend/app/services/ioc_service.py` and database models |
| Observation-based source correlation | Partially implemented | `backend/app/services/ioc_correlation.py`; summarizes sources for an existing IOC |
| Enrichment and deterministic risk scoring | Implemented | `backend/app/enrichment/` and `backend/app/scoring/` |
| Feature engineering | Partially implemented | `backend/app/features/ioc_features.py`; produces a feature vector, not model predictions |
| Threat-context correlation | Partially implemented | Current IOC context includes a stored threat type; no cross-source context graph is implemented |
| ML prioritization | Pending | No trained model or prediction pipeline |
| Explainability | Partially implemented | Deterministic score breakdown exists; no model-specific XAI implementation |
| Analyst dashboard | Implemented | `frontend/src/App.jsx` and investigation components |
| Experimental evaluation | Pending | No evaluation protocol/results in the repository |

## 9. Reproducibility

Run commands from the repository root unless a different working directory is
shown. Use the project’s configured Python/Node environments.

**Research data scripts:**

```powershell
python research_data/urlhaus/normalize.py
python research_data/profile.py
```

ThreatFox acquisition requires a personal key in the environment; do not put it
in source code:

```powershell
$env:THREATFOX_AUTH_KEY = "your-personal-auth-key"
python -m research_data.threatfox.fetch --days 7
python -m research_data.threatfox.profile
```

URLhaus raw/normalized JSON is stored under `research_data/urlhaus/` and ignored
by Git. ThreatFox raw, type-catalog, and normalized JSON is stored under
`research_data/threatfox/` and ignored by Git. The small metadata files are
trackable. Unified schema files contain design/tests, not merged records.

**Research and backend tests:**

```powershell
python -m pytest research_data/threatfox/tests research_data/unified/tests
Set-Location backend
python -m pytest
Set-Location ..
```

Backend tests use the configured `backend/.env` `DATABASE_URL`. Keep it pointed
at the intended test/development database and do not load research corpora into
it.

**Frontend production build:**

```powershell
Set-Location frontend
npm run build
Set-Location ..
```

## 10. Limitations

- The ThreatFox credential is unavailable, so no real ThreatFox sample has
  been acquired or empirically profiled.
- There is no real merged multi-source dataset.
- Cross-source entity resolution is not implemented.
- There is no ML model, XAI implementation, or experimental evaluation.
- URLhaus's exact acquisition URL/command is absent from its committed
  metadata.
- The unified schema has not been validated against real ThreatFox records or
  the acquired ThreatFox type catalogue.

## 11. Next research milestone

Acquire a documented recent ThreatFox sample with `THREATFOX_AUTH_KEY`, then
empirically validate its fields and IOC-type catalogue before implementing
source adapters or cross-source entity resolution.
