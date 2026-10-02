# CTIP research-data report

**Scope:** reproducible account of research assets and implementation status in
this repository. URLhaus values below come from its committed metadata and the
existing profile script. The research pipeline accepts both sources, but this
run contains no ThreatFox records because its credential and normalized sample
are unavailable; no cross-source findings are claimed.

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
→ entity resolution [implemented in-memory for adapted records; multi-source data pending]
→ correlation [research summaries implemented; empirical cross-source run pending]
→ enrichment [implemented]
→ threat context [partial]
→ ML prioritization [pending]
→ explainability [partial: deterministic rationale plus synthetic-only model contributions]
→ analyst dashboard [implemented]
→ evaluation [pending]
```

URLhaus is prepared as a separate research dataset. ThreatFox has an authenticated
acquisition workflow but no locally acquired records. The application supports
IOC ingestion and observation-based source correlation. Research adapters,
typed entity resolution, and deterministic correlation summaries are connected
by a multi-source-capable pipeline. The current run contains URLhaus only.
Production exact-value deduplication and correlation remain separate.

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

**Research pipeline execution:** the real normalized snapshot was run through
`research_data/sources/urlhaus.py`, typed resolution, and
`research_data/correlation/correlate.py` using
`research_data/pipeline/run_urlhaus.py`. The run metadata records the input
SHA-256 and results. It processed 14,354 normalized records into 14,354 adapted
records, 14,354 resolved typed identities, and 14,354 observations. There was
one represented source (`urlhaus`) and zero multi-source entities.

Threat context was present on all 14,354 observations, entirely as the single
threat type `malware_download`. Tags were present on 11,976 observations, absent
on 2,378, and comprised 535 distinct values. No confidence values were
available. The correlation layer had no `first_seen`, `last_seen`, or
`observation_timestamp` values to aggregate; source-specific `date_added` was
present on 14,354 records and `last_online` on 12,787. These URLhaus fields
remain preserved as source-specific provenance and are not reinterpreted as
seen timestamps. Context richness was 1 for 2,378 entities and 2 for 11,976
entities (threat type plus tags where present).

The complete provenance-preserving per-entity results are written to
`research_data/unified/research_pipeline_results.json` and ignored by Git.
Compact counts and run provenance are stored in
`research_data/pipeline/urlhaus_pipeline_metadata.json`. This is URLhaus-only
execution: it does not demonstrate cross-source correlation. The single-class
threat distribution is not a valid multi-class supervised target.

## 4. ThreatFox dataset

The documented Community API acquisition, normalization, and profiling workflow
exists under `research_data/threatfox/`. Acquisition requires
`THREATFOX_AUTH_KEY`; the local metadata currently says `not_collected` and has
no collection timestamp or measured counts. There are no local ThreatFox
statistics in this report. Fields in the ThreatFox normalizer and its
documentation are reference/schema information, not observations from a
collected dataset. The pipeline checks for
`research_data/threatfox/threatfox_normalized.json`; because it is absent, the
real run skipped ThreatFox and reported `not_collected`.

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

The research resolver uses `(ioc_type, normalized_ioc_value)` for records that
have already passed through a source adapter. It preserves all source
observations on each resulting entity, including repeated same-source records.
The correlation layer summarizes source diversity, context assertions,
confidence, and available timestamps while preserving each observation. The
multi-source orchestration is implemented, but only URLhaus data has been
available to process; no ThreatFox dataset has been merged.

## 6. Research experiments

The research feature builder is implemented under `research_data/features/` and
has been run against the real URLhaus correlation artifact. It produced 14,354
rows with 44 feature columns. Feature groups A/B/C below describe experimental
inputs only; they are not trained models or measured model results.

| Experiment | Intended feature families |
| --- | --- |
| A: IOC-only | IOC type and type-aware structural or lexical properties, such as value length, character composition, URL components, domain labels, and hash length. |
| B: IOC + correlation | Experiment A plus source/observation counts, reporter/source diversity, and explicitly defined cross-source agreement or temporal-overlap summaries. |
| C: IOC + correlation + threat context | Experiment B plus source-reported threat types, malware family, tags, confidence, and source-specific temporal/status context. |

The generated rows store a typed entity key, engineered features, source
provenance, raw source assertions, and `target: null` as separate fields. The
normalized IOC string is retained as an entity key, while feature columns use
safe value-shape counts rather than raw IOC text. All 14,354 rows are URLs;
each has one observation, one URLhaus source, one reporter, and no repeated or
multi-source observation. URL value length ranges from 18 to 246 characters
(mean 34.72). Threat context is available on every row, but it contains only
one distinct threat type; tags occur on 11,976 rows and there are no malware
family or confidence values. The three confidence-value columns and three
timestamp/span columns are null in all rows. There are no generic correlation
timestamps; URLhaus `date_added` and `last_online` remain source fields and are
excluded from temporal features. Context richness is 1 or 2. Exact per-feature
missingness and distributions are in
`research_data/features/urlhaus_feature_profile.json`.

## 7. Leakage and validity controls

- URLhaus `threat` is single-class (`malware_download`) and must not be used as
  a supervised target.
- Any future outcome or information only available after the prediction cutoff
  must not be an input feature. For example, if a URL status transition becomes
  an outcome, do not include that future status in the inputs.
- The deterministic `risk_score` is a rule-based baseline, not ground truth.
- The research feature dataset defines no target and excludes deterministic
  risk scores. URLhaus `threat` remains single-class and is not used as a
  supervised target. Future outcome/status fields are excluded; temporal
  features require a declared prediction cutoff before experimentation.
- Research exports remain under `research_data/`; they are not imported into
  the production IOC database by the research workflow. Keep test/database
  records separate from research corpora.
- Do not infer missing source fields, labels, or cross-source relationships.

### Supervised target status and candidates

**Target not currently available.** The repository contains no independent
validated outcome labels or complete longitudinal follow-up. The research
question is framed as context-aware CTI threat prioritization. A proposed
future task is to estimate, at an entity cutoff time `t`, whether independent
validation confirms harmful activity for that typed IOC entity during the next
7 days. A negative requires explicit non-harmful adjudication and documented
coverage for the full horizon; missing/censored/conflicting outcomes remain
unknown. This target design is conditional, not a selected target or current
label set.

The considered strategies are recorded in
`research_data/features/experiment_spec.json`:

- URLhaus `threat` is present but single-class (`malware_download`), so it is
  unsuitable as a current multiclass target and cannot simultaneously be an
  input assertion and target.
- Deterministic CTIP risk level is available as a rule output, not ground
  truth. It can only be a clearly named baseline; treating it as a target
  would train a model to reproduce the rule.
- Future/outcome labels are not in the repository and would require independent
  timestamped adjudication and complete follow-up.
- Multi-source consensus is unavailable in the URLhaus-only run and is not
  independent ground truth if the same agreement/source-count signals are
  inputs.
- No external validated label source is present. It could be considered only
  after its definitions, provenance, timing, and coverage are verified.

No candidate is selected or preferred from current evidence. The feature rows
remain `target: null`; no model has been trained and no performance metrics
have been calculated.

Target-building infrastructure is implemented in
`research_data/targets/build_targets.py` with the combined input/output
contract in `research_data/targets/target_schema.json`. It accepts typed
identities separately from independent outcome assertions and emits one
three-state row per typed entity. Matching assertion provenance is preserved;
unresolved conflicts remain unknown unless explicit supersession resolves
them. Synthetic tests exercise the logic. The builder has not been run against
the real URLhaus feature rows and no real label counts have been generated.
Every current feature row remains `target: null`.

The deterministic target-builder infrastructure is implemented at
`research_data/targets/build_targets.py` with its input/output contract in
`research_data/targets/target_schema.json`. It accepts typed identities and
independent outcome assertions as separate inputs, emits one three-state row
per typed entity, retains evidence provenance, and leaves unresolved conflicts
unknown unless an assertion explicitly supersedes the conflicting evidence.
It has only been exercised with synthetic tests; it has not been run against
the real URLhaus feature dataset. No real target rows or label counts have been
generated. The real feature artifact still has `target: null` for every row.

The experiment-dataset assembly layer is implemented in
`research_data/experiments/build_datasets.py`. It joins feature rows to supplied
target-builder rows only by `(ioc_type, normalized_ioc_value)`, uses the same
deterministically ordered entity identities in Experiments A/B/C, and selects
the declared feature groups from `feature_schema.json`. Unmatched identities
are explicitly `unknown`, never negative. Target reason, prediction window,
and outcome evidence are stored outside model-facing features. Source
provenance and source-specific context assertions are retained separately.
An identity is rejected if its outcome-evidence source also appears in its
feature provenance, preventing a target-source overlap from silently entering
the experiment inputs. Conflicting duplicate rows fail; exact duplicate rows collapse. The output
contract is documented in `research_data/experiments/experiment_dataset_schema.json`.

The assembly was run on the 14,354 real URLhaus feature rows with no target
input available. It generated 14,354 rows in each A/B/C dataset: 0 positive,
0 negative, and 14,354 unknown in every experiment. A has 20 input features,
B has 28, and C has 44. The JSON row datasets are ignored by Git under the
existing research-data ignore rule; reproducibility counts and hashes are in
`research_data/experiments/urlhaus_experiment_profile.json`. These are
prepared unlabeled datasets, not trained experiments or evaluation results.

### First ML baseline pipeline (controlled synthetic benchmark)

The baseline pipeline is implemented under `research_data/ml/`. Because all
14,354 real URLhaus experiment rows have unknown targets and there are no
validated outcome labels, they were not used for supervised training. A
separate deterministic benchmark of 600 synthetic examples (300 positive,
300 negative) validates the A/B/C feature selection, train/test split,
preprocessing, model fit, and metric reporting. It is explicitly marked
synthetic, not real-world ground truth, and not derived from human-validated
URLhaus labels. Its classes are generated from a balanced latent variable with
overlapping noisy feature distributions; deterministic risk scores are not
used to create labels. No target or label-generation flag enters the feature
matrix.

Logistic Regression and Gaussian Naive Bayes were run for each of A/B/C with a
stratified 75/25 split and fixed seeds. The implementations use Python's
standard library because scikit-learn is unavailable in the current runtime;
no dependencies were installed. Exact values are stored in
`research_data/ml/synthetic_baseline_results.json`, and every metric is labeled
**SYNTHETIC BENCHMARK RESULT**. These values validate code execution only; they
are not URLhaus performance, a real-world threat-detection estimate, or
evidence that adding CTI context improves prioritization. No validated real
target labels exist, so no real-world ML performance claim is currently
possible. Production risk scoring was not changed.

| Experiment | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| A | Logistic Regression | 0.653333 | 0.632184 | 0.733333 | 0.679012 | 0.696178 |
| A | Gaussian Naive Bayes | 0.680000 | 0.675325 | 0.693333 | 0.684211 | 0.694400 |
| B | Logistic Regression | 0.726667 | 0.717949 | 0.746667 | 0.732026 | 0.820444 |
| B | Gaussian Naive Bayes | 0.700000 | 0.687500 | 0.733333 | 0.709677 | 0.782222 |
| C | Logistic Regression | 0.900000 | 0.875000 | 0.933333 | 0.903226 | 0.953956 |
| C | Gaussian Naive Bayes | 0.846667 | 0.802326 | 0.920000 | 0.857143 | 0.935644 |

All values above are synthetic benchmark measurements on the deterministic
150-row test set; they do not rank real CTI experiment configurations.

### Model-derived feature contributions (Step 9)

An explainability layer in `research_data/ml/explainability/` produces local
and global feature-contribution summaries for the same synthetic test split.
For Logistic Regression, encoded value times coefficient is attributed to
each feature and sums with the intercept to log-odds. For Gaussian Naive Bayes,
each contribution is a feature's positive-versus-negative Gaussian
log-likelihood ratio; these sum with log prior odds to the model log-odds.
Both decompositions reconstruct the model probability. The artifact includes
the first held-out example predicted positive and the first predicted negative
per model/experiment, chosen by deterministic test order without filtering on
whether each prediction is correct. Global contributions are ranked by mean
absolute contribution. Group summaries cover IOC intrinsic, observation,
correlation, provenance/source, and threat context using the established A/B/C
feature columns.

These explain model behavior on the controlled synthetic benchmark only. They
do not establish causal relationships and do not demonstrate real-world threat
attribution. Contribution, feature importance, and observed correlation are
distinct from causality. No SHAP was used. The deterministic artifact is
`research_data/ml/explainability/synthetic_explanations.json`; it contains no
explanations for unknown-target real URLhaus rows. Real-world validation remains
impossible until independently adjudicated target labels and temporal coverage
are available.

### Future evaluation protocol

If an independent outcome set is acquired, build each feature snapshot only
from evidence available by index cutoff `t`, and assess the proposed 7-day
outcome horizon after `t`. Use chronological train, validation, and held-out
test periods with at least a 7-day purge/embargo between label windows. Group
all records by `(ioc_type, normalized_ioc_value)` before assignment so an IOC,
its repeated observations, and its cross-source records cannot span
partitions. Unknown/censored outcomes are excluded rather than treated as
negative. Fit preprocessing and thresholds on training data only; use
validation for model selection and test once. Exclude target-source fields;
report per-source metrics and, if data permit, a separate leave-one-source-out
stress test. Candidate metrics are PR-AUC/average precision, precision@K,
recall@K, secondary ROC-AUC, Brier/calibration, and per-type/source results
where sample sizes support them. No split dates or metrics are fabricated for
the current unlabeled dataset.

## 8. Current implementation status

| Component | Status | Evidence |
| --- | --- | --- |
| URLhaus research preparation | Implemented | `research_data/urlhaus/normalize.py`, `metadata.json`, and `research_data/profile.py` |
| ThreatFox acquisition/normalization workflow | Partially implemented | `research_data/threatfox/fetch.py`, `normalize.py`, `profile.py`; metadata says `not_collected` |
| Unified research schema | Design only | `research_data/unified/schema.py` and `README.md` |
| Research source adapters | Implemented | `research_data/sources/`; URLhaus and ThreatFox adapters map one normalized record to one provenance-preserving observation |
| Research entity resolution | Implemented | `research_data/entity_resolution/resolver.py`; executed on the real URLhaus snapshot |
| Research correlation/context aggregation | Implemented | `research_data/correlation/correlate.py`; executed on URLhaus-only entities; no cross-source result |
| Multi-source research pipeline | Partially implemented | `research_data/pipeline/run_urlhaus.py`; both adapters are orchestrated, but the real run included URLhaus only because ThreatFox is not collected |
| Research feature dataset | Implemented | `research_data/features/build_features.py`, `feature_schema.json`, and `urlhaus_feature_profile.json`; 14,354 URLhaus rows, no target |
| A/B/C experiment dataset assembly | Implemented | `research_data/experiments/build_datasets.py`; three aligned 14,354-row outputs, all target status unknown |
| Supervised target/evaluation specification | Partially implemented | `research_data/features/experiment_spec.json` and `research_data/targets/target_schema.json`; target unavailable, builder infrastructure tested synthetically, no real labels/model/evaluation |
| Future-outcome target builder | Implemented (research infrastructure only) | `research_data/targets/build_targets.py`; synthetic tests only, no real outcome data or target rows |
| IOC ingestion and normalization | Implemented | `backend/app/ingestion/`, `backend/app/normalization/`, and IOC services |
| Exact IOC deduplication and observations | Implemented | `backend/app/services/ioc_service.py` and database models |
| Observation-based source correlation | Partially implemented | `backend/app/services/ioc_correlation.py`; summarizes sources for an existing IOC |
| Research threat-context aggregation | Implemented | `research_data/correlation/correlate.py`; preserves per-observation context and reports distinct values/conflicts |
| Enrichment and deterministic risk scoring | Implemented | `backend/app/enrichment/` and `backend/app/scoring/` |
| Feature engineering | Partially implemented | `backend/app/features/ioc_features.py`; produces a feature vector, not model predictions |
| Threat-context correlation | Partially implemented | Current IOC context includes a stored threat type; no cross-source context graph is implemented |
| ML prioritization | Partially implemented | `research_data/ml/`; two baseline classifiers run on a controlled synthetic benchmark only; no real labeled-data model or prediction service |
| Explainability | Partially implemented | Production deterministic score breakdown plus synthetic-only model contributions in `research_data/ml/explainability/`; no real-world validation or production integration |
| Analyst dashboard | Implemented | `frontend/src/App.jsx` and investigation components |
| Experimental evaluation | Pending | No evaluation protocol/results in the repository |

## 9. Reproducibility

Run commands from the repository root unless a different working directory is
shown. Use the project’s configured Python/Node environments.

**Research data scripts:**

```powershell
python research_data/urlhaus/normalize.py
python research_data/profile.py
python -m research_data.pipeline.run_urlhaus
python -m research_data.features.build_features
python -m unittest research_data.targets.tests.test_build_targets
```

Feature preparation tests are under `research_data/features/tests/` and can be
run with `python -m pytest research_data/features/tests` when pytest is
available.

Run experiment-dataset assembly and its focused tests with:

```powershell
python -m research_data.experiments.build_datasets
python -m unittest research_data.experiments.tests.test_build_datasets
python -m research_data.ml.build_benchmark
python -m research_data.ml.train_baselines
python -m unittest research_data.ml.tests.test_baselines
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
- The current pipeline run uses URLhaus only. The adapters, resolver, and
  correlation layer are connected by the multi-source pipeline, but have not
  yet been run on real records from multiple sources; cross-source agreement
  has not been empirically demonstrated.
- There is no model trained or evaluated on validated real CTI labels, no
  production prediction service, and no real-world-validated XAI. Synthetic
  model contributions and baseline metrics are pipeline checks only; SHAP was
  not used.
- There is no validated supervised target; the current feature rows intentionally
  retain null targets.
- The target builder cannot produce real labels until independent, timestamped
  outcome adjudication and complete seven-day follow-up coverage data are acquired.
- URLhaus's exact acquisition URL/command is absent from its committed
  metadata.
- The unified schema has not been validated against real ThreatFox records or
  the acquired ThreatFox type catalogue.

## 11. Next research milestone

Acquire a documented recent ThreatFox sample with `THREATFOX_AUTH_KEY`, then
empirically validate its fields and IOC-type catalogue before using the
multi-source research pipeline on real records. Separately, acquire a licensed
independent outcome source with timestamped adjudication and complete coverage
before attempting supervised training or evaluation.

## 12. Analyst-facing research overview

The CTIP application exposes generated research status through the read-only
`GET /api/v1/research/overview` endpoint and its **Research & AI** view. It reads
the URLhaus feature and experiment profiles, synthetic baseline results,
synthetic explanation metadata, and ThreatFox collection metadata. If generated
artifacts are unavailable, the API identifies that state instead of inventing
counts or metrics. Real URLhaus data and controlled synthetic benchmark results
are presented in separate sections; every displayed benchmark metric is labeled
as a synthetic benchmark result. This presentation does not change the
production deterministic IOC risk scorer or turn synthetic outputs into
real-world IOC predictions. The IOC investigation workflow also surfaces
read-only research metadata and explains how operational observations, source
diversity, and threat context relate to research feature groups. It does not
generate an IOC-level research prediction; production scoring remains
deterministic.

## 13. Final demo implementation status

Steps 1–11 provide the controlled feed-ingestion workflow, operational IOC
submission/search/investigation, observation-based source correlation,
deterministic risk explanation, and the Research & AI overview/context. The
investigation response exposes research metadata only; it does not generate a
research feature vector or prediction for the operational IOC. Production risk
continues to come from the deterministic CTIP risk engine.

The real research run remains URLhaus-only: 14,354 records and zero real
supervised labels. The 600-sample benchmark and its model-derived feature
contributions are controlled synthetic research artifacts. ThreatFox remains
`not_collected`; cross-source behavior has not been empirically demonstrated
on real records. See `DEMO_CHECKLIST.md` for startup requirements, the
recommended evaluator sequence, sample-feed behavior, expected research
figures, and known environment constraints.

The production analyst workflow also provides deterministic mitigation
recommendations, local CVE identifier parsing without CVSS claims, a small
rule-based ATT&CK-style tactic map, and dependency-free rule-based IOC
extraction from analyst text. Controlled feeds accept JSON and CSV. A research
`TaxiiSourceAdapter` contract is available, but there is no live TAXII client,
full STIX integration, or external NVD/Wazuh/OpenSearch connection.

## 14. Final synopsis-alignment status

| Capability | Status | Evidence / limitation |
|---|---|---|
| Controlled CTI collection, normalization, IOC analysis, observations | IMPLEMENTED | Local JSON/CSV feed ingestion, PostgreSQL IOC processing, and observation history. |
| Source correlation, enrichment, dashboard, deterministic explainable risk | IMPLEMENTED | Operational API and analyst UI; risk remains the deterministic CTIP formula. |
| Mitigation recommendations | IMPLEMENTED | Rule-based, reasoned analyst guidance; CTIP does not take defensive action. |
| Analyst-text IOC extraction | IMPLEMENTED | Regex rules return typed values and positions; it is not transformer NLP. |
| CVE/CVSS context | PARTIAL | CVE identifier/year/number parsing only; no live NVD or CVSS data. |
| ATT&CK context | PARTIAL | Rule-based tactic categories only; no complete ATT&CK data or fabricated technique IDs. |
| A/B/C real-data feature configurations | RESEARCH-VALIDATED | 14,354 URLhaus feature rows, 20/28/44 features, and zero real supervised labels. |
| Supervised benchmark and model-derived contributions | RESEARCH-VALIDATED | Controlled 600-sample synthetic benchmark only; no real-world performance claim. |
| ThreatFox acquisition and TAXII | INTEGRATION-READY | ThreatFox workflow requires `THREATFOX_AUTH_KEY` and no real data is collected; TAXII is an interface contract only. |
| Full STIX ecosystem, NVD, ATT&CK, Wazuh/OpenSearch, transformer NLP, GNN | FUTURE | These integrations/models are not implemented or connected. |
| Real supervised evaluation and production ML scoring | FUTURE | Requires independently validated real outcomes; production scoring remains deterministic. |

## 15. Operational URLhaus demo subset

The operational CTIP dashboard can be seeded from the existing normalized
URLhaus artifact at `research_data/urlhaus/urlhaus_normalized.json`. That source
contains 14,354 normalized real URLhaus records; it is not modified by seeding.
The deterministic selection utility defaults to 50 records and favors distinct
hosts, new observed tags, balanced URL status, and reporter diversity, then
uses stable source fields to break ties. It does not randomize or create
records. Its dry-run against the local artifact selected 50 records covering
50 hosts, 25 online and 25 offline URLs, and 174 distinct tags.

The reset/seed command is limited to the loopback PostgreSQL database named
`ctip`, and deletes only operational IOC and observation rows before loading
the subset through the existing `process_ioc()` ingestion path. Re-running
without reset deduplicates the same typed IOC identities and records additional
observations. The source is stored as `URLhaus`; actual URLhaus threat context
and tags are retained. Its `date_added` uses the existing CTIP first-seen and
observation timestamp fields; when present, `last_online` uses CTIP last-seen.
If `last_online` is absent, the service's actual import-observation time remains
last-seen rather than an inferred source timestamp. The production schema has
no separate reporter,
URLhaus-ID, reference, or URL-status fields; these remain available in the
research artifact.

URLhaus does not supply confidence or severity labels. The operational IOC
schema's existing defaults (confidence 50, severity `medium`) are used only to
calculate the deterministic production risk display. They are not measured
URLhaus labels, CVSS values, or model predictions. This roughly 50-record
historical dashboard subset is distinct from the full research dataset (14,354
records), research feature space (14,354 × 44), zero real supervised labels,
and the separate 600-sample synthetic benchmark. The dashboard does not call
the records live intelligence.
