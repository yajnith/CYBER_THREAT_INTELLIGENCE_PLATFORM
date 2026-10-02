# Research feature preparation

This module converts the existing correlation-summary artifact into a fixed,
deterministic feature representation. It is research/ML preparation only: it
does not train a model, predict threat, score risk, assign labels, or choose a
ground-truth target.

Run it from the repository root after generating the correlation output:

```powershell
python -m research_data.features.build_features
```

Defaults:

- Input: `research_data/unified/research_pipeline_results.json`
- Feature rows: `research_data/urlhaus/urlhaus_research_features.json` (ignored
  under the existing URLhaus JSON ignore rule)
- Compact reproducibility profile:
  `research_data/features/urlhaus_feature_profile.json`
- Machine-readable column contract: `research_data/features/feature_schema.json`

The row has four separate parts: `entity_identity`, `features`,
`source_provenance`, `raw_context_assertions`, plus `target: null`. The
normalized IOC value is retained only as an entity join key. The model-facing
IOC representation uses IOC type, value length, and character-shape counts;
it does not expose the raw IOC string as a text feature. Provenance identifies
each source observation by source, record ID, reference, and reporter. Original
source-specific payloads remain in the input correlation artifact and are not
mutated by feature generation. Context assertions remain source-specific in
the row and are not collapsed into a selected truth claim.

## Feature groups and experiments

| Experiment | Features |
| --- | --- |
| A: IOC-only | IOC type, safe value-shape features, value length, and type indicators. |
| B: IOC + observation/correlation | Experiment A plus observation count, distinct source count, multi-source indicator, source diversity ratio, repeated-observation indicator, source indicators, and distinct reporter count. |
| C: IOC + observation/correlation + threat context | Experiment B plus distinct threat/family counts, context availability/richness, tag counts, confidence summaries, and correlation-layer temporal summaries. |

These are input-feature groups for future comparisons, not trained experiments
or model results. `source_diversity_ratio` is distinct source count divided by
observation count. `repeated_observation` is true when observations outnumber
distinct sources; observations are not deduplicated. `tag_count` counts tag
occurrences across observations, while `distinct_tag_count` counts the
correlation layer's tag union.

Temporal features use only `first_seen`, `last_seen`, and
`observation_timestamp` values already processed by the correlation layer.
URLhaus `date_added` and `last_online` are not reinterpreted as seen times.
Temporal features remain empty on the current URLhaus-only run. Future use of
absolute timestamps requires a documented prediction cutoff to avoid temporal
leakage.

## Target and leakage policy

- Every generated row has `target: null`; no label is defined or inferred.
- URLhaus `threat` is `malware_download` for all current records, so it is not a
  valid multi-class supervised target.
- No future outcome or URL status feature is generated.
- No deterministic CTIP `risk_score` is included. If used in a future
  experiment, it must be declared a rule-based baseline/reference and must not
  be treated as ground truth; training on it would reproduce the scoring rule.
- Raw assertions, aggregate features, and any future target are separate
  concepts. Feature generation currently creates only the first two.

## Supervised target and evaluation design

The prediction task is framed as **context-aware CTI threat prioritization**:
at an entity cutoff time `t`, estimate whether an independently validated
harmful-activity outcome occurs for that typed IOC entity during the following
7 days. This is a proposed future target definition only. A positive would
require a timestamped independent confirmation during `(t, t + 7 days]`; a
negative would require explicit independent non-harmful adjudication plus
documented follow-up coverage through the full horizon. Missing, conflicting,
or incompletely observed outcomes remain unknown and are excluded, not changed
to negative. No such validation/outcome labels or coverage are present now:
**Target not currently available.** No target strategy is selected or
preferred on current evidence.

Target candidates considered are documented in
`experiment_spec.json`:

- Source-reported threat type is available in URLhaus but is single-class
  (`malware_download`) and is not a useful current multiclass target. A source
  label also cannot be both target and input.
- Deterministic CTIP risk level is a rule output, not ground truth. It may only
  be shown as a clearly named rule-based baseline; learning it would copy the
  scoring rule.
- Future outcomes could be suitable with independent timestamped adjudication
  and complete follow-up; those data do not exist in this repository.
- Multi-source consensus is unavailable without real multi-source data and is
  derived from the same source-count/agreement features it would label.
- An independent validated external label may be useful after its provenance,
  timing, coverage, and definitions are verified; none is currently present.

Target preparation is implemented in `research_data/targets/build_targets.py`,
with the machine-readable input/output contract in
`research_data/targets/target_schema.json`. The builder accepts typed
identities separately from outcome assertions and emits one three-state row
per distinct identity. It retains every matching assertion with source, record
ID, reference, timestamps, and decision disposition. Explicit
`supersedes_assertion_ids` can resolve a conflict; without a clear superseding
adjudication, contradictory evidence remains unknown. Assertions marked
`independent_validation: false` are retained but cannot determine a target.

The builder has only been tested on synthetic unit fixtures. It has not been
run against the real URLhaus feature rows as if they had labels, and no real
positive, negative, or unknown counts are claimed. The current real feature
artifact remains unlabeled (`target: null`). Run its tests with:

```powershell
python -m unittest research_data.targets.tests.test_build_targets
```

The target-preparation infrastructure is implemented in
`research_data/targets/build_targets.py`, with the input/output contract in
`research_data/targets/target_schema.json`. Its function accepts typed entity
identities separately from outcome assertions and emits one three-state target
row per distinct identity. Every assertion is retained with its source,
record ID, reference, timestamps, and decision disposition. Explicit
`supersedes_assertion_ids` can resolve a conflict; without a clear superseding
adjudication, conflicting statuses remain unknown. Assertions marked
`independent_validation: false` are preserved but cannot determine a label.

This infrastructure has been tested only on synthetic unit fixtures. It has
not been run against the URLhaus feature rows as if they had outcomes, and no
real positive, negative, or unknown counts are claimed. The current real
feature artifact remains unlabeled (`target: null`).

### Future split and metrics

Construct features only from evidence available at or before cutoff `t`, then
measure outcomes in the seven-day horizon. Use chronological train, validation,
and held-out test periods with a purge/embargo of at least the target horizon.
Group by `(ioc_type, normalized_ioc_value)` before assignment: all repeats and
cross-source observations for one typed identity stay in a single partition.
Do not allow entity snapshots or source records to cross partitions. Keep
unknown/censored outcomes out of binary evaluation. Fit encoders, imputers,
feature selection, calibration, and thresholds on training data only. Report
per-source results and consider a separate leave-one-source-out stress test
only after additional sources are available.

If valid labels become available, report average precision/PR-AUC, precision@K,
recall@K, ROC-AUC as a secondary metric, Brier score/calibration, and
per-type/per-source results where sample sizes allow. No metric is calculated
now. The split dates must be chosen from actual labeled-data coverage; they are
not fabricated for the current URLhaus snapshot.

Experiments A/B/C use the same target definition, sample eligibility rules,
cutoffs, horizon, and splits. A uses IOC-only features; B adds observation and
correlation features; C adds threat context that is available by `t` and does
not come from the target-label source. The intended comparison is incremental
feature value, not a completed model result. See `experiment_spec.json` for the
machine-readable protocol.

## Current real URLhaus profile

The local normalized/correlated URLhaus run produced **14,354 feature rows**
with **44 feature columns**. All rows are URLs from URLhaus, with one
observation and one distinct source per row. All rows have one threat type and
zero malware-family or confidence values. Generic correlation timestamps are
missing for every row; source-specific URLhaus dates remain in the original
source observations, not the temporal feature group. Context richness is 1 or
2 (threat type, and tags when present). See `urlhaus_feature_profile.json` for
exact missingness and descriptive distributions from the latest run.

The feature tests use small synthetic in-memory entities only. They do not add
synthetic or ThreatFox records to the research datasets.

## Experiment dataset assembly

The preparation layer in `research_data/experiments/build_datasets.py` joins
feature rows to optional target-builder rows only by
`(ioc_type, normalized_ioc_value)`. It produces A/B/C datasets over the same
deterministically ordered entity set, selecting columns from the declared
feature groups. A missing target row becomes `unknown`, never negative. Target
reason, prediction window, and outcome evidence remain in `target_metadata`,
outside model-facing `features`; source provenance and context assertions are
also preserved separately. Exact duplicate input rows collapse. Conflicting
duplicates fail instead of choosing a label or feature vector arbitrarily.
If an outcome evidence source also appears in that entity's feature provenance,
assembly fails so target-source evidence cannot silently enter A/B/C inputs.

Run from the repository root:

```powershell
python -m research_data.experiments.build_datasets
```

Supply a target-builder JSON output with `--targets` when independently
validated target rows exist. Current real outputs are ignored JSON files under
`research_data/urlhaus/urlhaus_experiment_{A,B,C}.json`. The compact profile is
`research_data/experiments/urlhaus_experiment_profile.json`, and the output row
contract is `research_data/experiments/experiment_dataset_schema.json`. The
current URLhaus run contains no outcome rows, so every target is unknown and no
model or evaluation is run.
