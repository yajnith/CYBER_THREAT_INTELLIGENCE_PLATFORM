# Experiment dataset assembly

`build_datasets.py` combines deterministic feature rows with optional
three-state target-builder output. It does not train a model, evaluate
predictions, or infer labels.

## Identity and joining

Rows are matched only by `(ioc_type, normalized_ioc_value)`. Matching ignores
neither IOC type nor normalized value. A feature identity without a target row
is emitted with `target: "unknown"`. Target-only identities are counted in the
profile and are not emitted as feature rows.

Exact duplicate feature or target rows collapse. If duplicate rows for one
typed identity differ in any value, assembly fails; it never chooses a winner
by input order. Outputs sort by the typed identity, so all three experiments
have the same stable row order.

## Inputs and feature groups

The feature input is the output of `research_data/features/build_features.py`.
An optional target input is the output of `research_data/targets/build_targets.py`.
Feature columns come from `research_data/features/feature_schema.json`:

- A contains only group A IOC features.
- B contains groups A and B.
- C contains groups A, B, and C.

Target, target reason, prediction window, and outcome evidence are metadata,
never model input columns. Source provenance and source context assertions are
preserved outside the feature map. If a target evidence source also appears in
the feature provenance for that identity, assembly stops; feature rows must
first be rebuilt without that source's assertions. URLhaus's single-class
`threat` field is not used as the target.

## Run

From the repository root:

```powershell
python -m research_data.experiments.build_datasets
```

Pass `--targets path/to/target_rows.json` when independent target rows are
available. Current output JSON datasets are written to
`research_data/urlhaus/urlhaus_experiment_A.json`, `_B.json`, and `_C.json`;
the existing Git ignore rule excludes them. The tracked profile at
`urlhaus_experiment_profile.json` records counts, source coverage, class
balance, input/output SHA-256 digests, and whether a target input was present.

## Current real URLhaus run

The current feature input contains 14,354 unique typed identities. No real
target rows were supplied, so each experiment has 14,354 unknown targets, zero
positive labels, and zero negative labels. A/B/C contain 20/28/44 feature
columns respectively. These are prepared unlabeled datasets, not model or
evaluation results.
