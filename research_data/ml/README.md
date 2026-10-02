# First ML baseline pipeline (controlled synthetic data)

This step validates the CTIP experiment path only. **The benchmark labels and
all metrics are synthetic; they are not URLhaus ground truth or real-world
performance.** The real URLhaus experiment rows still have 14,354 unknown
targets and are never used for supervised fitting.

## Reproduce

From the repository root:

```powershell
python -m research_data.ml.build_benchmark
python -m research_data.ml.train_baselines
python -m unittest research_data.ml.tests.test_baselines
```

The deterministic benchmark uses seed `8137` with 300 positive and 300
negative rows. It has explicit dataset metadata: synthetic, controlled,
non-ground-truth, and not derived from human-validated URLhaus labels. Labels
come from a balanced latent class with overlapping, noisy class-conditional
feature distributions. No CTIP risk score threshold generates labels, and the
target or a label-generation indicator is not included in model features.

Any generated `source_threatfox` feature value exists only as a synthetic
schema fixture; it is not a ThreatFox observation and makes no claim that a
local ThreatFox dataset exists.

Feature columns come unchanged from
`research_data/features/feature_schema.json`: A uses group A, B uses A+B, and
C uses A+B+C. The script fits feature encoding, median imputation, and scaling
on training rows only. It uses a deterministic stratified 75/25 train/test
split (seed `2026`) and runs Logistic Regression and Gaussian Naive Bayes for
each experiment. Metrics are accuracy, precision, recall, F1, and ROC-AUC.

The environment does not have scikit-learn. The module therefore uses small,
dependency-free reference implementations of those two baseline algorithms;
it does not install packages. Results are written to
`synthetic_baseline_results.json`; each result is labeled
`SYNTHETIC BENCHMARK RESULT` and carries its dataset/split/model metadata.
`model_schema.json` defines the benchmark and result contract.

The training entry point accepts only the explicitly marked controlled
synthetic benchmark. Passing real URLhaus experiment data fails with a clear
message; unknown targets are never converted to negative labels. No model is
connected to the production risk scorer. SHAP/XAI and production integration
are outside this step.

## Measured synthetic results

Every value below is a **SYNTHETIC BENCHMARK RESULT** from the fixed 150-row
test set. These numbers do not measure URLhaus or real-world CTI performance.

| Experiment | Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| A | Logistic Regression | 0.653333 | 0.632184 | 0.733333 | 0.679012 | 0.696178 |
| A | Gaussian Naive Bayes | 0.680000 | 0.675325 | 0.693333 | 0.684211 | 0.694400 |
| B | Logistic Regression | 0.726667 | 0.717949 | 0.746667 | 0.732026 | 0.820444 |
| B | Gaussian Naive Bayes | 0.700000 | 0.687500 | 0.733333 | 0.709677 | 0.782222 |
| C | Logistic Regression | 0.900000 | 0.875000 | 0.933333 | 0.903226 | 0.953956 |
| C | Gaussian Naive Bayes | 0.846667 | 0.802326 | 0.920000 | 0.857143 | 0.935644 |

These are recorded measurements of the generated benchmark only. The
class-conditional feature distributions are deliberately controlled, so metric
differences cannot support a conclusion that context improves real CTI
prioritization.

## Model explanations (Step 9)

Run the deterministic explanation pass with:

```powershell
python -m research_data.ml.explainability.explain
python -m unittest research_data.ml.explainability.tests.test_explain
```

It refits the existing baseline implementations with the same benchmark and
split seeds as Step 8. Encoded feature values are used because those are the
values passed to each model. For Logistic Regression, feature contribution is
`x_j * beta_j`; the contributions sum with the intercept to the model log-odds.
For Gaussian Naive Bayes, contribution is the per-feature log-likelihood ratio
`log p(x_j | positive) - log p(x_j | negative)`; these sum with log prior odds
to the model log-odds. Positive contributions push toward the positive class,
negative contributions toward the negative class. In both cases, the sum
reconstructs the model's probability.

Local explanations include the predicted class/probability, the base log-odds,
top positive and negative feature contributions, encoded values, and group
contributions. For every experiment/model, examples are selected mechanically:
the first held-out example in deterministic split order predicted positive and
the first predicted negative, irrespective of correctness or contribution
magnitude. This avoids selecting cases based on favorable outcomes.

Global model feature contribution ranks encoded columns by mean absolute
contribution over the full synthetic test set; mean signed and summed absolute
contributions are also retained. Group analysis maps existing columns to IOC
intrinsic, observation, correlation, provenance/source, and threat-context
families. Observation counts/repeats belong to observation; source-diversity
counts to correlation; source flags, reporters, and confidence-source count to
provenance/source; remaining C-group context and temporal fields to threat
context. Only groups represented in an experiment are emitted.

These are **model feature contributions / model-derived feature importance**,
not causal importance. Correlation describes measured association; feature
contribution describes how a fitted model's score changes under its additive
decomposition; neither establishes causality. These explanations describe
model behavior on the controlled synthetic benchmark. They do not establish
causal relationships and do not demonstrate real-world threat attribution.
No SHAP was used, and no unknown-target URLhaus rows were explained as
supervised predictions. Artifact: `explainability/synthetic_explanations.json`.
