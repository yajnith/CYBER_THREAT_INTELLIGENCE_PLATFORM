# Multi-source CTI research pipeline

Run the real normalized URLhaus snapshot and, when available, the normalized
ThreatFox snapshot through the existing source adapters, typed entity
resolution, and deterministic correlation/context layer:

```powershell
python -m research_data.pipeline.run_urlhaus
```

The pipeline always requires `research_data/urlhaus/urlhaus_normalized.json`.
It also checks for `research_data/threatfox/threatfox_normalized.json`. If that
file exists, its real normalized records are passed to `ThreatFoxAdapter`; if
it does not, ThreatFox is omitted and the run metadata records its status from
`research_data/threatfox/metadata.json` (currently `not_collected`). No
ThreatFox records or cross-source findings are inferred when the file is
absent.

Each normalized record is mapped through its source adapter, then the existing
resolver groups observations only by `(ioc_type, normalized_ioc_value)`. The
correlation layer calculates deterministic source, context, confidence, and
temporal summaries. All source observations remain embedded in the output with
their source record IDs, references, reporters, timestamps, and source-specific
fields. Repeated same-source records are retained as separate observations.

The pipeline writes detailed per-entity results to
`research_data/unified/research_pipeline_results.json`, which is ignored by
Git, and a compact run profile to
`research_data/pipeline/urlhaus_pipeline_metadata.json`. The metadata includes
per-source record counts/status, input hashes, identity rule, coverage, and
whether more than one source dataset was actually included.

To use a different input/output location:

```powershell
python -m research_data.pipeline.run_urlhaus `
  --input path\to\urlhaus_normalized.json `
  --threatfox-input path\to\threatfox_normalized.json `
  --output path\to\results.json `
  --metadata path\to\run_metadata.json
```

The optional ThreatFox path is used only when it exists. The default execution
does not fetch either source or modify source datasets.
