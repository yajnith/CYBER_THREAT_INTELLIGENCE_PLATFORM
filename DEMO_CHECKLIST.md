# CTIP evaluator demo checklist

## Start the application

1. Start PostgreSQL and create/select the intended development database. Configure
   `backend/.env` with `DATABASE_URL`; the API creates/uses the production CTIP
   tables at startup. Do not point a demo run at a valuable database.
2. Start the API in a terminal:

   ```powershell
   Set-Location backend
   uvicorn app.main:app --reload
   ```

3. In a second terminal, start the frontend:

   ```powershell
   Set-Location frontend
   npm run dev
   ```

   The frontend expects the API at `http://127.0.0.1:8000` and Vite at its
   default local development port.

## Prepare the operational demo database

The primary dashboard dataset is a deterministic 50-record subset of the
existing normalized URLhaus research artifact. It is historical stored CTI,
not a live feed. Preview the selection and then reset only the local operational
IOC/observation tables before seeding:

```powershell
Set-Location 'E:\Major Project\CYBER_THREAT_INTELLIGENCE_PLATFORM-main'
python -m research_data.urlhaus.seed_demo --dry-run
python -m research_data.urlhaus.seed_demo --reset-demo-db --limit 50
```

The reset command is guarded to the loopback PostgreSQL database named `ctip`.
It deletes IOC and observation rows only; it does not delete research artifacts,
feed files, or automated test fixtures. Verify `backend/.env` points to the
intended local demo database before running it. The selection comes from
`research_data/urlhaus/urlhaus_normalized.json` (14,354 records), favors
distinct hosts, tag diversity, balanced URL status, and reporter diversity,
then breaks ties by stable source fields. Re-running without
`--reset-demo-db` reuses the same IOC identities and creates new observations.

URLhaus `date_added` is preserved in CTIP's first-seen and observation timestamp
fields; when present, `last_online` is preserved in CTIP's last-seen field. If
`last_online` is absent, the service's actual import observation time remains
as last-seen rather than inferring a source timestamp.
Threat type and tags are retained. URLhaus does not supply confidence or
severity, so CTIP's existing defaults (50 confidence and medium severity) are
used for deterministic risk display; these are not URLhaus labels or CVSS
values. Reporter, URLhaus ID, reference URL, and URL status remain in the
untouched research artifact rather than separate operational database fields.

## Recommended demonstration sequence

1. Open **Dashboard** and show the **Operational CTI Dataset · URLhaus demo
   subset** provenance banner, IOC summary, risk distribution, and source count.
   Clarify that this is historical data, not a live feed.
2. Open **IOC Intelligence** and investigate one URL from the seeded dashboard.
   Show its URL type, URLhaus source observation, actual malware-download threat
   context, available tags, source timestamps, enrichment, deterministic risk,
   and explanation. Confidence/severity use CTIP's schema defaults because
   URLhaus does not supply those fields.
3. Open **IOC Search** and search for the same URL to show the stored indicator.
4. From the investigation's **Research & AI Context**, open **Research & AI**.
   Show URLhaus real-data statistics separately from the controlled synthetic
   benchmark and its model-derived feature contribution examples.
5. Open **CTI Feed Ingestion** and optionally ingest `sample_cti_feed`. On a
   clean database, five feed records represent four IOC identities: the repeated
   domain is matched to the existing IOC and receives a second-source
   observation. The first run therefore reports four new, one existing, and
   five observations. The controlled sample feed remains separate from the
   primary URLhaus subset.
6. Return to **Dashboard** and show refreshed stored IOC data.
7. In **IOC Search**, paste a short analyst note and run **Rule-based IOC
   extraction**. Review candidate types and text offsets; extraction does not
   submit them.
8. Optionally ingest `sample_cti_csv` to demonstrate CSV parsing and repeated
   observations from two source names.
9. In an IOC investigation, show analyst recommendations as guidance only.
   CVEs receive local identifier parsing but no CVSS lookup; ATT&CK-style
   categories come from a small rule map.

## Research facts to state clearly

- Real URLhaus dataset: **14,354 records**.
- Real URLhaus supervised labels: **0**; real supervised labels are unavailable.
- Feature profile: **14,354 rows**, with experiments A/B/C using **20/28/44**
  features.
- Controlled synthetic benchmark: **600 synthetic samples**, balanced
  **300/300**; these results are not URLhaus or real-world performance.
- ThreatFox real data has **not** been collected.
- Production IOC risk is calculated by the deterministic CTIP risk engine.
- Synthetic benchmark outputs and model-derived feature contributions do not
  predict or explain an individual production IOC, and are not causal evidence.

## Known environment requirements and limitations

- PostgreSQL and a valid `backend/.env` `DATABASE_URL` are required by the
  backend. Keep research artifacts out of the production database.
- Installations should use their already configured Python and Node/npm
  environments; do not install dependencies during the demo.
- In the environment used for this hardening pass, the backend virtual
  environment launcher pointed to a missing absolute Python installation and
  the global npm launcher was broken. Verification used the bundled Python/Node
  runtimes and existing project packages. A machine with the same stale paths
  may need its normal development runtimes repaired before launching the app.
- The frontend API origin is currently fixed to `127.0.0.1:8000`.
- ThreatFox, a validated real outcome target, a real-label-trained model, and
  production ML scoring are not available.
- IOC extraction is rule-based, not transformer NLP; candidates require review.
- TAXII is an interface contract only; there is no live client or full STIX integration.
- CVE context has no live CVSS enrichment and recommendations do not execute
  defensive actions.

## Synopsis alignment status

| Capability | Status | Evidence / limitation |
|---|---|---|
| Controlled JSON/CSV IOC feeds and analyst workflow | IMPLEMENTED | Bounded local feed directory, IOC processing, observations, and dashboard refresh. |
| Mitigation guidance and rule-based IOC extraction | IMPLEMENTED | Investigation guidance and analyst-note candidates; no automated actions or NLP model. |
| CVE/CVSS | PARTIAL | Local CVE parsing works; no NVD query or CVSS score. |
| ATT&CK | PARTIAL | Tactic-style keyword mapping only; no technique IDs or full integration. |
| A/B/C and synthetic model explainability | RESEARCH-VALIDATED | Research artifacts and controlled benchmark; real supervised labels are unavailable. |
| ThreatFox/TAXII/STIX/external telemetry | INTEGRATION-READY | ThreatFox credential required; TAXII contract only; full STIX and Wazuh/OpenSearch are not connected. |
| Real-label ML evaluation / production ML | FUTURE | No validated real outcome labels; production scoring remains deterministic. |
