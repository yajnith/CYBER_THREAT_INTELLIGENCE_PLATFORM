# ThreatFox research data

This folder uses the documented [ThreatFox Community API](https://threatfox.abuse.ch/api/).
The recent IOC query is `POST https://threatfox-api.abuse.ch/api/v1/` with
`{"query":"get_iocs","days":7}`; the API documents a 1–7 day range. The API
requires an `Auth-Key`, available free through the [abuse.ch authentication
portal](https://auth.abuse.ch/). The downloader also requests the documented
`query=types` catalogue so unknown IOC types can be profiled against ThreatFox's
published list.

Set the key in the current shell; do not put it in source code or commit it:

```powershell
$env:THREATFOX_AUTH_KEY = "your-personal-auth-key"
python -m research_data.threatfox.fetch --days 7
```

The command saves the API responses as `threatfox_raw.json` and
`threatfox_types.json`, writes `threatfox_normalized.json`, and refreshes
`metadata.json`. Raw and normalized JSON exports are ignored by Git. To
re-normalize and profile an existing local acquisition without making an API
request, run:

```powershell
python -m research_data.threatfox.profile
```

`get_iocs` provides only the requested recent window, not the full historical
ThreatFox corpus. The normalizer retains the documented IOC, type and
description, threat type, malware family context, confidence, timestamps,
reporter, reference, and tags; unrecognized returned fields are retained in
`additional_fields`. Source timestamps and references remain verbatim.
