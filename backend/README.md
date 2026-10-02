# Local CTI feed ingestion demo

Configure PostgreSQL through `backend/.env` (`DATABASE_URL`), then start the
API from the `backend` directory using the project's installed dependencies:

```powershell
uvicorn app.main:app --reload
```

Place a JSON array of IOC records in `backend/feeds/`. Each filename stem is
the feed ID; the API only reads `.json` files from that directory. To ingest
the included sample feed from another terminal:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/ingestion/feeds/sample_cti_feed
```

The response reports processed records, new versus existing IOCs, and
observations created. Re-ingesting a feed reuses IOC records while recording
new observations. Invalid JSON is rejected with a parse error; invalid IOC
records include their record index and validation message. Arbitrary filesystem
paths are not accepted.
