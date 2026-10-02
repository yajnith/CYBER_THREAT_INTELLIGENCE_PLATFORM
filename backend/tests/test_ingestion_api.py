import json
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.database.database import SessionLocal
from app.database.models import IOC, IOCObservation
from app.api import ingestion as ingestion_api


@pytest.fixture
def api_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def remove_test_iocs(values):
    db = SessionLocal()
    try:
        iocs = db.query(IOC).filter(IOC.normalized_value.in_(values)).all()
        ioc_ids = [ioc.id for ioc in iocs]
        if ioc_ids:
            db.query(IOCObservation).filter(
                IOCObservation.ioc_id.in_(ioc_ids)
            ).delete(synchronize_session=False)
            db.query(IOC).filter(IOC.id.in_(ioc_ids)).delete(
                synchronize_session=False
            )
            db.commit()
    finally:
        db.close()


def test_feed_ingestion_reports_new_and_duplicate_counts(
    api_db,
    monkeypatch,
    tmp_path,
):
    token = uuid4().hex
    values = [f"feed-one-{token}.example", f"feed-two-{token}.example"]
    records = [
        {
            "indicator_type": "domain",
            "value": value,
            "source": "pytest_json_feed",
            "threat_type": "malware",
            "confidence": 80,
            "severity": "high",
            "tags": ["pytest"],
        }
        for value in values
    ]
    (tmp_path / "demo.json").write_text(json.dumps(records), encoding="utf-8")
    monkeypatch.setattr(ingestion_api, "FEED_DIR", tmp_path)

    try:
        first = ingestion_api.ingest_feed("demo", api_db)
        assert first == {
            "feed_id": "demo",
            "source_file": "demo.json",
            "records_processed": 2,
            "new_iocs": 2,
            "existing_iocs": 0,
            "observations_created": 2,
            "errors": [],
        }

        second = ingestion_api.ingest_feed("demo", api_db)
        assert second == {
            "feed_id": "demo",
            "source_file": "demo.json",
            "records_processed": 2,
            "new_iocs": 0,
            "existing_iocs": 2,
            "observations_created": 2,
            "errors": [],
        }

        db = SessionLocal()
        try:
            assert db.query(IOC).filter(IOC.normalized_value.in_(values)).count() == 2
            assert db.query(IOCObservation).join(IOC).filter(
                IOC.normalized_value.in_(values)
            ).count() == 4
        finally:
            db.close()
    finally:
        remove_test_iocs(values)


def test_feed_ingestion_rejects_invalid_json_records(
    api_db,
    monkeypatch,
    tmp_path,
):
    (tmp_path / "invalid.json").write_text(
        json.dumps([{"indicator_type": "not-an-ioc-type", "value": "bad"}]),
        encoding="utf-8",
    )
    monkeypatch.setattr(ingestion_api, "FEED_DIR", tmp_path)

    with pytest.raises(HTTPException) as error:
        ingestion_api.ingest_feed("invalid", api_db)

    assert error.value.status_code == 422
    assert "Invalid IOC record at index 0" in error.value.detail


def test_feed_ingestion_rejects_paths_outside_feed_directory(api_db):
    with pytest.raises(HTTPException) as error:
        ingestion_api.ingest_feed("../.env", api_db)

    assert error.value.status_code == 400


def test_csv_feed_ingestion_deduplicates_and_creates_observations(
    api_db, monkeypatch, tmp_path,
):
    token = uuid4().hex
    value = f"csv-feed-{token}.example"
    content = (
        "indicator_type,value,source,threat_type,confidence,severity,tags\n"
        f"domain,{value},csv_source_a,phishing,75,high,phishing;demo\n"
        f"domain,{value},csv_source_b,phishing,80,high,phishing;demo\n"
    )
    (tmp_path / "csv_demo.csv").write_text(content, encoding="utf-8")
    monkeypatch.setattr(ingestion_api, "FEED_DIR", tmp_path)
    try:
        first = ingestion_api.ingest_feed("csv_demo", api_db)
        second = ingestion_api.ingest_feed("csv_demo", api_db)
        assert first["source_file"] == "csv_demo.csv"
        assert (first["records_processed"], first["new_iocs"], first["existing_iocs"], first["observations_created"]) == (2, 1, 1, 2)
        assert (second["new_iocs"], second["existing_iocs"], second["observations_created"]) == (0, 2, 2)
        db = SessionLocal()
        try:
            ioc = db.query(IOC).filter(IOC.normalized_value == value).one()
            observations = db.query(IOCObservation).filter(IOCObservation.ioc_id == ioc.id).all()
            assert {item.source for item in observations} == {"csv_source_a", "csv_source_b"}
            assert len(observations) == 4
        finally:
            db.close()
    finally:
        remove_test_iocs([value])


def test_csv_feed_ingestion_reports_invalid_row(api_db, monkeypatch, tmp_path):
    (tmp_path / "invalid_csv.csv").write_text(
        "indicator_type,value,source\ninvalid,not-an-ioc,csv_test\n", encoding="utf-8"
    )
    monkeypatch.setattr(ingestion_api, "FEED_DIR", tmp_path)
    with pytest.raises(HTTPException) as error:
        ingestion_api.ingest_feed("invalid_csv", api_db)
    assert error.value.status_code == 422
    assert "CSV line 2" in error.value.detail
