import json
import csv
from pathlib import Path

from pydantic import ValidationError

from app.schemas.ioc import IOCCreate


def load_json_feed(file_path: str | Path) -> list[IOCCreate]:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("CTI feed must contain a JSON array")

    validated_records = []
    for index, record in enumerate(records):
        try:
            validated_records.append(IOCCreate.model_validate(record))
        except ValidationError as error:
            raise ValueError(
                f"Invalid IOC record at index {index}: {error}"
            ) from error

    return validated_records


def load_csv_feed(file_path: str | Path) -> list[IOCCreate]:
    """Load a bounded CTIP CSV feed with columns matching IOCCreate fields.

    Tags are separated by semicolons; a comma-separated cell is also accepted
    when the CSV field itself is quoted.
    """
    path = Path(file_path)
    validated_records = []
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            if not reader.fieldnames:
                raise ValueError("CTI CSV feed must include a header row")
            required = {"indicator_type", "value", "source"}
            missing = required.difference(reader.fieldnames)
            if missing:
                raise ValueError(
                    "CTI CSV feed is missing required columns: "
                    + ", ".join(sorted(missing))
                )

            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ValueError(f"Invalid CSV row at line {row_number}: too many columns")
                record = {key: (value.strip() if value is not None else "") for key, value in row.items()}
                if "tags" in record:
                    raw_tags = record["tags"]
                    delimiter = ";" if ";" in raw_tags else ","
                    record["tags"] = [tag.strip() for tag in raw_tags.split(delimiter) if tag.strip()]
                for optional in ("threat_type", "confidence", "severity"):
                    if record.get(optional, "") == "":
                        record.pop(optional, None)
                try:
                    validated_records.append(IOCCreate.model_validate(record))
                except ValidationError as error:
                    raise ValueError(
                        f"Invalid IOC record at CSV line {row_number}: {error}"
                    ) from error
    except csv.Error as error:
        raise ValueError(f"Invalid CTI CSV feed: {error}") from error
    return validated_records


def load_cti_feed(file_path: str | Path) -> list[IOCCreate]:
    """Select the small supported parser from the feed file extension."""
    path = Path(file_path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        return load_json_feed(path)
    if suffix == ".csv":
        return load_csv_feed(path)
    raise ValueError("Unsupported CTI feed format; use .json or .csv")
