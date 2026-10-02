import json
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
