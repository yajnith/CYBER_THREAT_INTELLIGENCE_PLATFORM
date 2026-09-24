import json
from pathlib import Path

from app.schemas.ioc import IOCCreate


def load_json_feed(file_path: str | Path) -> list[IOCCreate]:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("CTI feed must contain a JSON array")

    return [IOCCreate.model_validate(record) for record in records]
