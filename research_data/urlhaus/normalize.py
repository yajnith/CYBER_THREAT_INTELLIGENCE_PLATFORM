import json
from pathlib import Path
from typing import Any


INPUT_FILE = Path(__file__).with_name("urlhaus_recent.json")
OUTPUT_FILE = Path(__file__).with_name("urlhaus_normalized.json")


def normalize_tags(tags: Any) -> list[str]:
    """Convert URLhaus tags into a consistent list of strings."""

    if tags is None:
        return []

    if isinstance(tags, list):
        return [
            str(tag).strip()
            for tag in tags
            if str(tag).strip()
        ]

    if isinstance(tags, str):
        return [
            tag.strip()
            for tag in tags.split(",")
            if tag.strip()
        ]

    return [str(tags).strip()]


def normalize_record(
    urlhaus_id: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Convert one URLhaus record into the research schema."""

    return {
        "urlhaus_id": str(urlhaus_id),
        "url": str(record.get("url", "")).strip(),
        "date_added": record.get("dateadded"),
        "url_status": record.get("url_status"),
        "last_online": record.get("last_online"),
        "threat": record.get("threat"),
        "tags": normalize_tags(record.get("tags")),
        "urlhaus_link": record.get("urlhaus_link"),
        "reporter": record.get("reporter"),
    }


def load_urlhaus_records(
    input_file: Path = INPUT_FILE,
) -> list[dict[str, Any]]:
    """Load and flatten the URLhaus export."""

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "Expected URLhaus export to be a JSON object."
        )

    records: list[dict[str, Any]] = []

    for urlhaus_id, record_list in data.items():

        if not isinstance(record_list, list):
            raise ValueError(
                f"Expected a list for URLhaus ID {urlhaus_id}."
            )

        if len(record_list) != 1:
            raise ValueError(
                f"Expected exactly one record for "
                f"URLhaus ID {urlhaus_id}, "
                f"found {len(record_list)}."
            )

        record = record_list[0]

        if not isinstance(record, dict):
            raise ValueError(
                f"Expected record for URLhaus ID "
                f"{urlhaus_id} to be an object."
            )

        records.append(
            normalize_record(
                urlhaus_id,
                record,
            )
        )

    return records


def save_records(
    records: list[dict[str, Any]],
    output_file: Path = OUTPUT_FILE,
) -> None:
    """Save normalized records as JSON."""

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            records,
            file,
            indent=2,
            ensure_ascii=False,
        )


def main() -> None:
    records = load_urlhaus_records()

    save_records(records)

    print(f"Input file: {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Records normalized: {len(records)}")


if __name__ == "__main__":
    main()