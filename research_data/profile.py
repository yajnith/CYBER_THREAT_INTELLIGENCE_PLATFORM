import json
from collections import Counter
from pathlib import Path


RESEARCH_DATA_DIR = Path(__file__).parent
URLHAUS_FILE = (
    RESEARCH_DATA_DIR
    / "urlhaus"
    / "urlhaus_normalized.json"
)


def load_records() -> list[dict]:
    with URLHAUS_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError(
            "Expected URLhaus normalized data "
            "to be a JSON list."
        )

    return records


def count_missing(
    records: list[dict],
    field: str,
) -> int:
    return sum(
        1
        for record in records
        if record.get(field) in (None, "")
    )


def main() -> None:
    records = load_records()

    print("=== URLhaus Research Dataset Profile ===")
    print(f"Records: {len(records)}")

    print("\n--- Threat Distribution ---")

    threat_counts = Counter(
        record.get("threat")
        for record in records
    )

    for threat, count in threat_counts.most_common():
        print(f"{threat}: {count}")

    print("\n--- URL Status Distribution ---")

    status_counts = Counter(
        record.get("url_status")
        for record in records
    )

    for status, count in status_counts.most_common():
        print(f"{status}: {count}")

    print("\n--- Missing Values ---")

    fields = [
        "url",
        "date_added",
        "url_status",
        "last_online",
        "threat",
        "tags",
        "reporter",
    ]

    for field in fields:
        print(
            f"{field}: "
            f"{count_missing(records, field)}"
        )

    print("\n--- Tags ---")

    tag_counts = Counter()

    for record in records:
        for tag in record.get("tags", []):
            tag_counts[tag] += 1

    if tag_counts:
        for tag, count in tag_counts.most_common(20):
            print(f"{tag}: {count}")
    else:
        print("No tags found.")

    print("\n--- Reporters ---")

    reporter_counts = Counter(
        record.get("reporter")
        for record in records
        if record.get("reporter")
    )

    print(
        f"Unique reporters: "
        f"{len(reporter_counts)}"
    )

    for reporter, count in reporter_counts.most_common(20):
        print(f"{reporter}: {count}")


if __name__ == "__main__":
    main()