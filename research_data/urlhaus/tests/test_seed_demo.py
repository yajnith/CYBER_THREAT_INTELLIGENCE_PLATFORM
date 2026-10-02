import unittest

from research_data.urlhaus.seed_demo import (
    build_ioc,
    select_representative_records,
    validate_demo_database_url,
)


def record(url, record_id, tags, status="offline", reporter="reporter"):
    return {
        "urlhaus_id": str(record_id),
        "url": url,
        "date_added": "2026-09-25 10:47:31 UTC",
        "url_status": status,
        "last_online": None,
        "threat": "malware_download",
        "tags": tags,
        "urlhaus_link": f"https://urlhaus.abuse.ch/url/{record_id}/",
        "reporter": reporter,
    }


class SeedDemoTests(unittest.TestCase):
    def test_selection_is_deterministic_and_prefers_distinct_hosts(self):
        records = [
            record("https://a.example/one", 1, ["alpha"]),
            record("https://a.example/two", 2, ["beta"], reporter="second"),
            record("https://b.example/one", 3, ["beta"], status="online"),
            record("https://c.example/one", 4, ["gamma"]),
        ]
        first = select_representative_records(records, 3)
        second = select_representative_records(list(reversed(records)), 3)
        self.assertEqual([row["url"] for row in first], [row["url"] for row in second])
        self.assertEqual(len({row["url"].split("/")[2] for row in first}), 3)
        self.assertEqual(len(first), 3)

    def test_mapping_preserves_urlhaus_context_and_source_timestamps(self):
        source = record("http://192.0.2.9/payload", 42, ["elf", "mirai"], status="online")
        source["last_online"] = "2026-09-25 11:00:00 UTC"
        ioc, date_added, last_online = build_ioc(source)

        self.assertEqual(ioc.value, source["url"])
        self.assertEqual(ioc.indicator_type.value, "url")
        self.assertEqual(ioc.source, "URLhaus")
        self.assertEqual(ioc.threat_type, "malware_download")
        self.assertEqual(ioc.tags, ["elf", "mirai"])
        self.assertEqual(ioc.confidence, 50)
        self.assertEqual(ioc.severity.value, "medium")
        self.assertEqual(date_added.isoformat(), "2026-09-25T10:47:31+00:00")
        self.assertEqual(last_online.isoformat(), "2026-09-25T11:00:00+00:00")

    def test_reset_guard_rejects_non_loopback_or_non_demo_database(self):
        with self.assertRaises(RuntimeError):
            validate_demo_database_url("postgresql://user:pass@example.com/ctip")
        with self.assertRaises(RuntimeError):
            validate_demo_database_url("postgresql://user:pass@localhost/production")
        validate_demo_database_url("postgresql://user:pass@127.0.0.1/ctip")


if __name__ == "__main__":
    unittest.main()
