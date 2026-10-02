import json
from collections import Counter
from datetime import datetime
from functools import lru_cache
from math import isfinite
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query


router = APIRouter(
    prefix="/api/v1/research",
    tags=["Research"],
)

# backend/app/api/research.py -> repository root / research_data
RESEARCH_DATA_DIR = Path(__file__).resolve().parents[3] / "research_data"

ARTIFACT_PATHS = {
    "urlhaus_metadata": "urlhaus/metadata.json",
    "feature_profile": "features/urlhaus_feature_profile.json",
    "experiment_profile": "experiments/urlhaus_experiment_profile.json",
    "synthetic_benchmark": "ml/synthetic_baseline_results.json",
    "synthetic_explanations": "ml/explainability/synthetic_explanations.json",
    "threatfox_metadata": "threatfox/metadata.json",
}
URLHAUS_NORMALIZED_PATH = "urlhaus/urlhaus_normalized.json"

LIMITATIONS = [
    "Real validated outcome labels are not currently available.",
    "Real URLhaus rows therefore remain unsuitable for supervised training.",
    "ThreatFox real data has not been collected.",
    "Synthetic ML results do not establish real-world performance.",
    "Production CTIP risk scoring remains deterministic.",
    "Synthetic feature contributions are not causal explanations.",
]


def _read_artifact(name: str) -> tuple[dict[str, Any] | None, str]:
    path = RESEARCH_DATA_DIR / ARTIFACT_PATHS[name]
    try:
        # Some existing metadata files carry a UTF-8 BOM; accept both forms.
        with path.open(encoding="utf-8-sig") as artifact_file:
            content = json.load(artifact_file)
        if not isinstance(content, dict) or not _valid_artifact(name, content):
            return None, "invalid"
        return content, "available"
    except FileNotFoundError:
        return None, "unavailable"
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "invalid"


def _valid_artifact(name: str, content: dict[str, Any]) -> bool:
    """Check the small structural contract each overview artifact needs."""
    if name == "urlhaus_metadata":
        return (
            isinstance(content.get("dataset"), str)
            and isinstance(content.get("normalized_record_count"), int)
            and isinstance(content.get("threat_distribution", {}), dict)
        )
    if name == "feature_profile":
        stats = content.get("statistics")
        return (
            isinstance(stats, dict)
            and isinstance(stats.get("feature_row_count"), int)
            and isinstance(stats.get("feature_column_count"), int)
        )
    if name == "experiment_profile":
        stats = content.get("statistics")
        return (
            isinstance(stats, dict)
            and isinstance(stats.get("experiment_feature_counts"), dict)
            and isinstance(stats.get("experiment_row_counts"), dict)
            and isinstance(stats.get("labeled_count_per_experiment"), dict)
        )
    if name == "synthetic_benchmark":
        metadata = content.get("metadata")
        return (
            isinstance(metadata, dict)
            and isinstance(metadata.get("benchmark_size"), int)
            and isinstance(metadata.get("class_counts"), dict)
            and isinstance(metadata.get("models"), list)
            and isinstance(content.get("experiments"), dict)
        )
    if name == "synthetic_explanations":
        metadata = content.get("metadata")
        return isinstance(metadata, dict) and isinstance(metadata.get("models"), list)
    if name == "threatfox_metadata":
        return isinstance(content.get("status"), str)
    return False


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


@lru_cache(maxsize=2)
def _load_urlhaus_records_cached(
    path_text: str, modified_ns: int, size: int
) -> tuple[dict[str, Any], ...]:
    """Read normalized URLhaus records once per file version."""
    del modified_ns, size
    with Path(path_text).open(encoding="utf-8-sig") as records_file:
        records = json.load(records_file)
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("Normalized URLhaus data must be a list of record objects.")
    return tuple(records)


def load_urlhaus_records() -> tuple[dict[str, Any], ...]:
    path = RESEARCH_DATA_DIR / URLHAUS_NORMALIZED_PATH
    stat = path.stat()
    return _load_urlhaus_records_cached(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


def _parse_urlhaus_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith(" UTC"):
        normalized = normalized[:-4] + "+00:00"
    elif normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=None)
    return parsed


def build_urlhaus_summary() -> dict[str, Any]:
    """Calculate research analytics directly from the normalized URLhaus file."""
    records = load_urlhaus_records()
    metadata, _metadata_status = _read_artifact("urlhaus_metadata")
    feature_profile, _feature_status = _read_artifact("feature_profile")

    statuses: Counter[str] = Counter()
    threats: Counter[str] = Counter()
    reporters: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    months: Counter[str] = Counter()
    urls: set[str] = set()
    added_dates: list[tuple[datetime, str]] = []
    dated_count = 0
    undated_count = 0
    last_online_count = 0

    for record in records:
        url = record.get("url")
        if isinstance(url, str) and url.strip():
            urls.add(url.strip())
        for field, counter in (("url_status", statuses), ("threat", threats), ("reporter", reporters)):
            value = record.get(field)
            if isinstance(value, str) and value.strip():
                counter[value.strip()] += 1
        record_tags = record.get("tags")
        if isinstance(record_tags, list):
            tags.update(tag.strip() for tag in record_tags if isinstance(tag, str) and tag.strip())

        date_added = record.get("date_added")
        parsed = _parse_urlhaus_timestamp(date_added)
        if parsed is None:
            undated_count += 1
        else:
            dated_count += 1
            original = date_added.strip()
            added_dates.append((parsed, original))
            months[parsed.strftime("%Y-%m")] += 1
        if isinstance(record.get("last_online"), str) and record["last_online"].strip():
            last_online_count += 1

    added_dates.sort(key=lambda item: item[0])
    feature_stats = _as_dict(_as_dict(feature_profile).get("statistics"))
    normalized_count = len(records)
    return {
        "dataset": "URLhaus",
        "source": _as_dict(metadata).get("source"),
        "collection_timestamp": _as_dict(metadata).get("collection_timestamp"),
        "record_count": normalized_count,
        "unique_url_count": len(urls),
        "duplicate_url_count": normalized_count - len(urls),
        "ioc_type": "url",
        "threat_distribution": dict(sorted(threats.items())),
        "url_status_distribution": dict(sorted(statuses.items())),
        "unique_reporter_count": len(reporters),
        "top_reporters": _top_count_items(reporters),
        "top_tags": _top_count_items(tags),
        "temporal_distribution_by_month": [
            {"label": month, "value": count} for month, count in sorted(months.items())
        ],
        "date_range": {
            "first_date_added": added_dates[0][1] if added_dates else None,
            "last_date_added": added_dates[-1][1] if added_dates else None,
        },
        "date_added_coverage": {"present": dated_count, "missing_or_invalid": undated_count},
        "last_online_coverage": {"present": last_online_count, "missing": normalized_count - last_online_count},
        "feature_count": feature_stats.get("feature_column_count"),
        "supervised_label_count": feature_stats.get("rows_with_assigned_target"),
        "records_with_tags": sum(bool(row.get("tags")) for row in records),
    }


def _top_count_items(counts: Counter[str], limit: int = 10) -> list[dict[str, Any]]:
    return [
        {"label": label, "value": count}
        for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


def search_urlhaus_records(
    search: str = "", status: str = "", page: int = 1, page_size: int = 25
) -> dict[str, Any]:
    records = load_urlhaus_records()
    normalized_search = search.casefold().strip()
    normalized_status = status.casefold().strip()
    filtered = []
    for record in records:
        if normalized_status and str(record.get("url_status") or "").casefold() != normalized_status:
            continue
        if normalized_search:
            haystack = " ".join((
                str(record.get("url") or ""),
                str(record.get("urlhaus_id") or ""),
                str(record.get("url_status") or ""),
                str(record.get("threat") or ""),
                str(record.get("reporter") or ""),
                " ".join(str(tag) for tag in (record.get("tags") or []) if isinstance(tag, str)),
                str(record.get("date_added") or ""),
            )).casefold()
            if normalized_search not in haystack:
                continue
        filtered.append(record)

    total = len(filtered)
    start = (page - 1) * page_size
    return {
        "dataset_record_count": len(records),
        "total_records": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
        "records": filtered[start:start + page_size],
    }


def _top_urlhaus_tags(limit: int = 10) -> tuple[list[dict[str, Any]], str]:
    """Profile tag counts from the existing normalized real URLhaus artifact."""
    path = RESEARCH_DATA_DIR / "urlhaus" / "urlhaus_normalized.json"
    try:
        with path.open(encoding="utf-8-sig") as artifact_file:
            records = json.load(artifact_file)
    except FileNotFoundError:
        return [], "unavailable"
    except (OSError, UnicodeError, json.JSONDecodeError):
        return [], "invalid"
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        return [], "invalid"

    counts: Counter[str] = Counter()
    for record in records:
        tags = record.get("tags")
        if tags is None:
            continue
        if not isinstance(tags, list):
            return [], "invalid"
        counts.update(
            tag.strip()
            for tag in tags
            if isinstance(tag, str) and tag.strip()
        )
    return [
        {"label": tag, "value": count}
        for tag, count in counts.most_common(limit)
    ], "available"


def _global_feature_contributions(
    explanations: dict[str, Any], limit: int = 10
) -> dict[str, Any]:
    """Expose ranked values already stored in the explanation artifact."""
    experiments = _as_dict(explanations.get("experiments"))
    result: dict[str, Any] = {}
    for experiment_id, experiment in experiments.items():
        models = _as_dict(_as_dict(experiment).get("models"))
        result_models: dict[str, Any] = {}
        for model_name, model in models.items():
            contribution = _as_dict(
                _as_dict(model).get("global_model_feature_contribution")
            )
            features = contribution.get("features_ranked_by_mean_absolute_contribution")
            if not isinstance(features, list):
                continue
            ranked = []
            for item in features:
                if not isinstance(item, dict):
                    continue
                value = item.get("mean_absolute_contribution")
                if (
                    isinstance(item.get("feature"), str)
                    and isinstance(value, (int, float))
                    and isfinite(value)
                ):
                    ranked.append({
                        "feature": item["feature"],
                        "mean_absolute_contribution": value,
                    })
            if ranked:
                result_models[model_name] = ranked[:limit]
        if result_models:
            result[experiment_id] = result_models
    return result


def build_research_overview() -> dict[str, Any]:
    artifacts = {name: _read_artifact(name) for name in ARTIFACT_PATHS}
    availability = {name: state for name, (_, state) in artifacts.items()}

    def artifact(name: str) -> dict[str, Any]:
        return artifacts[name][0] or {}

    urlhaus_metadata = artifact("urlhaus_metadata")
    feature_profile = artifact("feature_profile")
    experiment_profile = artifact("experiment_profile")
    benchmark = artifact("synthetic_benchmark")
    explanations = artifact("synthetic_explanations")
    threatfox = artifact("threatfox_metadata")

    feature_stats = _as_dict(feature_profile.get("statistics"))
    experiment_stats = _as_dict(experiment_profile.get("statistics"))
    benchmark_metadata = _as_dict(benchmark.get("metadata"))
    explanation_metadata = _as_dict(explanations.get("metadata"))
    benchmark_experiments = _as_dict(benchmark.get("experiments"))
    urlhaus_top_tags, urlhaus_tag_status = _top_urlhaus_tags()
    try:
        urlhaus_analytics = build_urlhaus_summary()
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, ValueError):
        urlhaus_analytics = None

    experiments = []
    experiment_names = {
        "A": "IOC-only",
        "B": "IOC + correlation",
        "C": "IOC + correlation + threat context",
    }
    for experiment_id in ("A", "B", "C"):
        result = _as_dict(benchmark_experiments.get(experiment_id))
        experiment_feature_counts = _as_dict(experiment_stats.get("experiment_feature_counts"))
        experiment_row_counts = _as_dict(experiment_stats.get("experiment_row_counts"))
        labeled_counts = _as_dict(experiment_stats.get("labeled_count_per_experiment"))
        result_models = _as_dict(result.get("models"))
        experiments.append({
            "id": experiment_id,
            "name": experiment_names[experiment_id],
            "feature_count": experiment_feature_counts.get(experiment_id)
            or result.get("feature_count"),
            "row_count": experiment_row_counts.get(experiment_id),
            "labeled_count": labeled_counts.get(experiment_id),
            "models": result_models,
        })

    source_coverage = _as_dict(experiment_stats.get("feature_source_row_coverage"))
    real_labels = feature_stats.get("rows_with_assigned_target")
    if real_labels is None:
        real_labels = experiment_stats.get("input_target_row_count")

    return {
        "objective": "Context-aware and explainable threat prioritization using correlated CTI.",
        "artifacts": availability,
        "artifacts_available": all(state == "available" for state in availability.values()),
        "real_dataset": {
            "source": urlhaus_metadata.get("dataset", "URLhaus"),
            "records": urlhaus_metadata.get("normalized_record_count"),
            "source_coverage": source_coverage,
            "target_status": "unavailable / unknown" if real_labels in (None, 0) else "available",
            "supervised_labels": real_labels,
            "data_kind": "Real CTI data",
            "threat_distribution": urlhaus_metadata.get("threat_distribution", {}),
            "url_status_distribution": urlhaus_metadata.get("url_status_distribution", {}),
            "top_tags": urlhaus_top_tags,
            "top_tags_status": urlhaus_tag_status,
            "unique_urls": urlhaus_analytics.get("unique_url_count") if urlhaus_analytics else None,
            "unique_reporter_count": urlhaus_analytics.get("unique_reporter_count") if urlhaus_analytics else None,
            "top_reporters": urlhaus_analytics.get("top_reporters", []) if urlhaus_analytics else [],
            "temporal_distribution_by_month": urlhaus_analytics.get("temporal_distribution_by_month", []) if urlhaus_analytics else [],
            "date_range": urlhaus_analytics.get("date_range") if urlhaus_analytics else None,
            "ioc_type": urlhaus_analytics.get("ioc_type") if urlhaus_analytics else "url",
        },
        "urlhaus_analytics": urlhaus_analytics,
        "feature_engineering": {
            "rows": feature_stats.get("feature_row_count"),
            "total_features": feature_stats.get("feature_column_count"),
        },
        "experiments": experiments,
        "benchmark": {
            "available": availability["synthetic_benchmark"] == "available",
            "result_label": benchmark_metadata.get("result_type", "SYNTHETIC BENCHMARK RESULT"),
            "dataset_type": benchmark_metadata.get("dataset_type", "synthetic"),
            "synthetic": benchmark_metadata.get("synthetic"),
            "samples": benchmark_metadata.get("benchmark_size"),
            "positive": _as_dict(benchmark_metadata.get("class_counts")).get("positive"),
            "negative": _as_dict(benchmark_metadata.get("class_counts")).get("negative"),
            "seed": benchmark_metadata.get("random_seed"),
            "split": benchmark_metadata.get("split_strategy"),
            "split_seed": benchmark_metadata.get("split_seed"),
            "models": benchmark_metadata.get("models", []) if isinstance(benchmark_metadata.get("models", []), list) else [],
        },
        "explainability": {
            "available": availability["synthetic_explanations"] == "available",
            "local_explanations": bool(explanation_metadata.get("models")),
            "global_feature_contributions_available": bool(explanation_metadata.get("models")),
            "feature_group_contributions": bool(explanation_metadata.get("models")),
            "causal": explanation_metadata.get("model_feature_importance_is_causal", False),
            "dataset_type": explanation_metadata.get("dataset_type", "synthetic benchmark only"),
            "global_feature_contributions": _global_feature_contributions(explanations),
            "experiments": _as_dict(explanations.get("experiments")),
        },
        "threatfox": {
            "status": threatfox.get("status", "unknown"),
            "real_data_collected": threatfox.get("status") == "collected",
        },
        "limitations": LIMITATIONS,
    }


def build_investigation_research_context() -> dict[str, Any]:
    """Return read-only research metadata safe to attach to an IOC detail."""
    urlhaus, urlhaus_status = _read_artifact("urlhaus_metadata")
    feature_profile, feature_status = _read_artifact("feature_profile")
    experiment_profile, experiment_status = _read_artifact("experiment_profile")
    _benchmark, benchmark_status = _read_artifact("synthetic_benchmark")

    feature_stats = _as_dict((feature_profile or {}).get("statistics"))
    experiment_stats = _as_dict((experiment_profile or {}).get("statistics"))
    assigned_targets = feature_stats.get("rows_with_assigned_target")
    if assigned_targets is None:
        assigned_targets = experiment_stats.get("input_target_row_count")

    experiment_counts = _as_dict(experiment_stats.get("experiment_feature_counts"))
    experiment_ids = [
        experiment_id
        for experiment_id in ("A", "B", "C")
        if experiment_id in experiment_counts
    ]

    return {
        "available": all(
            state == "available"
            for state in (urlhaus_status, feature_status, experiment_status)
        ),
        # There is no trained/validated real-label model artifact in this project.
        "real_labeled_model_available": False,
        "real_supervised_label_count": assigned_targets,
        "research_dataset": (urlhaus or {}).get("dataset"),
        "research_records": (urlhaus or {}).get("normalized_record_count"),
        "feature_count": feature_stats.get("feature_column_count"),
        "experiment_configurations": experiment_ids,
        "synthetic_benchmark_available": benchmark_status == "available",
        "synthetic_benchmark_label": "Controlled synthetic dataset",
        "production_ml_enabled": False,
    }


@router.get("/overview")
def get_research_overview():
    """Return read-only status and metrics from existing research artifacts."""
    return build_research_overview()


@router.get("/urlhaus/summary")
def get_urlhaus_summary():
    """Return analytics calculated from the complete normalized URLhaus file."""
    try:
        return build_urlhaus_summary()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Normalized URLhaus research data is not available.") from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Unable to read normalized URLhaus research data: {exc}") from exc


@router.get("/urlhaus/records")
def get_urlhaus_records(
    search: str = Query(default="", max_length=200),
    status: str = Query(default="", max_length=40),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
):
    """Search the real normalized URLhaus records with bounded pagination."""
    try:
        return search_urlhaus_records(search=search, status=status, page=page, page_size=page_size)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Normalized URLhaus research data is not available.") from exc
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=f"Unable to read normalized URLhaus research data: {exc}") from exc


@router.get("/explainability")
def get_explainability_artifact():
    """Expose the existing model explanation artifact without synthesizing values."""
    explanations, state = _read_artifact("synthetic_explanations")
    if explanations is None:
        raise HTTPException(status_code=404, detail=f"Synthetic explainability artifact is {state}.")
    return explanations
