from __future__ import annotations
from typing import Any

VALID_STATUSES = {"available", "missing", "unchecked", "unavailable"}


def analyze_evidence(alert: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = []
    for item in evidence:
        status = str(item.get("status", "unchecked")).lower()
        if status not in VALID_STATUSES:
            status = "unchecked"
        normalized.append({
            "key": str(item.get("key", "unknown")),
            "label": str(item.get("label", item.get("key", "Evidence item"))),
            "status": status,
            "source": str(item.get("source", "Not specified")),
            "notes": str(item.get("notes", "")),
        })
    counts = {key: sum(1 for item in normalized if item["status"] == key) for key in VALID_STATUSES}
    applicable = counts["available"] + counts["missing"]
    completeness = round(counts["available"] / applicable * 100, 1) if applicable else None
    alert_rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
    alert_title = alert_rule.get("description") or alert.get("title") or "Security alert"
    return {
        "summary": f"Evidence review for: {alert_title}",
        "counts": counts,
        "evidence_completeness_percent": completeness,
        "gaps": [item for item in normalized if item["status"] == "missing"],
        "unchecked": [item for item in normalized if item["status"] == "unchecked"],
        "unavailable": [item for item in normalized if item["status"] == "unavailable"],
        "evidence": normalized,
        "limitations": [
            "A missing item means its relevant source was checked and the expected evidence was not found.",
            "Unchecked or unavailable evidence is not treated as missing.",
            "The results support analyst review and do not prove that an attack occurred or was resolved.",
        ],
    }
