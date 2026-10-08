"""Analyst feedback on triage verdicts, stored as JSONL for later review.

Step 1 of the learning loop: record whether a verdict was right, next to the original
alert and what the model decided. Nothing here retrains anything; it produces the
labelled data you review to tune regex rules, prompts, and few-shot examples.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pipeline.schemas import SocAlert, TriageResult

FEEDBACK_LOG = Path(__file__).resolve().parent.parent / "logs" / "feedback.jsonl"
SEVERITIES = ["low", "medium", "high", "critical"]


def _direction(ai_severity: str, correct_severity: str) -> str:
    diff = SEVERITIES.index(ai_severity) - SEVERITIES.index(correct_severity)
    return "match" if diff == 0 else "too_high" if diff > 0 else "too_low"


def save_feedback(
    alert: SocAlert,
    result: TriageResult,
    verdict: str,
    correct_severity: str,
    source: str,
    context: str = "",
    guardrails: bool = True,
    path: Path | None = None,
) -> dict:
    """Append one feedback record. `verdict` is "correct" or "wrong"."""
    if verdict not in ("correct", "wrong"):
        raise ValueError(f"verdict must be 'correct' or 'wrong', got {verdict!r}")
    if verdict == "correct":
        correct_severity = result.severity
    elif correct_severity == result.severity:
        raise ValueError("Marked wrong, but the actual severity equals the AI's severity.")

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "context": context,
        "guardrails": guardrails,
        "alert_id": alert.alert_id,
        "alert_type": alert.alert_type,
        "description": alert.description[:1000],
        "ai_severity": result.severity,
        "ai_confidence": result.confidence,
        "flagged": result.flagged_suspicious_input,
        "verdict": verdict,
        "correct_severity": correct_severity,
        "direction": _direction(result.severity, correct_severity),
    }
    target = path or FEEDBACK_LOG
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def load_feedback(path: Path | None = None) -> list[dict]:
    target = path or FEEDBACK_LOG
    if not target.exists():
        return []
    records = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def latest_per_alert(records: list[dict]) -> list[dict]:
    """Keep only the most recent entry per (source, alert_id, context)."""
    latest: dict[tuple, dict] = {}
    for rec in records:
        latest[(rec["source"], rec["alert_id"], rec.get("context", ""))] = rec
    return list(latest.values())


def summarize(records: list[dict]) -> dict:
    wrong = [r for r in records if r["verdict"] == "wrong"]
    n = len(records)
    return {
        "n": n,
        "agreement_rate": (n - len(wrong)) / n if n else 0.0,
        "disagreements": len(wrong),
        "too_high": sum(r["direction"] == "too_high" for r in wrong),
        "too_low": sum(r["direction"] == "too_low" for r in wrong),
    }
