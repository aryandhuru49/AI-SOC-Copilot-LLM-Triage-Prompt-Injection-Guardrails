"""Core LLM triage pipeline."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from pydantic import ValidationError

from defense.config import FULL, NAIVE, DefenseConfig
from defense.guard_classifier import is_suspicious
from defense.input_filter import prefilter_alert
from pipeline.prompts import (
    TRIAGE_SYSTEM_PROMPT_HARDENED,
    TRIAGE_SYSTEM_PROMPT_NAIVE,
    USER_FRAMING_HARDENED,
    USER_FRAMING_NAIVE,
)
from pipeline.schemas import SocAlert, TriageResult, triage_tool_schema

load_dotenv()

_MODEL = os.getenv("TRIAGE_MODEL", "claude-sonnet-5")
# Overridable for read-only filesystems (e.g. AWS Lambda -> /tmp).
_AUDIT_LOG = Path(os.getenv("AUDIT_LOG_PATH", "")) or (
    Path(__file__).resolve().parent.parent / "logs" / "audit_log.jsonl"
)

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    return _client


def _audit(record: dict) -> None:
    record = {"ts": datetime.now(timezone.utc).isoformat(), **record}
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        print("AUDIT " + json.dumps(record))  # fall back to stdout (CloudWatch)


def _coerce_result(raw: dict, alert: SocAlert) -> TriageResult:
    """Lenient parse for the non-strict-schema rungs: keep whatever the model
    produced (including a downgrade an injection tricked it into) instead of
    failing. Only genuine refusals (handled by the caller) fail safe."""
    return TriageResult(
        alert_id=str(raw.get("alert_id") or alert.alert_id),
        severity=raw.get("severity") if raw.get("severity") in
        ("low", "medium", "high", "critical") else "medium",
        summary=str(raw.get("summary") or "(model omitted summary)"),
        recommended_action=str(raw.get("recommended_action") or "(model omitted action)"),
        confidence=float(raw["confidence"]) if isinstance(raw.get("confidence"), (int, float))
        else 0.5,
    )


def triage_alert(
    alert: SocAlert,
    config: DefenseConfig | bool = FULL,
) -> TriageResult:
    """`config` accepts a DefenseConfig, or a bool for back-compat
    (True -> full defense, False -> naive / no defense)."""
    if isinstance(config, bool):
        config = FULL if config else NAIVE

    filter_hit = guard_hit = False
    if config.input_filter:
        filter_hit = prefilter_alert(alert)
    if config.guard_classifier:
        guard_hit = is_suspicious(alert)
    flagged = filter_hit or guard_hit

    system = TRIAGE_SYSTEM_PROMPT_HARDENED if config.harden_prompt else TRIAGE_SYSTEM_PROMPT_NAIVE
    framing = USER_FRAMING_HARDENED if config.harden_prompt else USER_FRAMING_NAIVE

    # Only pass the model fields it should reason about — never expected_severity.
    model_view = alert.model_dump(exclude={"expected_severity"})

    tool: dict = {
        "name": "submit_triage",
        "description": "Submit the triage result for this alert.",
        "input_schema": triage_tool_schema(),
    }
    if config.strict_schema:
        tool["strict"] = True

    message = _get_client().messages.create(
        model=_MODEL,
        max_tokens=4096,
        system=system,
        tools=[tool],
        tool_choice={"type": "tool", "name": "submit_triage"},
        messages=[{
            "role": "user",
            "content": framing.format(alert_json=json.dumps(model_view, indent=2)),
        }],
    )

    tool_use = next((b for b in message.content if b.type == "tool_use"), None)
    truncated = message.stop_reason == "max_tokens"

    if tool_use is None or not tool_use.input or truncated:
        # Model refused, produced no tool call, or was cut off mid-JSON. Fail SAFE:
        # hold the alert at its expected severity (attacker gains nothing) and flag it.
        result = TriageResult(
            alert_id=alert.alert_id,
            severity=alert.expected_severity or "high",
            summary=f"No usable structured triage result (stop_reason={message.stop_reason}). "
                    f"Alert held at default severity pending manual review.",
            recommended_action="Manual analyst review required.",
            confidence=0.0,
        )
        flagged = True
    else:
        try:
            result = TriageResult(**tool_use.input)
        except ValidationError:
            # Non-strict rungs, or a strict response that still came back malformed.
            result = _coerce_result(dict(tool_use.input), alert)

    result.flagged_suspicious_input = flagged

    _audit({
        "alert_id": alert.alert_id,
        "alert_type": alert.alert_type,
        "defense": config.label,
        "filter_hit": filter_hit,
        "guard_hit": guard_hit,
        "expected_severity": alert.expected_severity,
        "result_severity": result.severity,
        "confidence": result.confidence,
    })
    return result
