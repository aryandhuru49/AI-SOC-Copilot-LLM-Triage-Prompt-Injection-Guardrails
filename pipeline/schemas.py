"""Pydantic models for the triage pipeline.

Forcing the model to emit a `TriageResult` via tool use is itself a defense:
there is far less room to go off-script than with free text.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]

# Alert categories the synthetic generator produces.
AlertType = Literal[
    "network_intrusion",
    "malware",
    "auth_anomaly",
    "iac_misconfig",       # Part B: from Checkov/tfsec
    "container_cve",       # Part B: from Trivy
    "cloudtrail_event",    # Part B Tier 3: from AWS CloudTrail
]


class SocAlert(BaseModel):
    alert_id: str
    alert_type: AlertType = "network_intrusion"
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    description: str          # analyst-facing text — primary injection target
    raw_log: str             # raw log line — secondary injection target
    timestamp: str
    expected_severity: Severity | None = None  # ground truth for scoring, not shown to model


class TriageResult(BaseModel):
    alert_id: str
    severity: Severity
    summary: str
    recommended_action: str
    confidence: float = Field(ge=0.0, le=1.0)
    flagged_suspicious_input: bool = False


def triage_tool_schema() -> dict:
    """JSON schema for the `submit_triage` tool, minus fields the model shouldn't set.

    `additionalProperties: false` + a full `required` list let us pass `strict: true`
    on the tool, which guarantees the model's output validates against this schema —
    itself a defense against an injection nudging the model off the expected shape.
    """
    schema = TriageResult.model_json_schema()
    props = schema.get("properties", {})
    props.pop("flagged_suspicious_input", None)
    # `strict: true` rejects JSON-Schema validation keywords like minimum/maximum.
    # Keep the bounds as documentation in the field description instead.
    for name, spec in props.items():
        for kw in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
            spec.pop(kw, None)
        if name == "confidence":
            spec["description"] = "Model confidence from 0.0 to 1.0."
    schema["additionalProperties"] = False
    schema["required"] = [k for k in props if k != "flagged_suspicious_input"]
    return schema
