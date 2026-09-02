"""AWS Lambda: triage + guardrails.

Invoke payloads accepted:
  {"alert": { ...SocAlert fields... }}
  {"alerts": [ {...}, {...} ]}
  { ...SocAlert fields... }                 (bare alert)
  Lambda Function URL request (JSON body with any of the above)
"""
from __future__ import annotations

import json
import os

import boto3

# --- cold start: pull the Anthropic key from SSM into the env the SDK reads ---
_ssm_name = os.environ.get("SSM_KEY_NAME")
if _ssm_name and not os.environ.get("ANTHROPIC_API_KEY"):
    _val = boto3.client("ssm").get_parameter(Name=_ssm_name, WithDecryption=True)
    os.environ["ANTHROPIC_API_KEY"] = _val["Parameter"]["Value"]

from defense.config import FULL  # noqa: E402
from pipeline.schemas import SocAlert  # noqa: E402
from pipeline.triage import triage_alert  # noqa: E402

_ddb = boto3.resource("dynamodb")
_table = _ddb.Table(os.environ["DDB_TABLE"]) if os.environ.get("DDB_TABLE") else None
_sns = boto3.client("sns")
_TOPIC = os.environ.get("SNS_TOPIC_ARN")


def _extract_alerts(event: dict) -> list[dict]:
    if "body" in event and isinstance(event["body"], str):  # Function URL
        try:
            event = json.loads(event["body"] or "{}")
        except json.JSONDecodeError:
            return []
    if "alerts" in event:
        return list(event["alerts"])
    if "alert" in event:
        return [event["alert"]]
    if "description" in event:  # bare alert
        return [event]
    return []


def _persist(alert: SocAlert, result) -> None:
    if _table is None:
        return
    _table.put_item(Item={
        "alert_id": alert.alert_id,
        "alert_type": alert.alert_type,
        "source_ip": alert.source_ip,
        "timestamp": alert.timestamp,
        "expected_severity": alert.expected_severity or "unknown",
        "severity": result.severity,
        "summary": result.summary[:1500],
        "recommended_action": result.recommended_action[:1500],
        "confidence": str(result.confidence),
        "flagged_suspicious_input": result.flagged_suspicious_input,
    })


def _notify(alert: SocAlert, result) -> None:
    if _TOPIC and result.severity in ("high", "critical"):
        _sns.publish(
            TopicArn=_TOPIC,
            Subject=f"[SOC {result.severity.upper()}] {alert.alert_id} ({alert.alert_type})",
            Message=f"{result.summary}\n\nAction: {result.recommended_action}\n"
                    f"Flagged suspicious input: {result.flagged_suspicious_input}",
        )


def handler(event, context):
    raw_alerts = _extract_alerts(event or {})
    if not raw_alerts:
        return {"statusCode": 400, "body": json.dumps({"error": "no alert(s) in payload"})}

    out = []
    for raw in raw_alerts:
        alert = SocAlert(**raw)
        result = triage_alert(alert, config=FULL)
        _persist(alert, result)
        _notify(alert, result)
        out.append(result.model_dump())

    return {"statusCode": 200, "body": json.dumps({"results": out})}
