"""AWS Lambda: pull real CloudTrail management events, normalize to SocAlerts,
store them, and fire the triage Lambda for each.

Triggered hourly by EventBridge. Uses cloudtrail:LookupEvents (free Event history) —
no trail, no data events, $0.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import boto3

from pipeline.schemas import SocAlert

_HOURS = int(os.environ.get("CLOUDTRAIL_HOURS", "1"))
_TRIAGE_FN = os.environ.get("TRIAGE_FUNCTION")
_TABLE_NAME = os.environ.get("DDB_TABLE")

_ct = boto3.client("cloudtrail")
_lambda = boto3.client("lambda")
_table = boto3.resource("dynamodb").Table(_TABLE_NAME) if _TABLE_NAME else None

# event name -> default severity for events worth surfacing
_INTERESTING = {
    "ConsoleLogin": "medium", "CreateUser": "high", "CreateAccessKey": "high",
    "AttachUserPolicy": "high", "PutUserPolicy": "high", "CreateLoginProfile": "high",
    "AuthorizeSecurityGroupIngress": "medium", "DeleteTrail": "critical",
    "StopLogging": "critical", "PutBucketPolicy": "high", "PutBucketAcl": "high",
    "DisableKey": "high", "DeleteFlowLogs": "high", "UpdateAssumeRolePolicy": "high",
}


def _to_alert(ev: dict, i: int) -> SocAlert | None:
    name = ev.get("EventName", "")
    if name not in _INTERESTING:
        return None
    detail = json.loads(ev.get("CloudTrailEvent", "{}"))
    src_ip = detail.get("sourceIPAddress", "0.0.0.0")
    ua = detail.get("userAgent", "")  # attacker-influenced free text
    actor = (detail.get("userIdentity", {}) or {}).get("arn", ev.get("Username", "unknown"))
    return SocAlert(
        alert_id=f"CT-{ev.get('EventId', i)}",
        alert_type="cloudtrail_event",
        source_ip=src_ip if src_ip[:1].isdigit() else "0.0.0.0",
        description=f"{name} by {actor} from {src_ip}. userAgent={ua!r}. "
                    f"region={detail.get('awsRegion')} errorCode={detail.get('errorCode', 'none')}",
        raw_log=ev.get("CloudTrailEvent", "{}")[:4000],
        timestamp=str(ev.get("EventTime", "")),
        expected_severity=_INTERESTING[name],
    )


def handler(event, context):
    start = datetime.now(timezone.utc) - timedelta(hours=_HOURS)
    paginator = _ct.get_paginator("lookup_events")
    raw_events: list[dict] = []
    for page in paginator.paginate(StartTime=start, EndTime=datetime.now(timezone.utc)):
        raw_events.extend(page.get("Events", []))

    alerts = [a for i, ev in enumerate(raw_events) if (a := _to_alert(ev, i))]

    dispatched = 0
    for alert in alerts:
        if _table is not None:
            _table.put_item(Item={
                "alert_id": alert.alert_id, "alert_type": alert.alert_type,
                "source_ip": alert.source_ip, "timestamp": alert.timestamp,
                "expected_severity": alert.expected_severity or "unknown",
                "severity": "pending", "summary": "", "recommended_action": "",
                "confidence": "0", "flagged_suspicious_input": False,
            })
        if _TRIAGE_FN:
            _lambda.invoke(
                FunctionName=_TRIAGE_FN, InvocationType="Event",
                Payload=json.dumps({"alert": alert.model_dump(exclude={"expected_severity"})
                                    | {"expected_severity": alert.expected_severity}}).encode(),
            )
            dispatched += 1

    return {"scanned_events": len(raw_events), "alerts": len(alerts), "dispatched": dispatched}
