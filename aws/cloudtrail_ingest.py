"""Part B Tier 3 — pull REAL AWS CloudTrail management events (free 'Event history',
no trail, no S3) and normalize them into SocAlerts for the copilot.

Cost: $0. Uses cloudtrail:LookupEvents on the last 90 days of management events.
Requires:  pip install boto3  + AWS credentials (IAM user, least privilege).

    python aws/cloudtrail_ingest.py --hours 24
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone

from pipeline.schemas import SocAlert

# Event names worth surfacing as alerts, with a rough default severity.
_INTERESTING = {
    "ConsoleLogin": "medium",
    "CreateUser": "high", "CreateAccessKey": "high", "AttachUserPolicy": "high",
    "PutUserPolicy": "high", "CreateLoginProfile": "high",
    "AuthorizeSecurityGroupIngress": "medium", "DeleteTrail": "critical",
    "StopLogging": "critical", "PutBucketPolicy": "high", "PutBucketAcl": "high",
    "DisableKey": "high", "DeleteFlowLogs": "high",
}


def fetch_events(hours: int = 24, region: str | None = None) -> list[dict]:
    import boto3

    client = boto3.client("cloudtrail", region_name=region or os.getenv("AWS_REGION", "us-east-1"))
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    events: list[dict] = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start, EndTime=datetime.now(timezone.utc)):
        events.extend(page.get("Events", []))
    return events


def to_alerts(events: list[dict]) -> list[SocAlert]:
    alerts: list[SocAlert] = []
    for i, ev in enumerate(events):
        detail = json.loads(ev.get("CloudTrailEvent", "{}"))
        name = ev.get("EventName", "")
        if name not in _INTERESTING:
            continue
        src_ip = detail.get("sourceIPAddress", "0.0.0.0")
        user_agent = detail.get("userAgent", "")  # <-- attacker-influenced free text
        actor = (detail.get("userIdentity", {}) or {}).get("arn", ev.get("Username", "unknown"))
        alerts.append(SocAlert(
            alert_id=f"CT-{i:04d}",
            alert_type="cloudtrail_event",
            source_ip=src_ip if src_ip[0].isdigit() else "0.0.0.0",
            description=f"{name} by {actor} from {src_ip}. userAgent={user_agent!r}. "
                        f"region={detail.get('awsRegion')} errorCode={detail.get('errorCode', 'none')}",
            raw_log=ev.get("CloudTrailEvent", "{}"),
            timestamp=str(ev.get("EventTime", "")),
            expected_severity=_INTERESTING[name],
        ))
    return alerts


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--region", default=None)
    args = ap.parse_args()

    evs = fetch_events(args.hours, args.region)
    alerts = to_alerts(evs)
    print(f"{len(evs)} raw events -> {len(alerts)} alerts")
    for a in alerts[:15]:
        print(f"  [{a.expected_severity:>8}] {a.description[:120]}")
