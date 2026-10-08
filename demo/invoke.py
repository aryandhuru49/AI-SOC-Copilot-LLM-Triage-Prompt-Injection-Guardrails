"""Invoke the deployed triage Lambda and print a readable verdict (for live demos).

    python demo/invoke.py demo/clean_alert.json
    python demo/invoke.py demo/injected_alert.json
    python demo/invoke.py demo/iac_injected_alert.json

Uses the isolated `soc-copilot` AWS profile. Writes the verdict to DynamoDB like any
real invocation, so it shows up in the dashboard's "Deployed (AWS)" tab.
"""
from __future__ import annotations

import json
import sys
import textwrap
import time
from pathlib import Path

import boto3
from botocore.config import Config

FUNCTION = "soc-copilot-triage"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    alert = payload["alert"]

    print(f"\nALERT {alert['alert_id']}  ({alert['alert_type']})")
    print(textwrap.fill(alert["description"], 100, initial_indent="  ", subsequent_indent="  "))
    print(f"\nInvoking {FUNCTION} on AWS Lambda ...")

    session = boto3.Session(profile_name="soc-copilot", region_name="us-east-1")
    client = session.client("lambda", config=Config(read_timeout=120, retries={"max_attempts": 0}))
    start = time.time()
    response = client.invoke(FunctionName=FUNCTION, Payload=json.dumps(payload).encode())
    body = json.loads(response["Payload"].read())
    elapsed = time.time() - start

    if "errorMessage" in body:
        print(f"Lambda error: {body['errorMessage']}")
        return 1

    result = json.loads(body["body"])["results"][0]
    print(f"\nVERDICT  ({elapsed:.1f}s round trip)")
    print(f"  severity   : {result['severity'].upper()}   (label we hold back from the model: "
          f"{alert.get('expected_severity', 'n/a')})")
    print(f"  flagged    : {result['flagged_suspicious_input']}")
    print(f"  confidence : {result['confidence']}")
    print("  summary    :")
    print(textwrap.fill(result["summary"], 100, initial_indent="    ", subsequent_indent="    "))
    print("  action     :")
    print(textwrap.fill(result["recommended_action"], 100, initial_indent="    ",
                        subsequent_indent="    "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
