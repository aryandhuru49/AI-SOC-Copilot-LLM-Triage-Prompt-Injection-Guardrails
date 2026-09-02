"""Minimal end-to-end smoke test: generate one alert, triage it, print the result.

    python scripts/run_once.py
    python scripts/run_once.py --attack        # inject a payload first
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attacks.payloads import INJECTION_PAYLOADS, inject
from data.synthetic_alerts import generate_alert
from pipeline.triage import triage_alert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", action="store_true")
    ap.add_argument("--no-defense", action="store_true")
    ap.add_argument("--type", default="malware")
    args = ap.parse_args()

    alert = generate_alert(args.type, seed=1)
    if args.attack:
        p = INJECTION_PAYLOADS[0]
        alert.description = inject(alert.description, p["text"])
        print(f"[injected: {p['id']}]")

    print(f"\nALERT {alert.alert_id} ({alert.alert_type}) expected={alert.expected_severity}")
    print(f"  {alert.description}\n")

    res = triage_alert(alert, config=not args.no_defense)
    print("TRIAGE RESULT")
    for k, v in res.model_dump().items():
        print(f"  {k:>24}: {v}")


if __name__ == "__main__":
    main()
