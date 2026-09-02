"""Part B Tier 1 — run Checkov over vulnerable Terraform, normalize findings to SocAlerts.

Requires:  pip install checkov
Usage:     python -m iac.scan     (or: python iac/scan.py)
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.schemas import SocAlert  # noqa: E402

_DIR = Path(__file__).resolve().parent / "vulnerable"
_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_checkov(path: Path = _DIR) -> dict:
    # `python -m checkov.main` works whether or not the `checkov` shim is on PATH.
    proc = subprocess.run(
        [sys.executable, "-m", "checkov.main", "-d", str(path), "-o", "json", "--quiet"],
        capture_output=True, text=True,
    )
    if not proc.stdout.strip():
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError("checkov produced no output — is it installed? `pip install checkov`")
    data = json.loads(proc.stdout)
    return data[0] if isinstance(data, list) else data


def to_alerts(checkov_json: dict) -> list[SocAlert]:
    results = checkov_json.get("results", {}) if isinstance(checkov_json, dict) else {}
    failed = results.get("failed_checks", [])
    alerts: list[SocAlert] = []
    for i, chk in enumerate(failed):
        sev = _SEVERITY_MAP.get((chk.get("severity") or "MEDIUM").upper(), "medium")
        # code_block carries the raw .tf source lines — attacker-controlled text
        code_block = " ".join(line.strip() for _, line in (chk.get("code_block") or []))
        alerts.append(SocAlert(
            alert_id=f"IAC-{i:03d}",
            alert_type="iac_misconfig",
            description=f"{chk.get('check_id')} {chk.get('check_name')} on "
                        f"{chk.get('resource')} ({chk.get('file_path')}:{chk.get('file_line_range')}). "
                        f"Code: {code_block}",
            raw_log=json.dumps(chk),
            timestamp=datetime.now(timezone.utc).isoformat(),
            expected_severity=sev,
        ))
    return alerts


if __name__ == "__main__":
    data = run_checkov()
    alerts = to_alerts(data)
    print(f"{len(alerts)} IaC findings -> alerts")
    for a in alerts[:10]:
        print(f"  [{a.expected_severity:>8}] {a.description[:110]}")
