"""Part B Tier 1 — run Trivy against the vulnerable dependency pins and Dockerfile,
normalize findings into SocAlerts. No image build required.

Requires:  trivy on PATH  (https://trivy.dev/)
Usage:     python -m containers.scan       (or: python containers/scan.py)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.schemas import SocAlert  # noqa: E402

_HERE = Path(__file__).resolve().parent
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}

_TRIVY = os.environ.get("TRIVY_BIN", "trivy")


def _run_trivy(args: list[str]) -> dict:
    proc = subprocess.run([_TRIVY, *args, "--quiet", "--format", "json"],
                          capture_output=True, text=True)
    if not proc.stdout.strip():
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError("trivy produced no output — is it installed and on PATH?")
    return json.loads(proc.stdout)


def scan_dependencies(req: Path = _HERE / "vuln-app") -> dict:
    # Trivy detects dependency files by name, so the pinned-old packages live in
    # vuln-app/requirements.txt.
    return _run_trivy(["fs", "--scanners", "vuln", str(req)])


def scan_dockerfile(path: Path = _HERE) -> dict:
    return _run_trivy(["config", str(path)])


def to_alerts(trivy_json: dict) -> list[SocAlert]:
    alerts: list[SocAlert] = []
    i = 0
    for res in trivy_json.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = _SEV.get((v.get("Severity") or "UNKNOWN").upper(), "low")
            desc = (v.get("Description") or "")[:400]  # upstream pkg metadata — attacker-influenced
            alerts.append(SocAlert(
                alert_id=f"CVE-{i:03d}",
                alert_type="container_cve",
                description=f"{v.get('VulnerabilityID')} in {v.get('PkgName')} "
                            f"{v.get('InstalledVersion')} (fixed: {v.get('FixedVersion') or 'none'}). {desc}",
                raw_log=json.dumps({k: v.get(k) for k in ("VulnerabilityID", "PkgName", "PrimaryURL")}),
                timestamp=datetime.now(timezone.utc).isoformat(),
                expected_severity=sev,
            ))
            i += 1
        for m in res.get("Misconfigurations", []) or []:
            sev = _SEV.get((m.get("Severity") or "MEDIUM").upper(), "medium")
            alerts.append(SocAlert(
                alert_id=f"DKR-{i:03d}",
                alert_type="iac_misconfig",
                description=f"{m.get('ID')} {m.get('Title')} — {m.get('Description', '')[:300]} "
                            f"[{res.get('Target')}]",
                raw_log=json.dumps({k: m.get(k) for k in ("ID", "Title", "Resolution")}),
                timestamp=datetime.now(timezone.utc).isoformat(),
                expected_severity=sev,
            ))
            i += 1
    return alerts


if __name__ == "__main__":
    alerts = to_alerts(scan_dependencies()) + to_alerts(scan_dockerfile())
    print(f"{len(alerts)} container findings -> alerts")
    for a in alerts[:12]:
        print(f"  [{a.expected_severity:>8}] {a.alert_type:<13} {a.description[:100]}")
