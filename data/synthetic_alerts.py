"""Generate realistic synthetic SOC alerts as `SocAlert` objects.

No LLM, no network. Deterministic when you pass a seed so eval runs are reproducible.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from pipeline.schemas import SocAlert

_MALWARE_NAMES = ["Emotet", "AgentTesla", "Cobalt Strike beacon", "Mimikatz", "XMRig miner"]
_USER_AGENTS = ["python-requests/2.31", "curl/8.4.0", "Mozilla/5.0 (Windows NT 10.0)", "sqlmap/1.8"]
_INTERNAL = "10.{}.{}.{}"
_EXTERNAL = "{}.{}.{}.{}"


def _ip(template: str, rng: random.Random) -> str:
    octets = [rng.randint(1, 254) for _ in range(template.count("{}"))]
    return template.format(*octets)


def _ts(rng: random.Random) -> str:
    base = datetime.now(timezone.utc) - timedelta(minutes=rng.randint(0, 720))
    return base.isoformat()


def _network_intrusion(aid: str, rng: random.Random) -> SocAlert:
    src, dst = _ip(_EXTERNAL, rng), _ip(_INTERNAL, rng)
    port = rng.choice([22, 445, 3389, 8080, 1433])
    return SocAlert(
        alert_id=aid,
        alert_type="network_intrusion",
        source_ip=src,
        dest_ip=dst,
        description=f"IDS signature ET SCAN detected {rng.randint(200, 4000)} connection attempts "
                    f"from {src} to {dst}:{port} in 60s. Possible port scan / brute force.",
        raw_log=f'{_ts(rng)} suricata alert src={src} dst={dst} dport={port} '
                f'sig="ET SCAN Potential SSH Scan" sev=2 ua="{rng.choice(_USER_AGENTS)}"',
        timestamp=_ts(rng),
        expected_severity="medium",
    )


def _malware(aid: str, rng: random.Random) -> SocAlert:
    host = _ip(_INTERNAL, rng)
    name = rng.choice(_MALWARE_NAMES)
    return SocAlert(
        alert_id=aid,
        alert_type="malware",
        source_ip=host,
        dest_ip=_ip(_EXTERNAL, rng),
        description=f"EDR flagged process execution matching {name} on host {host}. "
                    f"Child process spawned from winword.exe, outbound C2 beaconing observed.",
        raw_log=f'{_ts(rng)} edr host={host} proc="powershell.exe -enc SQBFAFgA" '
                f'parent="winword.exe" verdict=malicious family="{name}"',
        timestamp=_ts(rng),
        # malware executing + active C2 beaconing = active compromise -> critical
        expected_severity="critical",
    )


def _auth_anomaly(aid: str, rng: random.Random) -> SocAlert:
    user = rng.choice(["j.doe", "svc_backup", "administrator", "a.patel"])
    src = _ip(_EXTERNAL, rng)
    return SocAlert(
        alert_id=aid,
        alert_type="auth_anomaly",
        source_ip=src,
        dest_ip=_ip(_INTERNAL, rng),
        description=f"Impossible-travel sign-in for {user}: login from {src} (geo mismatch) "
                    f"{rng.randint(3, 20)} min after a login from a domestic IP. MFA satisfied.",
        raw_log=f'{_ts(rng)} azuread user={user} ip={src} result=success mfa=yes risk=high '
                f'reason="unfamiliarLocation"',
        timestamp=_ts(rng),
        expected_severity="high",
    )


_GENERATORS = {
    "network_intrusion": _network_intrusion,
    "malware": _malware,
    "auth_anomaly": _auth_anomaly,
}


def generate_alert(alert_type: str | None = None, seed: int | None = None) -> SocAlert:
    rng = random.Random(seed)
    if alert_type is None:
        alert_type = rng.choice(list(_GENERATORS))
    aid = f"A-{rng.randint(10_000, 99_999)}"
    return _GENERATORS[alert_type](aid, rng)


def generate_batch(n: int = 15, seed: int = 0) -> list[SocAlert]:
    rng = random.Random(seed)
    types = list(_GENERATORS)
    return [generate_alert(types[i % len(types)], seed=rng.randint(0, 1_000_000)) for i in range(n)]


if __name__ == "__main__":
    for a in generate_batch(6):
        print(f"[{a.alert_type:>17}] {a.alert_id}  expected={a.expected_severity}")
        print(f"    {a.description}")
