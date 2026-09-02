"""Score triage quality on clean alerts and run the defense ladder."""
from __future__ import annotations

import pandas as pd

from attacks.harness import run_ladder, summarize
from attacks.payloads import INJECTION_PAYLOADS
from data.synthetic_alerts import generate_batch
from defense.config import FULL, NAIVE
from pipeline.triage import triage_alert

_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def score_clean(n: int = 12, seed: int = 0, config=FULL) -> dict:
    """How well does the pipeline triage non-adversarial alerts vs. expected_severity?"""
    rows = []
    for alert in generate_batch(n, seed=seed):
        res = triage_alert(alert, config=config)
        exp, got = alert.expected_severity, res.severity
        rows.append({
            "alert_id": alert.alert_id,
            "alert_type": alert.alert_type,
            "expected": exp,
            "got": got,
            "exact": exp == got,
            "within_one": abs(_ORDER[exp] - _ORDER[got]) <= 1 if exp else None,
            "flagged": res.flagged_suspicious_input,
        })
    df = pd.DataFrame(rows)
    return {
        "n": len(df),
        "exact_accuracy": round(float(df["exact"].mean()), 3),
        "within_one_accuracy": round(float(df["within_one"].mean()), 3),
        "false_flag_rate": round(float(df["flagged"].mean()), 3),  # clean alerts flagged as attacks
        "detail": df,
    }


def run_ladder_df(payloads=INJECTION_PAYLOADS, **kw) -> pd.DataFrame:
    """Run the full defense ladder; return a tidy DataFrame + print a summary."""
    rows = run_ladder(payloads=payloads, **kw)
    df = pd.DataFrame(rows)
    print("\n--- ladder summary (attack success rate by rung) ---")
    print(df.groupby("rung")["attack_succeeded"].mean().round(3).to_string())
    return df
