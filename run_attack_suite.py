"""CLI entry point: run the defense ladder over all payloads, save results + charts.

Usage:
    python run_attack_suite.py                 # generic payloads
    python run_attack_suite.py --all           # + IaC/container payloads
    python run_attack_suite.py --position prefix
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from attacks.payloads import ALL_PAYLOADS, INJECTION_PAYLOADS
from eval.report import before_after_chart, ladder_chart, per_technique_chart
from eval.scorer import run_ladder_df

OUT = Path("eval/out")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="include IaC/container payloads")
    ap.add_argument("--position", default="suffix", choices=["prefix", "middle", "suffix"])
    ap.add_argument("--target-type", default="malware")
    args = ap.parse_args()

    payloads = ALL_PAYLOADS if args.all else INJECTION_PAYLOADS
    df = run_ladder_df(payloads=payloads, position=args.position, target_type=args.target_type)

    OUT.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT / "attack_results.csv", index=False)

    rates = df.groupby("rung")["attack_succeeded"].mean().round(3).to_dict()
    (OUT / "summary.json").write_text(json.dumps({
        "n_payloads": len(payloads),
        "position": args.position,
        "attack_success_rate_by_rung": rates,
    }, indent=2))

    c0 = ladder_chart(df)
    c1 = before_after_chart(df)
    c2 = per_technique_chart(df)
    print(f"\nSaved: {OUT/'attack_results.csv'}\n       {c0}\n       {c1}\n       {c2}")


if __name__ == "__main__":
    main()
