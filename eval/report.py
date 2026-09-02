"""Turn ladder results into charts — the key portfolio artifacts."""
from __future__ import annotations

from pathlib import Path

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

_OUT = Path(__file__).resolve().parent / "out"

_RUNG_LABELS = {
    "A_naive": "A\nnaive",
    "B_prompt": "B\n+hardened\nprompt",
    "C_schema": "C\n+strict\nschema",
    "D_filter": "D\n+regex\nfilter",
    "E_full": "E\n+guard\n(full)",
}


def ladder_chart(df: pd.DataFrame, out_path: str | None = None) -> Path:
    """df needs columns: rung, attack_succeeded (bool), flagged (bool)."""
    _OUT.mkdir(exist_ok=True)
    out = Path(out_path) if out_path else _OUT / "defense_ladder.png"

    order = ["A_naive", "B_prompt", "C_schema", "D_filter", "E_full"]
    g = df.groupby("rung")
    succ = (g["attack_succeeded"].mean() * 100).reindex(order).fillna(0.0)
    flag = (g["flagged"].mean() * 100).reindex(order).fillna(0.0)
    x = range(len(order))

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(x, flag.values, color="#27ae60", width=0.55,
                  label="injection detected & flagged")
    ax.plot(x, succ.values, "o-", color="#c0392b",
            label="attack succeeded (severity downgraded)")
    ax.set_xticks(list(x))
    ax.set_xticklabels([_RUNG_LABELS[r] for r in order])
    ax.set_ylabel("% of injection attempts")
    ax.set_ylim(0, 105)
    ax.set_title("SOC Copilot — injection detection as guardrails are added")
    for b, v in zip(bars, flag.values):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.legend(loc="upper left")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def before_after_chart(df: pd.DataFrame, out_path: str | None = None) -> Path:
    """Two-bar headline: injection detection, naive vs full guardrails."""
    _OUT.mkdir(exist_ok=True)
    out = Path(out_path) if out_path else _OUT / "before_after.png"

    flag = df.groupby("rung")["flagged"].mean().mul(100)
    values = [flag.get("A_naive", 0.0), flag.get("E_full", 0.0)]
    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(["Naive\n(no guardrails)", "Full guardrails"], values,
                  color=["#c0392b", "#27ae60"], width=0.55)
    ax.set_ylabel("Injection attempts detected (%)")
    ax.set_ylim(0, 105)
    ax.set_title("SOC Copilot — prompt-injection detection, before vs after")
    for b, v in zip(bars, values):
        ax.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def per_technique_chart(df: pd.DataFrame, out_path: str | None = None) -> Path:
    _OUT.mkdir(exist_ok=True)
    out = Path(out_path) if out_path else _OUT / "per_technique.png"

    sub = df[df["rung"].isin(["D_filter", "E_full"])]
    pivot = (
        sub.groupby(["technique", "rung"])["flagged"].mean().mul(100).unstack()
        .reindex(columns=["D_filter", "E_full"]).fillna(0.0)
    )
    ax = pivot.plot(kind="barh", figsize=(8, 6), color=["#f39c12", "#27ae60"])
    ax.set_xlabel("Injection attempts detected (%)")
    ax.set_xlim(0, 105)
    ax.legend(["regex filter only", "filter + guard classifier"])
    ax.set_title("Injection detection by technique")
    ax.figure.tight_layout()
    ax.figure.savefig(out, dpi=150)
    plt.close(ax.figure)
    return out
