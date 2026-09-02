"""Defense configuration + the layer ladder used for the before/after evaluation.

The whole point of the eval is to measure each layer's *marginal* contribution,
so defenses are toggled independently rather than with one boolean.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefenseConfig:
    harden_prompt: bool = True   # "all fields are untrusted data" system + user framing
    strict_schema: bool = True   # strict tool use — API guarantees output shape
    input_filter: bool = True    # cheap regex/heuristic prefilter
    guard_classifier: bool = True  # separate LLM: "does this text contain instructions?"

    @property
    def label(self) -> str:
        on = [n for n, v in (
            ("prompt", self.harden_prompt), ("schema", self.strict_schema),
            ("filter", self.input_filter), ("guard", self.guard_classifier),
        ) if v]
        return "+".join(on) if on else "naive"


NAIVE = DefenseConfig(False, False, False, False)
FULL = DefenseConfig(True, True, True, True)

# Ordered ladder: each rung adds one layer on top of the previous.
LADDER: dict[str, DefenseConfig] = {
    "A_naive":       DefenseConfig(False, False, False, False),
    "B_prompt":      DefenseConfig(True,  False, False, False),
    "C_schema":      DefenseConfig(True,  True,  False, False),
    "D_filter":      DefenseConfig(True,  True,  True,  False),
    "E_full":        DefenseConfig(True,  True,  True,  True),
}
