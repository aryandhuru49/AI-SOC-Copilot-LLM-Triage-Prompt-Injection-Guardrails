"""Cheap, fast, no-LLM pre-filter.

Catches the obvious prompt-injection patterns with regex/heuristics before any
model call. High precision is not the goal here — this is a first tripwire; the
guard classifier is the second.
"""
from __future__ import annotations

import base64
import re

from pipeline.schemas import SocAlert

_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions", re.I),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|the\s+above)", re.I),
    re.compile(r"\[/?\s*(system|inst|assistant)\s*\]", re.I),
    re.compile(r"<\|.*?\|>", re.I),
    re.compile(r"(you\s+are\s+now|from\s+now\s+on)\b.*\b(assistant|ai|model)", re.I),
    re.compile(r"(reveal|print|output|repeat)\b.*\b(system\s+prompt|instructions|verbatim)", re.I),
    re.compile(r"\b(set(ting)?|mark|change|downgrade|lower|reduce|suppress)\b.*\bseverity\b.*\b(low|medium|informational)\b", re.I),
    re.compile(r"\bseverity\s*[=:]\s*(low|medium|informational)\b", re.I),
    re.compile(r"\bsuppress\b.*\b(alert|finding|ticket)", re.I),
    re.compile(r"\b(false\s+positive|already\s+(reviewed|triaged)|no\s+action\s+needed|close\s+(this|the)\s+alert)\b", re.I),
    re.compile(r"as\s+(the\s+)?(lead|senior|head)\s+(soc\s+)?analyst", re.I),
    re.compile(r"decode\s+(this|the\s+following)\s+base64", re.I),
    re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I),
    re.compile(r"<div[^>]*style=[\"'][^\"']*(display\s*:\s*none|hidden)", re.I),
    re.compile(r"checkov:skip|tfsec:ignore|trivy:ignore|nosec", re.I),  # scanner suppression abuse
    re.compile(r'"?(role|type)"?\s*[:=]\s*"?(tool_result|tool_use|assistant|system)"?', re.I),
    re.compile(r"tool_use_id|submit_triage\b.*\bseverity", re.I),  # tool-result mimicry
    re.compile(r"\n\s*(assistant|human|user)\s*:", re.I),          # fake conversation turns
    re.compile(r"pre-?validated|trust_score\s*=|disposition\s*=\s*benign", re.I),
]

_B64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_INJECTION_HINTS = ("ignore", "instruction", "system", "severity", "prompt", "disregard", "alert")


def _decoded_base64_looks_hostile(text: str) -> bool:
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8", "ignore").lower()
        except Exception:
            continue
        if any(h in decoded for h in _INJECTION_HINTS):
            return True
    return False


def scan_text(text: str) -> list[str]:
    """Return a list of human-readable reasons the text looks like an injection."""
    reasons = [p.pattern for p in _PATTERNS if p.search(text)]
    if _decoded_base64_looks_hostile(text):
        reasons.append("base64-encoded instruction")
    return reasons


def prefilter_alert(alert: SocAlert) -> bool:
    fields = " \n ".join([alert.description, alert.raw_log, alert.source_ip, alert.dest_ip])
    return bool(scan_text(fields))
