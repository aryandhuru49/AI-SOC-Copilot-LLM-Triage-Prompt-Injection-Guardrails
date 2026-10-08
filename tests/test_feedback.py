"""Offline tests for analyst-feedback storage (no API key, no Streamlit)."""
from __future__ import annotations

import pytest

from pipeline.feedback import latest_per_alert, load_feedback, save_feedback, summarize
from pipeline.schemas import SocAlert, TriageResult


def _alert(alert_id="A-1", alert_type="malware") -> SocAlert:
    return SocAlert(alert_id=alert_id, alert_type=alert_type, description="EDR flagged Emotet",
                    raw_log="edr verdict=malicious", timestamp="2026-10-08T00:00:00Z",
                    expected_severity="critical")


def _result(severity="critical", alert_id="A-1") -> TriageResult:
    return TriageResult(alert_id=alert_id, severity=severity, summary="s",
                        recommended_action="a", confidence=0.9)


def test_correct_verdict_pins_correct_severity_to_ai_severity(tmp_path):
    log = tmp_path / "fb.jsonl"
    rec = save_feedback(_alert(), _result("high"), "correct", "low", source="queue", path=log)
    assert rec["correct_severity"] == "high"
    assert rec["direction"] == "match"
    assert load_feedback(log)[0]["verdict"] == "correct"


def test_wrong_verdict_records_direction(tmp_path):
    log = tmp_path / "fb.jsonl"
    low = save_feedback(_alert(), _result("low"), "wrong", "high", source="queue", path=log)
    high = save_feedback(_alert("A-2"), _result("critical", "A-2"), "wrong", "medium",
                         source="queue", path=log)
    assert low["direction"] == "too_low"
    assert high["direction"] == "too_high"


def test_wrong_with_same_severity_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_feedback(_alert(), _result("high"), "wrong", "high", source="queue",
                      path=tmp_path / "fb.jsonl")


def test_bad_verdict_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_feedback(_alert(), _result(), "maybe", "high", source="queue",
                      path=tmp_path / "fb.jsonl")


def test_load_skips_blank_and_corrupt_lines(tmp_path):
    log = tmp_path / "fb.jsonl"
    save_feedback(_alert(), _result(), "correct", "critical", source="queue", path=log)
    with log.open("a", encoding="utf-8") as fh:
        fh.write("\n{not json}\n")
    assert len(load_feedback(log)) == 1


def test_missing_log_loads_as_empty(tmp_path):
    assert load_feedback(tmp_path / "nope.jsonl") == []


def test_latest_per_alert_keeps_last_entry_per_key(tmp_path):
    log = tmp_path / "fb.jsonl"
    save_feedback(_alert(), _result("low"), "wrong", "high", source="queue", path=log)
    save_feedback(_alert(), _result("high"), "correct", "high", source="queue", path=log)
    save_feedback(_alert(), _result("critical"), "correct", "critical",
                  source="playground", context="urgency_social", path=log)
    latest = latest_per_alert(load_feedback(log))
    assert len(latest) == 2
    queue_entry = next(r for r in latest if r["source"] == "queue")
    assert queue_entry["verdict"] == "correct"


def test_summarize(tmp_path):
    log = tmp_path / "fb.jsonl"
    save_feedback(_alert("A-1"), _result("critical", "A-1"), "correct", "critical",
                  source="queue", path=log)
    save_feedback(_alert("A-2"), _result("low", "A-2"), "wrong", "high", source="queue", path=log)
    save_feedback(_alert("A-3"), _result("critical", "A-3"), "wrong", "medium",
                  source="queue", path=log)
    s = summarize(load_feedback(log))
    assert s["n"] == 3
    assert s["disagreements"] == 2
    assert s["too_low"] == 1 and s["too_high"] == 1
    assert s["agreement_rate"] == pytest.approx(1 / 3)


def test_summarize_empty():
    assert summarize([])["agreement_rate"] == 0.0
