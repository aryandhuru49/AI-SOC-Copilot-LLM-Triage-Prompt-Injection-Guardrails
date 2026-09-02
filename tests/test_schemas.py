from __future__ import annotations

from pipeline.schemas import SocAlert, TriageResult, triage_tool_schema


def test_triage_tool_schema_hides_internal_field():
    schema = triage_tool_schema()
    assert "flagged_suspicious_input" not in schema["properties"]
    assert "severity" in schema["properties"]


def test_socalert_roundtrips():
    a = SocAlert(alert_id="A-1", description="d", raw_log="r", timestamp="t")
    assert SocAlert.model_validate_json(a.model_dump_json()) == a


def test_triageresult_confidence_bounds():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TriageResult(alert_id="A-1", severity="low", summary="s",
                     recommended_action="a", confidence=1.5)
