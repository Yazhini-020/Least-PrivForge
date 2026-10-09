

"""
test_temporal_analyzer.py — Tests for Temporal Access Pattern Analyzer
 
These tests are completely offline.
They test timezone handling, timestamp parsing, temporal classification,
rare-use detection, malformed data handling, insight generation,
and AI payload construction without contacting AWS or any external API.
"""
 
from datetime import datetime, timezone
 
import pytest
 
from src.temporal_analyzer import TemporalAccessAnalyzer
 
 
def make_entry(action="s3:GetObject", event_time="2026-01-05T10:00:00Z"):
    """Return a reusable temporal-analysis entry."""
    return {"action": action, "event_time": event_time}
 
 
# =========================================================
# __init__() / timezone tests
# =========================================================
 
def test_init_default_timezone():
    """Default timezone should be UTC."""
    analyzer = TemporalAccessAnalyzer()
 
    assert str(analyzer._tz) == "UTC"
 
 
def test_init_explicit_utc_timezone():
    """UTC should be accepted explicitly."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    assert str(analyzer._tz) == "UTC"
 
 
def test_init_asia_kolkata_timezone():
    """Asia/Kolkata should be accepted."""
    analyzer = TemporalAccessAnalyzer("Asia/Kolkata")
 
    assert str(analyzer._tz) == "Asia/Kolkata"
 
 
def test_init_new_york_timezone():
    """America/New_York should be accepted."""
    analyzer = TemporalAccessAnalyzer("America/New_York")
 
    assert str(analyzer._tz) == "America/New_York"
 
 
def test_init_invalid_timezone():
    """Invalid IANA timezone should raise ValueError."""
    with pytest.raises(ValueError):
        TemporalAccessAnalyzer("Invalid/Timezone")
 
 
# =========================================================
# _localize() tests
# =========================================================
 
def test_localize_utc_string():
    """UTC ISO timestamp should preserve its UTC hour."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer._localize("2026-01-05T10:00:00Z")
 
    assert result.hour == 10
    assert result.tzinfo is not None
 
 
def test_localize_indian_timezone():
    """UTC timestamp should convert correctly to IST."""
    analyzer = TemporalAccessAnalyzer("Asia/Kolkata")
 
    result = analyzer._localize("2026-01-05T04:30:00Z")
 
    assert result.hour == 10
    assert result.tzinfo is not None
 
 
def test_localize_datetime_with_timezone():
    """Timezone-aware datetime should convert to the configured timezone."""
    analyzer = TemporalAccessAnalyzer("Asia/Kolkata")
    value = datetime(2026, 1, 5, 4, 30, tzinfo=timezone.utc)
 
    result = analyzer._localize(value)
 
    assert result.hour == 10
 
 
def test_localize_naive_datetime():
    """Naive datetime should be treated as UTC before conversion."""
    analyzer = TemporalAccessAnalyzer("Asia/Kolkata")
    value = datetime(2026, 1, 5, 4, 30)
 
    result = analyzer._localize(value)
 
    assert result.hour == 10
 
 
def test_localize_invalid_string():
    """Invalid timestamp string should raise ValueError."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    with pytest.raises(ValueError):
        analyzer._localize("not-a-date")
 
 
def test_localize_invalid_type():
    """Unsupported timestamp type should raise TypeError."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    with pytest.raises(TypeError):
        analyzer._localize(12345)
 
 
# =========================================================
# analyze() basic tests
# =========================================================
 
def test_analyze_empty_input():
    """Empty input should return an empty complete analysis."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([])
 
    assert result["per_action"] == {}
    assert result["summary"]["total_actions_analyzed"] == 0
    assert result["data_quality"]["complete"] is True
 
 
def test_analyze_single_action():
    """A valid action should be counted once."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([make_entry()])
 
    assert result["per_action"]["s3:GetObject"]["count"] == 1
    assert result["summary"]["total_actions_analyzed"] == 1
 
 
def test_analyze_multiple_same_actions():
    """Repeated actions should be grouped together."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-06T11:00:00Z"),
        make_entry(event_time="2026-01-07T12:00:00Z"),
    ])
 
    assert result["per_action"]["s3:GetObject"]["count"] == 3
 
 
def test_analyze_multiple_different_actions():
    """Different actions should have separate entries."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry("s3:GetObject", "2026-01-05T10:00:00Z"),
        make_entry("s3:PutObject", "2026-01-05T11:00:00Z"),
    ])
 
    assert result["summary"]["total_actions_analyzed"] == 2
    assert "s3:GetObject" in result["per_action"]
    assert "s3:PutObject" in result["per_action"]
 
 
def test_analyze_records_first_seen():
    """first_seen should contain the earliest localized timestamp."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-06T10:00:00Z"),
        make_entry(event_time="2026-01-05T10:00:00Z"),
    ])
 
    assert "2026-01-05" in result["per_action"]["s3:GetObject"]["first_seen"]
 
 
def test_analyze_records_last_seen():
    """last_seen should contain the latest localized timestamp."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-06T10:00:00Z"),
    ])
 
    assert "2026-01-06" in result["per_action"]["s3:GetObject"]["last_seen"]
 
 
def test_analyze_records_timezone():
    """Each action result should record the configured timezone."""
    analyzer = TemporalAccessAnalyzer("Asia/Kolkata")
 
    result = analyzer.analyze([make_entry()])
 
    assert result["per_action"]["s3:GetObject"]["timezone"] == "Asia/Kolkata"
 
 
def test_analyze_records_hours_used():
    """hours_used should contain the observed local hour."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T14:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["hours_used"] == [14]
 
 
def test_analyze_records_weekdays_used():
    """weekdays_used should contain the observed weekday."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z")  # Monday
    ])
 
    assert result["per_action"]["s3:GetObject"]["weekdays_used"] == ["Monday"]
 
 
# =========================================================
# Business-hours classification tests
# =========================================================
 
def test_business_hours_at_09():
    """09:00 on a weekday is inside business hours."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T09:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is True
 
 
def test_business_hours_at_17():
    """17:00 on a weekday is inside business hours."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T17:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is True
 
 
def test_business_hours_at_18_is_false():
    """18:00 is outside the configured business-hours range."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T18:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
def test_business_hours_before_09_is_false():
    """08:59 is outside the configured business-hours range."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T08:59:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
def test_weekend_saturday_is_false():
    """Saturday activity is not business-hours-only."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-10T10:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
def test_weekend_sunday_is_false():
    """Sunday activity is not business-hours-only."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-11T10:00:00Z")
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
def test_business_hours_requires_all_observed_hours():
    """One out-of-hours event makes the action not business-hours-only."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-05T20:00:00Z"),
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
def test_business_hours_requires_weekdays_only():
    """One weekend event makes the action not business-hours-only."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-10T10:00:00Z"),
    ])
 
    assert result["per_action"]["s3:GetObject"]["business_hours_only"] is False
 
 
# =========================================================
# Rare-use tests
# =========================================================
 
def test_one_use_is_rare():
    """One observed use should be rarely used."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([make_entry()])
 
    assert result["per_action"]["s3:GetObject"]["is_rarely_used"] is True
 
 
def test_two_uses_are_rare():
    """Two observed uses should still be rarely used."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-06T10:00:00Z"),
    ])
 
    assert result["per_action"]["s3:GetObject"]["is_rarely_used"] is True
 
 
def test_three_uses_are_not_rare():
    """Three observed uses should exceed the rare-use threshold."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry(event_time="2026-01-06T10:00:00Z"),
        make_entry(event_time="2026-01-07T10:00:00Z"),
    ])
 
    assert result["per_action"]["s3:GetObject"]["is_rarely_used"] is False
 
 
def test_rare_action_appears_in_summary():
    """Rare actions should appear in rarely_used_actions."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([make_entry()])
 
    assert "s3:GetObject" in result["summary"]["rarely_used_actions"]
 
 
def test_nonrare_action_is_not_in_summary():
    """Non-rare actions should not appear in rarely_used_actions."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-01T10:00:00Z"),
        make_entry(event_time="2026-01-02T10:00:00Z"),
        make_entry(event_time="2026-01-03T10:00:00Z"),
    ])
 
    assert "s3:GetObject" not in result["summary"]["rarely_used_actions"]
 
 
# =========================================================
# Data-quality tests
# =========================================================
 
def test_missing_action_is_skipped():
    """An entry without action should be skipped."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        {"event_time": "2026-01-05T10:00:00Z"}
    ])
 
    assert result["data_quality"]["complete"] is False
    assert result["data_quality"]["entries_skipped"] == 1
 
 
def test_missing_event_time_is_skipped():
    """An entry without event_time should be skipped."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        {"action": "s3:GetObject"}
    ])
 
    assert result["data_quality"]["complete"] is False
    assert result["data_quality"]["entries_skipped"] == 1
 
 
def test_invalid_event_time_is_skipped():
    """An invalid event_time should be skipped."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        {"action": "s3:GetObject", "event_time": "bad"}
    ])
 
    assert result["data_quality"]["complete"] is False
    assert result["data_quality"]["entries_skipped"] == 1
 
 
def test_none_entry_is_skipped():
    """A non-dictionary entry should be skipped."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([None])
 
    assert result["data_quality"]["complete"] is False
    assert result["data_quality"]["entries_skipped"] == 1
 
 
def test_string_entry_is_skipped():
    """A string entry should be skipped."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze(["not-a-dict"])
 
    assert result["data_quality"]["complete"] is False
    assert result["data_quality"]["entries_skipped"] == 1
 
 
def test_skipped_detail_contains_index():
    """Malformed entry details should contain the original index."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(),
        {"action": "bad"},
    ])
 
    assert result["data_quality"]["skipped_details"][0]["index"] == 1
 
 
def test_mixed_valid_and_invalid_entries():
    """Valid entries should still be analyzed when malformed ones exist."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(),
        {"action": "bad"},
    ])
 
    assert result["per_action"]["s3:GetObject"]["count"] == 1
    assert result["data_quality"]["entries_skipped"] == 1
    assert result["data_quality"]["complete"] is False
 
 
# =========================================================
# Insight-note tests
# =========================================================
 
def test_build_insight_notes_returns_list():
    """Insight notes should always be returned as a list."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([])
 
    notes = analyzer.build_insight_notes(result)
 
    assert isinstance(notes, list)
 
 
def test_build_insight_notes_reports_business_hours():
    """Business-hours-only activity should generate an insight."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        make_entry(event_time="2026-01-05T10:00:00Z")
    ])
 
    notes = analyzer.build_insight_notes(result)
 
    assert any("business hours" in note for note in notes)
 
 
def test_build_insight_notes_reports_rare_use():
    """Rarely used activity should generate an insight."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([make_entry()])
 
    notes = analyzer.build_insight_notes(result)
 
    assert any("used only" in note for note in notes)
 
 
def test_build_insight_notes_reports_incomplete_data():
    """Malformed data should generate a warning insight."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        {"action": "s3:GetObject"}
    ])
 
    notes = analyzer.build_insight_notes(result)
 
    assert any("malformed" in note for note in notes)
 
 
# =========================================================
# AI-payload tests
# =========================================================
 
def test_build_ai_payload_returns_dict():
    """AI payload should be a dictionary."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([])
 
    payload = analyzer.build_ai_payload(result)
 
    assert isinstance(payload, dict)
 
 
def test_build_ai_payload_contains_notes():
    """AI payload should contain notes."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([])
 
    payload = analyzer.build_ai_payload(result)
 
    assert "notes" in payload
 
 
def test_build_ai_payload_contains_data_quality():
    """AI payload should contain data quality separately."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([])
 
    payload = analyzer.build_ai_payload(result)
 
    assert "data_quality" in payload
 
 
def test_build_ai_payload_preserves_data_quality():
    """AI payload should preserve the analysis data-quality object."""
    analyzer = TemporalAccessAnalyzer("UTC")
 
    result = analyzer.analyze([
        {"action": "s3:GetObject"}
    ])
 
    payload = analyzer.build_ai_payload(result)
 
    assert payload["data_quality"] == result["data_quality"]
 
 
# =========================================================
# Determinism tests
# =========================================================
 
def test_analyze_is_deterministic():
    """The same input should produce the same analysis."""
    analyzer = TemporalAccessAnalyzer("UTC")
    entries = [
        make_entry(event_time="2026-01-05T10:00:00Z"),
        make_entry("s3:PutObject", "2026-01-06T11:00:00Z"),
    ]
 
    result1 = analyzer.analyze(entries)
    result2 = analyzer.analyze(entries)
 
    assert result1 == result2
 
 
def test_build_ai_payload_is_deterministic():
    """The same analysis should produce the same payload."""
    analyzer = TemporalAccessAnalyzer("UTC")
    result = analyzer.analyze([make_entry()])
 
    payload1 = analyzer.build_ai_payload(result)
    payload2 = analyzer.build_ai_payload(result)
 
    assert payload1 == payload2
 
