import pytest
import json
from src.ai_generator import _parse_response, _build_system_prompt, _build_user_prompt


def test_parse_response_clean_json():
    """Test parsing a clean JSON response"""
    raw = json.dumps({
        "policy": {"Version": "2012-10-17", "Statement": []},
        "explanation": "test",
        "removed_actions": [],
        "confidence": "high",
        "confidence_reason": "test"
    })
    result = _parse_response(raw)
    assert result is not None
    assert "policy" in result


def test_parse_response_with_markdown_fences():
    """Test parsing JSON wrapped in markdown code fences"""
    raw = '```json\n{"policy": {"Version": "2012-10-17", "Statement": []}}\n```'
    result = _parse_response(raw)
    assert result is not None
    assert "policy" in result


def test_parse_response_invalid_json():
    """Test that invalid JSON returns None instead of raising"""
    raw = "this is not json at all"
    result = _parse_response(raw)
    assert result is None


def test_parse_response_missing_policy_key():
    """Test that valid JSON without 'policy' key returns None"""
    raw = json.dumps({"explanation": "test"})
    result = _parse_response(raw)
    assert result is None


def test_build_user_prompt_includes_usage_data():
    """Test that CloudTrail usage data appears in the prompt"""
    finding = {
        "entity_name": "test-role",
        "entity_type": "role",
        "policy_json": {"Statement": []},
        "finding_type": "WILDCARD_ACTION",
        "description": "test description"
    }
    usage = {"actions_used": ["s3:GetObject"], "action_count": 1, "days_analyzed": 30}

    prompt = _build_user_prompt(finding, usage)
    assert "s3:GetObject" in prompt
    assert "test-role" in prompt


def test_build_user_prompt_with_retry_error():
    """Test that retry prompts include the previous error"""
    finding = {
        "entity_name": "test-role",
        "entity_type": "role",
        "policy_json": {"Statement": []},
        "finding_type": "WILDCARD_ACTION",
        "description": "test"
    }
    usage = {"actions_used": [], "action_count": 0, "days_analyzed": 30}

    prompt = _build_user_prompt(finding, usage, previous_error="Missing Effect field")
    assert "Missing Effect field" in prompt
    assert "previous attempt failed" in prompt