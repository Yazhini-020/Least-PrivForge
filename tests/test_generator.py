
"""
test_generator.py — Tests for AI policy generator helpers

These tests are completely offline.
They test JSON parsing and prompt construction without
calling any external AI/API service.
"""

import json

from src.ai_generator import (
    _parse_response,
    _build_system_prompt,
    _build_user_prompt,
)


# =========================================================
# _parse_response() tests
# =========================================================

def test_parse_response_clean_json():
    """Test parsing a clean JSON response."""
    raw = json.dumps({
        "policy": {
            "Version": "2012-10-17",
            "Statement": []
        },
        "explanation": "test",
        "removed_actions": [],
        "confidence": "high",
        "confidence_reason": "test",
    })

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_with_markdown_fences():
    """Test parsing JSON wrapped in markdown code fences."""
    raw = (
        '```json\n'
        '{"policy": {"Version": "2012-10-17", "Statement": []}}\n'
        '```'
    )

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_with_plain_code_fence():
    """Test parsing JSON wrapped in a plain code fence."""
    raw = (
        '```\n'
        '{"policy": {"Version": "2012-10-17", "Statement": []}}\n'
        '```'
    )

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_invalid_json():
    """Test that invalid JSON returns None instead of raising."""
    raw = "this is not json at all"

    result = _parse_response(raw)

    assert result is None


def test_parse_response_empty_string():
    """Test empty response."""
    result = _parse_response("")

    assert result is None


def test_parse_response_whitespace_only():
    """Test whitespace-only response."""
    result = _parse_response("   \n\t  ")

    assert result is None


def test_parse_response_missing_policy_key():
    """Test that valid JSON without 'policy' key returns None."""
    raw = json.dumps({
        "explanation": "test"
    })

    result = _parse_response(raw)

    assert result is None


def test_parse_response_policy_is_none():
    """Test policy=None."""
    raw = json.dumps({
        "policy": None
    })

    result = _parse_response(raw)

    # A policy key exists, but the value is invalid.
    # The exact behavior depends on the implementation.
    assert result is None or "policy" in result


def test_parse_response_policy_is_empty_object():
    """Test an empty policy object."""
    raw = json.dumps({
        "policy": {}
    })

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_policy_with_statement():
    """Test parsing a realistic policy."""
    raw = json.dumps({
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::example/*"],
                }
            ]
        },
        "explanation": "Removed unnecessary permissions.",
        "removed_actions": ["s3:DeleteObject"],
        "confidence": "high",
        "confidence_reason": "Only read access is required.",
    })

    result = _parse_response(raw)

    assert result is not None
    assert result["policy"]["Version"] == "2012-10-17"
    assert len(result["policy"]["Statement"]) == 1


def test_parse_response_json_with_extra_fields():
    """Test that additional JSON fields do not break parsing."""
    raw = json.dumps({
        "policy": {
            "Version": "2012-10-17",
            "Statement": []
        },
        "extra_field": "extra",
        "another_field": 123,
    })

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_nested_markdown_text():
    """Test fenced JSON with surrounding whitespace."""
    raw = """
    ```json
    {
        "policy": {
            "Version": "2012-10-17",
            "Statement": []
        }
    }
    ```
    """

    result = _parse_response(raw)

    assert result is not None
    assert "policy" in result


def test_parse_response_json_array():
    """Test that a JSON array is not accepted as a policy response."""
    raw = json.dumps([
        {"policy": {"Statement": []}}
    ])

    result = _parse_response(raw)

    assert result is None


def test_parse_response_json_string():
    """Test that a JSON string is not accepted."""
    raw = json.dumps("hello")

    result = _parse_response(raw)

    assert result is None


def test_parse_response_json_number():
    """Test that a JSON number is not accepted."""
    raw = "12345"

    result = _parse_response(raw)

    assert result is None


# =========================================================
# _build_system_prompt() tests
# =========================================================

def test_build_system_prompt_returns_string():
    """System prompt should be a non-empty string."""
    prompt = _build_system_prompt()

    assert isinstance(prompt, str)
    assert len(prompt) > 0


def test_build_system_prompt_mentions_policy():
    """System prompt should contain IAM/policy-related instructions."""
    prompt = _build_system_prompt()

    prompt_lower = prompt.lower()

    assert "policy" in prompt_lower


def test_build_system_prompt_mentions_json():
    """System prompt should instruct the model about JSON output."""
    prompt = _build_system_prompt()

    prompt_lower = prompt.lower()

    assert "json" in prompt_lower


def test_build_system_prompt_is_deterministic():
    """Calling the helper twice should produce the same prompt."""
    prompt1 = _build_system_prompt()
    prompt2 = _build_system_prompt()

    assert prompt1 == prompt2


# =========================================================
# _build_user_prompt() tests
# =========================================================

def make_finding():
    """Return a reusable test finding."""
    return {
        "entity_name": "test-role",
        "entity_type": "role",
        "policy_json": {
            "Version": "2012-10-17",
            "Statement": []
        },
        "finding_type": "WILDCARD_ACTION",
        "description": "test description",
    }


def test_build_user_prompt_includes_usage_data():
    """Test that CloudTrail usage data appears in the prompt."""
    finding = make_finding()

    usage = {
        "actions_used": ["s3:GetObject"],
        "action_count": 1,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert "s3:GetObject" in prompt
    assert "test-role" in prompt


def test_build_user_prompt_includes_entity_type():
    """Test that entity type appears in the prompt."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert "role" in prompt.lower()


def test_build_user_prompt_includes_finding_type():
    """Test that finding type appears in the prompt."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert "WILDCARD_ACTION" in prompt


def test_build_user_prompt_includes_description():
    """Test that finding description appears in the prompt."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert "test description" in prompt


def test_build_user_prompt_with_no_usage_actions():
    """Test prompt construction when no actions were observed."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert isinstance(prompt, str)
    assert len(prompt) > 0


def test_build_user_prompt_with_multiple_usage_actions():
    """Test multiple CloudTrail actions."""
    finding = make_finding()

    usage = {
        "actions_used": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:ListBucket",
            "s3:GetBucketLocation",
        ],
        "action_count": 4,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    for action in usage["actions_used"]:
        assert action in prompt


def test_build_user_prompt_with_zero_days():
    """Test usage data with zero analysis days."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 0,
    }

    prompt = _build_user_prompt(finding, usage)

    assert isinstance(prompt, str)


def test_build_user_prompt_with_long_usage_list():
    """Test prompt construction with many observed actions."""
    finding = make_finding()

    actions = [
        f"s3:Action{i}"
        for i in range(50)
    ]

    usage = {
        "actions_used": actions,
        "action_count": len(actions),
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert isinstance(prompt, str)
    assert "s3:Action0" in prompt
    assert "s3:Action49" in prompt


def test_build_user_prompt_with_retry_error():
    """Test that retry prompts include the previous error."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(
        finding,
        usage,
        previous_error="Missing Effect field",
    )

    assert "Missing Effect field" in prompt
    assert "previous attempt failed" in prompt


def test_build_user_prompt_without_retry_error():
    """Test normal prompt when there is no previous error."""
    finding = make_finding()

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(
        finding,
        usage,
        previous_error=None,
    )

    assert isinstance(prompt, str)
    assert "test-role" in prompt


def test_build_user_prompt_is_deterministic():
    """Same input should produce the same prompt."""
    finding = make_finding()

    usage = {
        "actions_used": ["s3:GetObject"],
        "action_count": 1,
        "days_analyzed": 30,
    }

    prompt1 = _build_user_prompt(finding, usage)
    prompt2 = _build_user_prompt(finding, usage)

    assert prompt1 == prompt2


# =========================================================
# Edge cases for finding data
# =========================================================

def test_build_user_prompt_with_empty_policy():
    """Test prompt construction with an empty policy."""
    finding = make_finding()
    finding["policy_json"] = {}

    usage = {
        "actions_used": [],
        "action_count": 0,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert isinstance(prompt, str)


def test_build_user_prompt_with_multiple_findings_actions():
    """Test prompt with multiple risky actions in the finding."""
    finding = make_finding()
    finding["actions"] = [
        "s3:*",
        "iam:*",
        "ec2:*",
    ]

    usage = {
        "actions_used": ["s3:GetObject"],
        "action_count": 1,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert isinstance(prompt, str)
    assert "test-role" in prompt


def test_build_user_prompt_with_special_characters():
    """Test names/descriptions containing special characters."""
    finding = make_finding()
    finding["entity_name"] = "role-with-special_chars-123"
    finding["description"] = (
        'Risky policy: "*" access & unrestricted permissions.'
    )

    usage = {
        "actions_used": ["s3:GetObject"],
        "action_count": 1,
        "days_analyzed": 30,
    }

    prompt = _build_user_prompt(finding, usage)

    assert "role-with-special_chars-123" in prompt
    assert "unrestricted permissions" in prompt
