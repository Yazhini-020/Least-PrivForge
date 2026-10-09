"""
test_validator.py — Tests for IAM Policy Validator

These tests are completely offline.
They test the three validation checks (structure, syntax, quota),
AWS size limits for managed and inline policies, and the combined
validate_policy_json() result without calling any external service.
"""

import json

from src.validator import (
    PolicyValidator,
    INLINE_SIZE_LIMITS,
    MANAGED_SIZE_LIMIT,
)


def make_policy(action="s3:GetObject", resource="arn:aws:s3:::bucket/*",
                effect="Allow"):
    """Return a reusable valid policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": effect, "Action": action, "Resource": resource}
        ],
    }


def make_policy_of_size(target_size):
    """Return a valid policy whose compact JSON is exactly target_size chars."""
    prefix = "arn:aws:s3:::"
    base = len(json.dumps(make_policy(resource=prefix), separators=(",", ":")))
    return make_policy(resource=prefix + "a" * (target_size - base))


def compact_size(policy):
    """Return the compact JSON size used by the validator."""
    return len(json.dumps(policy, separators=(",", ":")))


# =========================================================
# _check_1_structure() tests
# =========================================================

def test_structure_valid_policy():
    """A well-formed policy should pass the structure check."""
    result = PolicyValidator()._check_1_structure(make_policy())

    assert result["is_valid"] is True
    assert result["errors"] == []


def test_structure_rejects_list():
    """A JSON array is not a policy."""
    result = PolicyValidator()._check_1_structure([])

    assert result["is_valid"] is False
    assert "JSON object" in result["errors"][0]


def test_structure_rejects_none():
    """None is not a policy."""
    result = PolicyValidator()._check_1_structure(None)

    assert result["is_valid"] is False


def test_structure_rejects_string():
    """A string is not a policy."""
    result = PolicyValidator()._check_1_structure("policy")

    assert result["is_valid"] is False


def test_structure_wrong_version():
    """An old policy version should be rejected."""
    policy = make_policy()
    policy["Version"] = "2008-10-17"

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is False
    assert any("Version" in e for e in result["errors"])


def test_structure_missing_version():
    """A missing Version should be rejected."""
    policy = make_policy()
    del policy["Version"]

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is False
    assert any("Version" in e for e in result["errors"])


def test_structure_missing_statement():
    """A missing Statement should be rejected."""
    result = PolicyValidator()._check_1_structure({"Version": "2012-10-17"})

    assert result["is_valid"] is False
    assert any("Statement" in e for e in result["errors"])


def test_structure_empty_statement_list():
    """An empty Statement list should be rejected."""
    result = PolicyValidator()._check_1_structure(
        {"Version": "2012-10-17", "Statement": []}
    )

    assert result["is_valid"] is False
    assert any("non-empty" in e for e in result["errors"])


def test_structure_statement_as_dict_is_accepted():
    """A single statement object is valid IAM and should be accepted."""
    policy = make_policy()
    policy["Statement"] = policy["Statement"][0]

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is True


def test_structure_statement_item_not_object():
    """A statement that is not an object should be reported."""
    policy = {"Version": "2012-10-17", "Statement": ["bad"]}

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is False
    assert any("Statement 0 must be an object" in e for e in result["errors"])


def test_structure_invalid_effect():
    """Effect must be Allow or Deny."""
    result = PolicyValidator()._check_1_structure(make_policy(effect="Maybe"))

    assert result["is_valid"] is False
    assert any("Effect" in e for e in result["errors"])


def test_structure_deny_effect_is_valid():
    """Deny is a valid Effect."""
    result = PolicyValidator()._check_1_structure(make_policy(effect="Deny"))

    assert result["is_valid"] is True


def test_structure_missing_action():
    """A statement without Action should be reported."""
    policy = make_policy()
    del policy["Statement"][0]["Action"]

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is False
    assert any("missing 'Action'" in e for e in result["errors"])


def test_structure_missing_resource():
    """A statement without Resource should be reported."""
    policy = make_policy()
    del policy["Statement"][0]["Resource"]

    result = PolicyValidator()._check_1_structure(policy)

    assert result["is_valid"] is False
    assert any("missing 'Resource'" in e for e in result["errors"])


def test_structure_reports_statement_index():
    """Errors should identify which statement is broken."""
    policy = make_policy()
    policy["Statement"].append({"Effect": "Bad", "Action": "s3:*", "Resource": "*"})

    result = PolicyValidator()._check_1_structure(policy)

    assert any("Statement 1" in e for e in result["errors"])


# =========================================================
# _check_2_syntax() tests
# =========================================================

def test_syntax_valid_policy():
    """A valid policy should pass the syntax check."""
    result = PolicyValidator()._check_2_syntax(make_policy())

    assert result["is_valid"] is True


def test_syntax_string_action_and_resource_accepted():
    """String Action/Resource values are normalized to lists."""
    result = PolicyValidator()._check_2_syntax(
        make_policy(action="s3:GetObject", resource="*")
    )

    assert result["is_valid"] is True


def test_syntax_list_action_accepted():
    """Lists of valid actions should pass."""
    result = PolicyValidator()._check_2_syntax(
        make_policy(action=["s3:GetObject", "s3:PutObject"])
    )

    assert result["is_valid"] is True


def test_syntax_global_wildcard_action_accepted():
    """The '*' action is syntactically valid."""
    result = PolicyValidator()._check_2_syntax(make_policy(action="*"))

    assert result["is_valid"] is True


def test_syntax_service_wildcard_action_accepted():
    """A service wildcard like s3:* is syntactically valid."""
    result = PolicyValidator()._check_2_syntax(make_policy(action="s3:*"))

    assert result["is_valid"] is True


def test_syntax_empty_action_list_rejected():
    """An empty Action list grants nothing and must be rejected."""
    result = PolicyValidator()._check_2_syntax(make_policy(action=[]))

    assert result["is_valid"] is False
    assert any("'Action' must not be empty" in e for e in result["errors"])


def test_syntax_empty_resource_list_rejected():
    """An empty Resource list must be rejected."""
    result = PolicyValidator()._check_2_syntax(make_policy(resource=[]))

    assert result["is_valid"] is False
    assert any("'Resource' must not be empty" in e for e in result["errors"])


def test_syntax_action_without_colon_rejected():
    """An action missing the service prefix is invalid."""
    result = PolicyValidator()._check_2_syntax(make_policy(action="GetObject"))

    assert result["is_valid"] is False
    assert any("invalid action format" in e for e in result["errors"])


def test_syntax_action_with_space_rejected():
    """Whitespace in an action is invalid."""
    result = PolicyValidator()._check_2_syntax(make_policy(action="s3: GetObject"))

    assert result["is_valid"] is False


def test_syntax_non_string_action_rejected():
    """A non-string action is invalid."""
    result = PolicyValidator()._check_2_syntax(make_policy(action=[123]))

    assert result["is_valid"] is False
    assert any("invalid action format" in e for e in result["errors"])


def test_syntax_invalid_resource_rejected():
    """A bare name is not a valid resource ARN."""
    result = PolicyValidator()._check_2_syntax(make_policy(resource="my-bucket"))

    assert result["is_valid"] is False
    assert any("invalid resource format" in e for e in result["errors"])


def test_syntax_non_string_resource_rejected():
    """A non-string resource is invalid."""
    result = PolicyValidator()._check_2_syntax(make_policy(resource=[42]))

    assert result["is_valid"] is False


def test_syntax_wildcard_resource_accepted():
    """The '*' resource is syntactically valid."""
    result = PolicyValidator()._check_2_syntax(make_policy(resource="*"))

    assert result["is_valid"] is True


def test_syntax_arn_with_account_id_accepted():
    """An IAM ARN with a 12-digit account ID should be accepted."""
    result = PolicyValidator()._check_2_syntax(
        make_policy(resource="arn:aws:iam::123456789012:role/my-role")
    )

    assert result["is_valid"] is True


def test_syntax_reports_statement_index():
    """Syntax errors should identify the broken statement."""
    policy = make_policy()
    policy["Statement"].append(
        {"Effect": "Allow", "Action": "bad", "Resource": "*"}
    )

    result = PolicyValidator()._check_2_syntax(policy)

    assert any("Statement 1" in e for e in result["errors"])


def test_syntax_collects_multiple_errors():
    """Several problems in one statement should all be reported."""
    result = PolicyValidator()._check_2_syntax(
        make_policy(action="bad", resource="also-bad")
    )

    assert len(result["errors"]) == 2


# =========================================================
# _check_3_quota() tests
# =========================================================

def test_quota_small_policy_passes():
    """A small policy is within every quota."""
    result = PolicyValidator()._check_3_quota(make_policy(), "managed", "role")

    assert result["is_valid"] is True
    assert result["errors"] == []


def test_quota_reports_size():
    """The result should report the compact JSON size."""
    policy = make_policy()

    result = PolicyValidator()._check_3_quota(policy, "managed", "role")

    assert result["size"] == compact_size(policy)


def test_quota_managed_limit_value():
    """Managed policies use the 6144-char limit."""
    result = PolicyValidator()._check_3_quota(make_policy(), "managed", "user")

    assert result["limit"] == MANAGED_SIZE_LIMIT == 6144


def test_quota_inline_user_limit_value():
    """Inline user policies use the 2048-char limit."""
    result = PolicyValidator()._check_3_quota(make_policy(), "inline", "user")

    assert result["limit"] == INLINE_SIZE_LIMITS["user"] == 2048


def test_quota_inline_role_limit_value():
    """Inline role policies use the 10240-char limit."""
    result = PolicyValidator()._check_3_quota(make_policy(), "inline", "role")

    assert result["limit"] == INLINE_SIZE_LIMITS["role"] == 10240


def test_quota_inline_group_limit_value():
    """Inline group policies use the 5120-char limit."""
    result = PolicyValidator()._check_3_quota(make_policy(), "inline", "group")

    assert result["limit"] == INLINE_SIZE_LIMITS["group"] == 5120


def test_quota_unknown_entity_defaults_to_2048():
    """An unknown entity type falls back to the strictest inline limit."""
    result = PolicyValidator()._check_3_quota(make_policy(), "inline", "robot")

    assert result["limit"] == 2048


def test_quota_exactly_at_managed_limit_passes():
    """A managed policy exactly at the limit is allowed."""
    policy = make_policy_of_size(6144)

    result = PolicyValidator()._check_3_quota(policy, "managed", "role")

    assert result["size"] == 6144
    assert result["is_valid"] is True


def test_quota_one_over_managed_limit_fails():
    """A managed policy one char over the limit is rejected."""
    policy = make_policy_of_size(6145)

    result = PolicyValidator()._check_3_quota(policy, "managed", "role")

    assert result["is_valid"] is False


def test_quota_inline_user_over_limit_fails():
    """An inline user policy over 2048 chars is rejected."""
    policy = make_policy_of_size(2049)

    result = PolicyValidator()._check_3_quota(policy, "inline", "user")

    assert result["is_valid"] is False


def test_quota_same_policy_ok_as_inline_role():
    """A 3000-char policy fails for an inline user but passes for a role."""
    policy = make_policy_of_size(3000)
    validator = PolicyValidator()

    assert validator._check_3_quota(policy, "inline", "user")["is_valid"] is False
    assert validator._check_3_quota(policy, "inline", "role")["is_valid"] is True


def test_quota_error_message_contains_details():
    """The error should mention size, limit, policy type and entity type."""
    policy = make_policy_of_size(2049)

    result = PolicyValidator()._check_3_quota(policy, "inline", "user")

    message = result["errors"][0]
    assert "2049" in message
    assert "2048" in message
    assert "inline" in message
    assert "user" in message


# =========================================================
# validate_policy_json() tests
# =========================================================

def test_validate_valid_policy():
    """A valid policy should pass all checks."""
    result = PolicyValidator().validate_policy_json(make_policy())

    assert result["is_valid"] is True
    assert result["errors"] == []
    assert set(result["checks"]) == {"structure", "syntax", "quota"}


def test_validate_structure_failure_skips_other_checks():
    """A structurally broken policy should only report the structure check."""
    result = PolicyValidator().validate_policy_json({"Version": "bad"})

    assert result["is_valid"] is False
    assert set(result["checks"]) == {"structure"}


def test_validate_empty_action_policy_fails():
    """The empty-Action policy must fail overall."""
    result = PolicyValidator().validate_policy_json(make_policy(action=[]))

    assert result["is_valid"] is False
    assert any("must not be empty" in e for e in result["errors"])


def test_validate_combines_syntax_and_quota_errors():
    """Syntax and quota errors should be combined in one error list."""
    policy = make_policy_of_size(2049)
    policy["Statement"][0]["Action"] = "bad"

    result = PolicyValidator().validate_policy_json(policy, "inline", "user")

    assert result["is_valid"] is False
    assert len(result["errors"]) == 1
    assert "invalid action format 'bad'" in result["errors"][0]


def test_validate_defaults_to_managed_policy_on_role():
    """Defaults are policy_type='managed' and entity_type='role'."""
    result = PolicyValidator().validate_policy_json(make_policy())

    assert result["checks"]["quota"]["limit"] == MANAGED_SIZE_LIMIT


def test_validate_passes_inline_arguments_to_quota():
    """Inline policy_type/entity_type should select the inline limit."""
    result = PolicyValidator().validate_policy_json(
        make_policy(), policy_type="inline", entity_type="group"
    )

    assert result["checks"]["quota"]["limit"] == 5120
def test_scope_check_accepts_required_wildcard():
    p = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}]}
    r = PolicyValidator().check_resource_scope_claims(p)
    assert r["statements"][0]["wildcard_fully_justified"] is True

def test_scope_check_flags_unnecessary_wildcard():
    p = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}
    r = PolicyValidator().check_resource_scope_claims(p)
    assert r["statements"][0]["wildcard_fully_justified"] is False
    assert r["statements"][0]["actions_not_requiring_wildcard"] == ["s3:GetObject"]