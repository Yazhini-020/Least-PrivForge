
"""
test_scorer.py — Tests for RiskScorer (Module 2)
AI IAM Least-Privilege Enforcer

All tests use use_ml=False so results are deterministic and
do not depend on models/xgboost_model.pkl.
"""

from src.risk_scorer import RiskScorer


# ---------------------------------------------------------
# Initialization
# ---------------------------------------------------------

def test_scorer_init():
    scorer = RiskScorer(use_ml=False)

    assert scorer is not None
    assert scorer.use_ml is False


# ---------------------------------------------------------
# Basic risk scoring
# ---------------------------------------------------------

def test_critical_finding_full_admin():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["*"],
        "resources": ["*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["severity"] == "CRITICAL"
    assert result["score"] > 0.7
    assert result["method"] == "rule_based"


def test_high_risk_multi_service_wildcard():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:*", "iam:*", "ec2:*", "lambda:*"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["severity"] in ["HIGH", "CRITICAL"]
    assert result["score"] > 0


def test_low_risk_scoped_policy():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject", "s3:PutObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["severity"] == "LOW"
    assert result["score"] < 0.4


# ---------------------------------------------------------
# Edge cases — actions
# ---------------------------------------------------------

def test_single_wildcard_action():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["*"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result
    assert result["score"] >= 0


def test_service_wildcard_action():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:*"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["score"] >= 0
    assert result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_many_specific_actions():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket",
            "s3:GetBucketLocation",
        ],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["score"] >= 0
    assert result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_empty_actions():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": [],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result


def test_missing_actions():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result


# ---------------------------------------------------------
# Edge cases — resources
# ---------------------------------------------------------

def test_wildcard_resource():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": ["*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["score"] >= 0
    assert result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_multiple_resources():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": [
            "arn:aws:s3:::bucket1/*",
            "arn:aws:s3:::bucket2/*",
        ],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result


def test_empty_resources():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": [],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result


def test_missing_resources():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result


# ---------------------------------------------------------
# Policy type edge cases
# ---------------------------------------------------------

def test_managed_policy():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["*"],
        "resources": ["*"],
        "policy_type": "managed",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["severity"] in ["HIGH", "CRITICAL"]
    assert result["score"] > 0


def test_inline_policy():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert result["method"] == "rule_based"


# ---------------------------------------------------------
# Entity type edge cases
# ---------------------------------------------------------

def test_user_entity():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["*"],
        "resources": ["*"],
        "policy_type": "inline",
        "entity_type": "user",
    }

    result = scorer.score_policy(finding)

    assert result["severity"] in ["HIGH", "CRITICAL"]


def test_group_entity():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "group",
    }

    result = scorer.score_policy(finding)

    assert "score" in result


# ---------------------------------------------------------
# Score boundaries
# ---------------------------------------------------------

def test_score_is_between_zero_and_one():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::bucket/*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
        {
            "actions": ["s3:*"],
            "resources": ["*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
        {
            "actions": ["*"],
            "resources": ["*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
    ]

    for finding in findings:
        result = scorer.score_policy(finding)

        assert 0 <= result["score"] <= 1


def test_result_contains_expected_fields():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result = scorer.score_policy(finding)

    assert "score" in result
    assert "severity" in result
    assert "method" in result


# ---------------------------------------------------------
# Multiple policies
# ---------------------------------------------------------

def test_score_multiple_policies_sorted_by_risk():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "safe-role",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::b/*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
        {
            "entity_name": "risky-role",
            "actions": ["*"],
            "resources": ["*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
    ]

    scored = scorer.score_multiple_policies(findings)

    assert scored[0]["entity_name"] == "risky-role"
    assert scored[0]["score"] >= scored[1]["score"]


def test_score_multiple_empty_list():
    scorer = RiskScorer(use_ml=False)

    scored = scorer.score_multiple_policies([])

    assert scored == []


def test_score_multiple_single_finding():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "single-role",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::b/*"],
            "policy_type": "inline",
            "entity_type": "role",
        }
    ]

    scored = scorer.score_multiple_policies(findings)

    assert len(scored) == 1
    assert scored[0]["entity_name"] == "single-role"


def test_score_multiple_preserves_findings():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "role-a",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::a/*"],
            "policy_type": "inline",
            "entity_type": "role",
        },
        {
            "entity_name": "role-b",
            "actions": ["s3:ListBucket"],
            "resources": ["arn:aws:s3:::b"],
            "policy_type": "inline",
            "entity_type": "role",
        },
    ]

    scored = scorer.score_multiple_policies(findings)

    assert len(scored) == len(findings)
    assert {item["entity_name"] for item in scored} == {"role-a", "role-b"}


# ---------------------------------------------------------
# Usage data
# ---------------------------------------------------------

def test_usage_data_merged_by_entity_name():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "my-role",
            "actions": ["*"],
            "resources": ["*"],
            "policy_type": "inline",
            "entity_type": "role",
        }
    ]

    usage_data_map = {
        "my-role": {
            "actions_used": ["s3:GetObject"],
            "action_count": 1,
        }
    }

    scored = scorer.score_multiple_policies(findings, usage_data_map)

    assert scored[0]["entity_name"] == "my-role"
    assert "score" in scored[0]


def test_usage_data_missing_entity():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "role-a",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::a/*"],
            "policy_type": "inline",
            "entity_type": "role",
        }
    ]

    usage_data_map = {
        "role-b": {
            "actions_used": ["s3:PutObject"],
            "action_count": 1,
        }
    }

    scored = scorer.score_multiple_policies(findings, usage_data_map)

    assert len(scored) == 1
    assert scored[0]["entity_name"] == "role-a"


def test_empty_usage_data():
    scorer = RiskScorer(use_ml=False)

    findings = [
        {
            "entity_name": "role-a",
            "actions": ["s3:GetObject"],
            "resources": ["arn:aws:s3:::a/*"],
            "policy_type": "inline",
            "entity_type": "role",
        }
    ]

    scored = scorer.score_multiple_policies(findings, {})

    assert len(scored) == 1
    assert "score" in scored[0]


# ---------------------------------------------------------
# Regression / consistency tests
# ---------------------------------------------------------

def test_same_input_gives_same_result():
    scorer = RiskScorer(use_ml=False)

    finding = {
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    result1 = scorer.score_policy(finding)
    result2 = scorer.score_policy(finding)

    assert result1 == result2


def test_full_admin_is_riskier_than_scoped_access():
    scorer = RiskScorer(use_ml=False)

    scoped = {
        "actions": ["s3:GetObject"],
        "resources": ["arn:aws:s3:::bucket/*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    admin = {
        "actions": ["*"],
        "resources": ["*"],
        "policy_type": "inline",
        "entity_type": "role",
    }

    scoped_result = scorer.score_policy(scoped)
    admin_result = scorer.score_policy(admin)

    assert admin_result["score"] > scoped_result["score"]