"""
test_risk_scorer.py — Tests for Risk Scoring Engine

These tests are completely offline.
They test model loading and fallback, the ML scoring path (with a fake
model and stubbed feature extraction), rule-based scoring, severity
thresholds, and batch scoring without needing a trained XGBoost model.
"""

import sys
import types
from unittest.mock import Mock

import pytest

import src.risk_scorer as rs
from src.risk_scorer import RiskScorer


class FakeModel:
    """Minimal stand-in for a trained model."""

    def __init__(self, prediction=0.5):
        self.prediction = prediction

    def predict(self, vector):
        return [self.prediction]


def make_finding(actions=None, resources=None):
    """Return a reusable finding."""
    return {
        "entity_name": "test-role",
        "entity_type": "role",
        "policy_type": "inline",
        "actions": actions if actions is not None else ["s3:GetObject"],
        "resources": resources if resources is not None else ["arn:aws:s3:::b/*"],
    }


def make_ml_scorer(monkeypatch, tmp_path, prediction=0.5):
    """Create a scorer that loads a fake model from a temporary file."""
    model_file = tmp_path / "model.pkl"
    model_file.write_bytes(b"fake")

    monkeypatch.setattr(rs, "MODEL_PATH", str(model_file))
    monkeypatch.setattr(rs.pickle, "load", lambda f: FakeModel(prediction))

    return RiskScorer(use_ml=True)


def stub_ml_features(monkeypatch, capture=None):
    """Replace src.ml_features with a tiny offline stub."""
    stub = types.ModuleType("src.ml_features")

    def extract_features(finding, usage_data):
        if capture is not None:
            capture["usage_data"] = usage_data
        return {"x": 1.0}

    stub.extract_features = extract_features
    stub.features_to_vector = lambda features: [features["x"]]
    monkeypatch.setitem(sys.modules, "src.ml_features", stub)


# =========================================================
# __init__() / model loading tests
# =========================================================

def test_init_rule_based_mode_has_no_model():
    """use_ml=False should not load a model."""
    scorer = RiskScorer(use_ml=False)

    assert scorer.model is None
    assert scorer.use_ml is False


def test_init_missing_model_file_falls_back(monkeypatch, tmp_path):
    """A missing model file should leave model as None."""
    monkeypatch.setattr(rs, "MODEL_PATH", str(tmp_path / "missing.pkl"))

    scorer = RiskScorer(use_ml=True)

    assert scorer.model is None


def test_init_empty_model_file_falls_back(monkeypatch, tmp_path):
    """An empty model file should leave model as None."""
    empty = tmp_path / "empty.pkl"
    empty.write_bytes(b"")
    monkeypatch.setattr(rs, "MODEL_PATH", str(empty))

    scorer = RiskScorer(use_ml=True)

    assert scorer.model is None


def test_init_loads_model_when_file_exists(monkeypatch, tmp_path):
    """A non-empty model file should be loaded."""
    scorer = make_ml_scorer(monkeypatch, tmp_path)

    assert isinstance(scorer.model, FakeModel)


def test_init_does_not_load_model_in_rule_based_mode(monkeypatch, tmp_path):
    """use_ml=False should ignore an existing model file."""
    model_file = tmp_path / "model.pkl"
    model_file.write_bytes(b"fake")
    monkeypatch.setattr(rs, "MODEL_PATH", str(model_file))
    load = Mock()
    monkeypatch.setattr(rs.pickle, "load", load)

    RiskScorer(use_ml=False)

    load.assert_not_called()


# =========================================================
# score_policy() routing tests
# =========================================================

def test_score_policy_rule_based_when_ml_disabled():
    """use_ml=False should use rule-based scoring."""
    result = RiskScorer(use_ml=False).score_policy(make_finding())

    assert result["method"] == "rule_based"


def test_score_policy_falls_back_when_model_missing(monkeypatch, tmp_path):
    """Missing model should still produce a rule-based score."""
    monkeypatch.setattr(rs, "MODEL_PATH", str(tmp_path / "missing.pkl"))

    result = RiskScorer(use_ml=True).score_policy(make_finding())

    assert result["method"] == "rule_based"


def test_score_policy_uses_ml_when_model_loaded(monkeypatch, tmp_path):
    """A loaded model should be used for scoring."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path, prediction=0.7)

    result = scorer.score_policy(make_finding())

    assert result["method"] == "xgboost"


def test_score_policy_passes_usage_data_to_features(monkeypatch, tmp_path):
    """usage_data should reach feature extraction."""
    capture = {}
    stub_ml_features(monkeypatch, capture)
    scorer = make_ml_scorer(monkeypatch, tmp_path)
    usage = {"actions_used": ["s3:GetObject"], "action_count": 1}

    scorer.score_policy(make_finding(), usage)

    assert capture["usage_data"] == usage


def test_score_policy_none_usage_becomes_empty_dict(monkeypatch, tmp_path):
    """Missing usage_data should be passed on as an empty dict."""
    capture = {}
    stub_ml_features(monkeypatch, capture)
    scorer = make_ml_scorer(monkeypatch, tmp_path)

    scorer.score_policy(make_finding())

    assert capture["usage_data"] == {}


# =========================================================
# _score_ml() tests
# =========================================================

def test_ml_score_is_clipped_to_one(monkeypatch, tmp_path):
    """Predictions above 1.0 should be clipped."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path, prediction=1.7)

    result = scorer.score_policy(make_finding())

    assert result["score"] == 1.0


def test_ml_score_is_clipped_to_zero(monkeypatch, tmp_path):
    """Negative predictions should be clipped to 0."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path, prediction=-0.5)

    result = scorer.score_policy(make_finding())

    assert result["score"] == 0.0


def test_ml_score_is_rounded(monkeypatch, tmp_path):
    """Scores should be rounded to 3 decimal places."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path, prediction=0.123456)

    result = scorer.score_policy(make_finding())

    assert result["score"] == 0.123


def test_ml_severity_follows_score(monkeypatch, tmp_path):
    """The ML result should include the matching severity."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path, prediction=0.9)

    result = scorer.score_policy(make_finding())

    assert result["severity"] == "CRITICAL"


def test_ml_result_includes_features(monkeypatch, tmp_path):
    """The ML result should expose the features used."""
    stub_ml_features(monkeypatch)
    scorer = make_ml_scorer(monkeypatch, tmp_path)

    result = scorer.score_policy(make_finding())

    assert result["features"] == {"x": 1.0}


# =========================================================
# Rule-based scoring tests
# =========================================================

def test_rule_safe_policy_is_low():
    """A narrow policy should score zero."""
    result = RiskScorer(use_ml=False).score_policy(make_finding())

    assert result["score"] == 0.0
    assert result["severity"] == "LOW"


def test_rule_full_wildcard_is_critical():
    """Action '*' on Resource '*' should be critical."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["*"], resources=["*"])
    )

    assert result["score"] == pytest.approx(0.85)
    assert result["severity"] == "CRITICAL"


def test_rule_global_action_wildcard_only():
    """Action '*' alone adds 0.5."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["*"])
    )

    assert result["score"] == pytest.approx(0.5)
    assert result["severity"] == "MEDIUM"


def test_rule_service_wildcard():
    """A service wildcard adds 0.3."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["s3:*"])
    )

    assert result["score"] == pytest.approx(0.3)
    assert result["severity"] == "LOW"


def test_rule_resource_wildcard_only():
    """Resource '*' alone adds 0.35."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(resources=["*"])
    )

    assert result["score"] == pytest.approx(0.35)
    assert result["severity"] == "MEDIUM"


def test_rule_high_impact_service():
    """A specific high-impact service action adds 0.2."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["iam:GetUser"])
    )

    assert result["score"] == pytest.approx(0.2)


def test_rule_high_impact_service_wildcard_combined():
    """iam:* adds the wildcard and high-impact penalties."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["iam:*"])
    )

    assert result["score"] == pytest.approx(0.5)


def test_rule_more_than_three_services():
    """Four low-impact services add 0.25."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=[
            "s3:GetObject", "dynamodb:GetItem",
            "sqs:SendMessage", "sns:Publish",
        ])
    )

    assert result["score"] == pytest.approx(0.25)


def test_rule_exactly_three_services_has_no_bonus():
    """Three services do not trigger the multi-service penalty."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=[
            "s3:GetObject", "dynamodb:GetItem", "sqs:SendMessage",
        ])
    )

    assert result["score"] == 0.0


def test_rule_score_is_capped_at_one():
    """The score must never exceed 1.0."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(
            actions=["*", "iam:*", "ec2:*", "s3:*", "kms:*"],
            resources=["*"],
        )
    )

    assert result["score"] == 1.0
    assert result["severity"] == "CRITICAL"


def test_rule_none_actions_and_resources_are_handled():
    """None values should be treated as empty lists."""
    finding = make_finding()
    finding["actions"] = None
    finding["resources"] = None

    result = RiskScorer(use_ml=False).score_policy(finding)

    assert result["score"] == 0.0


def test_rule_non_string_actions_are_ignored():
    """Non-string actions should not crash scoring."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=[123, None])
    )

    assert result["score"] == 0.0


def test_rule_reasons_empty_for_safe_policy():
    """A safe policy should have no reasons."""
    result = RiskScorer(use_ml=False).score_policy(make_finding())

    assert result["reasons"] == []


def test_rule_reason_lists_sorted_service_wildcards():
    """Service wildcards should be listed in sorted order."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["s3:*", "ec2:*"])
    )

    assert any("ec2:*, s3:*" in r for r in result["reasons"])


def test_rule_reason_lists_sorted_high_impact_services():
    """High-impact services should be listed in sorted order."""
    result = RiskScorer(use_ml=False).score_policy(
        make_finding(actions=["iam:GetUser", "ec2:DescribeInstances"])
    )

    assert any("ec2, iam" in r for r in result["reasons"])


# =========================================================
# _score_to_severity() tests
# =========================================================

def test_severity_critical_at_080():
    """0.8 is the CRITICAL boundary."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.8) == "CRITICAL"


def test_severity_high_just_below_080():
    """Just below 0.8 is HIGH."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.79) == "HIGH"


def test_severity_high_at_060():
    """0.6 is the HIGH boundary."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.6) == "HIGH"


def test_severity_medium_just_below_060():
    """Just below 0.6 is MEDIUM."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.59) == "MEDIUM"


def test_severity_medium_at_035():
    """0.35 is the MEDIUM boundary."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.35) == "MEDIUM"


def test_severity_low_just_below_035():
    """Just below 0.35 is LOW."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.349) == "LOW"


def test_severity_low_at_zero():
    """Zero is LOW."""
    assert RiskScorer(use_ml=False)._score_to_severity(0.0) == "LOW"


# =========================================================
# score_multiple_policies() tests
# =========================================================

def test_batch_empty_list():
    """No findings should produce no results."""
    assert RiskScorer(use_ml=False).score_multiple_policies([]) == []


def test_batch_sorted_highest_risk_first():
    """Results should be sorted by score descending."""
    safe = make_finding()
    risky = make_finding(actions=["*"], resources=["*"])

    result = RiskScorer(use_ml=False).score_multiple_policies([safe, risky])

    assert result[0]["score"] > result[1]["score"]


def test_batch_merges_finding_and_score_fields():
    """Each result should keep the original finding fields."""
    result = RiskScorer(use_ml=False).score_multiple_policies([make_finding()])

    assert result[0]["entity_name"] == "test-role"
    assert "score" in result[0]
    assert "severity" in result[0]


def test_batch_passes_usage_by_entity_name():
    """usage_data_map should be looked up by entity_name."""
    scorer = RiskScorer(use_ml=False)
    scorer.score_policy = Mock(return_value={"score": 0.1})
    usage = {"actions_used": ["s3:GetObject"], "action_count": 1}
    finding = make_finding()

    scorer.score_multiple_policies([finding], {"test-role": usage})

    scorer.score_policy.assert_called_once_with(finding, usage)


def test_batch_missing_usage_defaults_to_empty_dict():
    """An entity without usage data should get an empty dict."""
    scorer = RiskScorer(use_ml=False)
    scorer.score_policy = Mock(return_value={"score": 0.1})
    finding = make_finding()

    scorer.score_multiple_policies([finding], {"other-role": {"x": 1}})

    scorer.score_policy.assert_called_once_with(finding, {})


def test_batch_without_usage_map():
    """usage_data_map is optional."""
    result = RiskScorer(use_ml=False).score_multiple_policies(
        [make_finding()], None
    )

    assert len(result) == 1