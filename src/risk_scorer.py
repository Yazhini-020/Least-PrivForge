"""
risk_scorer.py — Risk Scoring Engine (Module 2)
AI IAM Least-Privilege Enforcer

ML mode (default): loads trained XGBoost model from models/xgboost_model.pkl,
falls back to rule-based scoring if the model file is missing or empty.

Both modes take a finding dict shaped like scanner.py's output:
    {"actions": [...], "resources": [...], "policy_type": ..., "entity_type": ...}
and an optional usage_data dict shaped like cloudtrail_analyzer.py's output:
    {"actions_used": [...], "action_count": ...}
"""

import os
import pickle
import logging
from typing import Dict, Any, List

log = logging.getLogger(__name__)

MODEL_PATH = "models/xgboost_model.pkl"


class RiskScorer:
    def __init__(self, use_ml: bool = True):
        self.use_ml = use_ml
        self.model = None

        if use_ml and os.path.exists(MODEL_PATH) and os.path.getsize(MODEL_PATH) > 0:
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            log.info("Loaded XGBoost risk model from %s", MODEL_PATH)
        elif use_ml:
            log.warning(
                "ML mode requested but no trained model found at %s. "
                "Run `python -m src.train_model` first. Falling back to rule-based scoring.",
                MODEL_PATH
            )
            self.use_ml = True

    def score_policy(self, finding: dict, usage_data: dict = None) -> Dict[str, Any]:
        """
        Score a single finding.

        Args:
            finding: dict with 'actions', 'resources', 'policy_type', 'entity_type'
            usage_data: optional dict with 'actions_used', 'action_count'
        """
        usage_data = usage_data or {}
        if self.use_ml and self.model is not None:
            return self._score_ml(finding, usage_data)
        return self._score_rule_based(finding)

    def _score_ml(self, finding: dict, usage_data: dict) -> Dict[str, Any]:
        from src.ml_features import extract_features, features_to_vector
        import numpy as np

        features = extract_features(finding, usage_data)
        vector = np.array([features_to_vector(features)])

        score = float(self.model.predict(vector)[0])
        score = max(0.0, min(1.0, score))

        return {
            "score": round(score, 3),
            "severity": self._score_to_severity(score),
            "method": "xgboost",
            "features": features,
        }

    def _score_rule_based(self, finding: dict) -> Dict[str, Any]:
        score = 0.0
        reasons = []

        actions = finding.get("actions", []) or []
        resources = finding.get("resources", []) or []

        if "*" in actions:
            score += 0.5
            reasons.append("Action:* grants all permissions")

        service_wildcards = [a for a in actions if isinstance(a, str) and a.endswith(":*")]
        if service_wildcards:
            score += 0.3
            reasons.append(f"Service-level wildcard(s): {', '.join(sorted(service_wildcards))}")

        if "*" in resources:
            score += 0.35
            reasons.append("Resource:* exposes entire account")

        services = {a.split(":")[0] for a in actions if isinstance(a, str) and ":" in a}
        if len(services) > 3:
            score += 0.25
            reasons.append(f"Grants access to {len(services)} services")

        high_impact = {"iam", "ec2", "kms", "lambda", "sts", "organizations"}
        touched = services & high_impact
        if touched:
            score += 0.2
            reasons.append(f"Touches high-impact services: {', '.join(sorted(touched))}")

        score = min(score, 1.0)

        return {
            "score": round(score, 3),
            "severity": self._score_to_severity(score),
            "method": "rule_based",
            "reasons": reasons,
        }
    
    def _score_to_severity(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.35:
            return "MEDIUM"
        return "LOW"

    def score_multiple_policies(self, findings: List[dict], usage_data_map: dict = None) -> List[dict]:
        """
        Score a batch of findings, merging in usage data by entity_name.
        Returns findings sorted by score, highest risk first.
        """
        usage_data_map = usage_data_map or {}
        scored = []
        for finding in findings:
            usage = usage_data_map.get(finding.get("entity_name"), {})
            result = self.score_policy(finding, usage)
            scored.append({**finding, **result})
        return sorted(scored, key=lambda x: x["score"], reverse=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scorer = RiskScorer()
    test_finding = {"actions": ["*"], "resources": ["*"], "policy_type": "inline", "entity_type": "role"}
    result = scorer.score_policy(test_finding)
    print(result)