"""
ml_features.py — Feature extraction for XGBoost risk scoring
AI IAM Least-Privilege Enforcer

Converts a scanner finding (+ optional CloudTrail usage data) into a
numeric feature vector that XGBoost can learn from.

Expects finding dicts shaped like scanner.py's output:
    {"actions": [...], "resources": [...], "policy_type": "inline"|"managed",
     "entity_type": "role"|"user"|"group", ...}

Expects usage dicts shaped like cloudtrail_analyzer.py's output:
    {"actions_used": [...], "action_count": int, ...}
"""

FEATURE_NAMES = [
    "has_action_wildcard",
    "has_resource_wildcard",
    "has_service_wildcard",
    "num_actions",
    "num_services",
    "has_iam_action",
    "has_ec2_action",
    "has_kms_action",
    "has_lambda_action",
    "has_sts_action",
    "has_organizations_action",
    "has_admin_keyword",
    "is_inline_policy",
    "entity_is_role",
    "cloudtrail_action_count",
    "cloudtrail_usage_ratio",
]

HIGH_IMPACT_SERVICES = ("iam", "ec2", "kms", "lambda", "sts", "organizations")


def extract_features(finding: dict, usage_data: dict = None) -> dict:
    """
    finding: a scanner.py finding dict — must have 'actions', 'resources',
             'policy_type', 'entity_type' keys.
    usage_data: optional dict from cloudtrail_analyzer.py
                (actions_used, action_count). Pass {} if unavailable.
    """
    usage_data = usage_data or {}
    actions = finding.get("actions", []) or []
    resources = finding.get("resources", []) or []

    services = set()
    for a in actions:
        if isinstance(a, str) and ":" in a:
            services.add(a.split(":")[0])

    has_action_wildcard = 1 if "*" in actions else 0
    has_resource_wildcard = 1 if "*" in resources else 0
    has_service_wildcard = 1 if any(
        isinstance(a, str) and a.endswith(":*") and a != "*" for a in actions
    ) else 0

    actions_used = usage_data.get("actions_used", []) or []
    cloudtrail_action_count = len(actions_used)

    granted_estimate = max(len(actions), 1)
    if has_action_wildcard or has_service_wildcard:
        granted_estimate = 50
    usage_ratio = min(cloudtrail_action_count / granted_estimate, 1.0)

    return {
        "has_action_wildcard": has_action_wildcard,
        "has_resource_wildcard": has_resource_wildcard,
        "has_service_wildcard": has_service_wildcard,
        "num_actions": len(actions),
        "num_services": len(services),
        "has_iam_action": 1 if "iam" in services else 0,
        "has_ec2_action": 1 if "ec2" in services else 0,
        "has_kms_action": 1 if "kms" in services else 0,
        "has_lambda_action": 1 if "lambda" in services else 0,
        "has_sts_action": 1 if "sts" in services else 0,
        "has_organizations_action": 1 if "organizations" in services else 0,
        "has_admin_keyword": 1 if any(
            isinstance(a, str) and kw in a for a in actions for kw in ("Admin", "Full", "*")
        ) else 0,
        "is_inline_policy": 1 if finding.get("policy_type") == "inline" else 0,
        "entity_is_role": 1 if finding.get("entity_type") == "role" else 0,
        "cloudtrail_action_count": cloudtrail_action_count,
        "cloudtrail_usage_ratio": round(usage_ratio, 3),
    }


def features_to_vector(features: dict) -> list:
    return [features[name] for name in FEATURE_NAMES]