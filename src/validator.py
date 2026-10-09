"""
validator.py — IAM Policy Validator (3 checks)
AI IAM Least-Privilege Enforcer

Check 1 — structure: required fields present, right shape.
Check 2 — syntax: Action/Resource formats are valid AND non-empty.
          An empty Action list is syntactically legal JSON but grants
          nothing — not a usable least-privilege fix — so it is rejected
          here, not left for a human to notice in the report.
Check 3 — quota: AWS rejects policy documents over its size limit at
          deploy time; caught here before the user tries to apply it.
"""

import json
import re
from typing import Dict, Any, List

# AWS IAM policy size quotas. Managed policy document: 6144 chars.
# Inline policy max depends on which entity type it's attached to.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
INLINE_SIZE_LIMITS = {"user": 2048, "role": 10240, "group": 5120}
MANAGED_SIZE_LIMIT = 6144

ACTION_RE = re.compile(r"^[a-zA-Z0-9]+:[a-zA-Z0-9\*]+$")
ARN_RE = re.compile(r"^arn:aws[a-zA-Z-]*:[a-zA-Z0-9\-]*:[a-zA-Z0-9\-]*:\d{0,12}:.+$")
# AWS IAM actions that do not support resource-level permissions, so
# Resource:"*" is required for them. Only add an action here after
# confirming "Resource types" is empty for it in the AWS Service
# Authorization Reference:
# https://docs.aws.amazon.com/service-authorization/latest/reference/
REQUIRES_WILDCARD_RESOURCE = frozenset({
    "s3:ListAllMyBuckets",
    "ec2:DescribeInstances",
    "ec2:DescribeRegions",
    "cloudtrail:LookupEvents",
})


def action_requires_wildcard_resource(action: str) -> bool:
    """True if AWS itself requires Resource:"*" for this action, so an
    unscoped resource is a platform constraint, not an over-broad grant."""
    return action in REQUIRES_WILDCARD_RESOURCE

class PolicyValidator:

    def validate_policy_json(
        self,
        policy: Dict[str, Any],
        policy_type: str = "managed",
        entity_type: str = "role",
    ) -> Dict[str, Any]:
        structure = self._check_1_structure(policy)
        if not structure["is_valid"]:
            return {"is_valid": False, "errors": structure["errors"],
                     "checks": {"structure": structure}}

        syntax = self._check_2_syntax(policy)
        quota = self._check_3_quota(policy, policy_type, entity_type)

        all_errors = structure["errors"] + syntax["errors"] + quota["errors"]
        return {
            "is_valid": len(all_errors) == 0,
            "errors": all_errors,
            "checks": {"structure": structure, "syntax": syntax, "quota": quota},
        }

    def _check_1_structure(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        if not isinstance(policy, dict):
            return {"is_valid": False, "errors": ["Policy must be a JSON object"]}
        if policy.get("Version") != "2012-10-17":
            errors.append("Version must be the string '2012-10-17'")

        statements = policy.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or not statements:
            errors.append("Statement must be a non-empty array")
            return {"is_valid": False, "errors": errors}

        for i, st in enumerate(statements):
            if not isinstance(st, dict):
                errors.append(f"Statement {i} must be an object")
                continue
            if st.get("Effect") not in ("Allow", "Deny"):
                errors.append(f"Statement {i}: Effect must be 'Allow' or 'Deny'")
            if "Action" not in st:
                errors.append(f"Statement {i}: missing 'Action'")
            if "Resource" not in st:
                errors.append(f"Statement {i}: missing 'Resource'")

        return {"is_valid": len(errors) == 0, "errors": errors}

    def _check_2_syntax(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for i, st in enumerate(statements):
            actions = st.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            resources = st.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources

            if not actions:
                errors.append(f"Statement {i}: 'Action' must not be empty")
            if not resources:
                errors.append(f"Statement {i}: 'Resource' must not be empty")

            for a in actions:
                if not isinstance(a, str) or not (a == "*" or ACTION_RE.match(a)):
                    errors.append(f"Statement {i}: invalid action format '{a}'")

            for r in resources:
                if not isinstance(r, str) or not (r == "*" or ARN_RE.match(r)):
                    errors.append(f"Statement {i}: invalid resource format '{r}'")

        return {"is_valid": len(errors) == 0, "errors": errors}

    def _check_3_quota(
        self, policy: Dict[str, Any], policy_type: str, entity_type: str
    ) -> Dict[str, Any]:
        size = len(json.dumps(policy, separators=(",", ":")))
        limit = (
            MANAGED_SIZE_LIMIT
            if policy_type == "managed"
            else INLINE_SIZE_LIMITS.get(entity_type, 2048)
        )
        errors = []
        if size > limit:
            errors.append(
                f"Policy document is {size} chars, exceeds the AWS quota of "
                f"{limit} chars for a {policy_type} policy on a {entity_type}"
            )
        return {"is_valid": len(errors) == 0, "errors": errors, "size": size, "limit": limit}
    def check_resource_scope_claims(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        For every statement using Resource:"*", determine whether every
        action in it is one that genuinely requires a wildcard resource.
        If even one action doesn't need it, the "*" is a real over-broad
        grant, not an unavoidable platform constraint — flag it.
        """
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        findings = []
        for i, st in enumerate(statements):
            resources = st.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else resources
            if "*" not in resources:
                continue

            actions = st.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions

            unjustified = [a for a in actions if not action_requires_wildcard_resource(a)]
            justified = [a for a in actions if action_requires_wildcard_resource(a)]

            findings.append({
                "statement_index": i,
                "wildcard_fully_justified": len(unjustified) == 0,
                "actions_requiring_wildcard": justified,
                "actions_not_requiring_wildcard": unjustified,
            })

        return {"statements": findings}

if __name__ == "__main__":
    v = PolicyValidator()

    good = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket/*"}],
    }
    print("Valid policy:")
    print(json.dumps(v.validate_policy_json(good), indent=2))

    empty = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": [], "Resource": "*"}],
    }
    print("\nEmpty-action policy (should now fail):")
    print(json.dumps(v.validate_policy_json(empty), indent=2))