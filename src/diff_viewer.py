"""
diff_viewer.py — Before/After Policy Diff
AI IAM Least-Privilege Enforcer

Takes one entry from fixes_report.json and renders a side-by-side
before/after comparison: original policy, generated policy, what
changed, and whether the resource-scope claims in the explanation
are independently verified by the validator — not just asserted.
"""

import json
from typing import Dict, Any, List


def build_diff(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    finding: one entry from fixes_report.json (must have policy_json,
    ai_recommendation with policy/removed_actions/explanation).
    """
    rec = finding.get("ai_recommendation", {})

    if rec.get("skipped") or not rec.get("success"):
        return {
            "entity_name": finding["entity_name"],
            "status": "skipped" if rec.get("skipped") else "failed",
            "reason": rec.get("explanation", "No explanation provided"),
        }

    before = finding["policy_json"]
    after = rec["policy"]

    before_actions = _flatten_actions(before)
    after_actions = _flatten_actions(after)

    from src.validator import PolicyValidator
    validator = PolicyValidator()
    scope_check = validator.check_resource_scope_claims(after)
    unjustified = [s for s in scope_check["statements"] if not s["wildcard_fully_justified"]]

    return {
        "entity_name": finding["entity_name"],
        "entity_type": finding["entity_type"],
        "status": "fixed",
        "severity": finding.get("severity"),
        "risk_score": finding.get("score"),
        "before": {
            "actions": before_actions,
            "action_count": len(before_actions),
        },
        "after": {
            "actions": after_actions,
            "action_count": len(after_actions),
        },
        "removed_actions": rec.get("removed_actions", []),
        "wildcards_before": sum(1 for a in before_actions if a == "*" or a.endswith(":*")),
        "wildcards_after": sum(1 for a in after_actions if a == "*" or a.endswith(":*")),
        "explanation": rec.get("explanation", ""),
        "confidence": rec.get("confidence"),
        "resource_scope_verified": len(unjustified) == 0,
        "resource_scope_issues": unjustified,
    }


def _flatten_actions(policy: Dict[str, Any]) -> List[str]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    actions = []
    for st in statements:
        a = st.get("Action", [])
        a = [a] if isinstance(a, str) else a
        actions.extend(a)
    return actions

def render_text(diff: Dict[str, Any]) -> str:
    if diff["status"] != "fixed":
        return f"{diff['entity_name']}: {diff['status']} — {diff['reason']}"

    lines = [
        f"=== {diff['entity_name']} ({diff['entity_type']}) ===",
        f"Severity: {diff['severity']}  Risk score: {diff['risk_score']}",
        "",
        f"BEFORE ({diff['before']['action_count']} action(s)):",
        *[f"  - {a}" + ("  (wildcard: every action in that service)" if a == "*" or a.endswith(":*") else "")
        for a in diff["before"]["actions"]],
        f"AFTER ({diff['after']['action_count']} action(s)):",
        *[f"  + {a}" for a in diff["after"]["actions"]],
        "",
        f"Wildcard actions: {diff['wildcards_before']} → {diff['wildcards_after']}",
        f"Confidence: {diff['confidence']}",
        f"Resource-scope claims verified: {'YES' if diff['resource_scope_verified'] else 'NO — review flagged below'}",
    ]
    if not diff["resource_scope_verified"]:
        for issue in diff["resource_scope_issues"]:
            lines.append(f"  ⚠ Statement {issue['statement_index']}: "
                          f"{issue['actions_not_requiring_wildcard']} do not require Resource:\"*\"")
    lines.append(f"\nExplanation: {diff['explanation']}")
    return "\n".join(lines)


if __name__ == "__main__":
    with open("fixes_report.json") as f:
        findings = json.load(f)

    for finding in findings:
        diff = build_diff(finding)
        print(render_text(diff))
        print()