"""
scanner.py — IAM Policy Scanner (Module 1)
AI IAM Least-Privilege Enforcer

What this file does
-------------------
Scans every IAM entity in an AWS account (roles, users, groups),
reads all their attached policies (inline + managed), and detects
five types of over-privileged wildcard patterns.

Two modes
---------
USE_MOCK = True   → reads from src/mock_data.py  (default, no AWS needed)
USE_MOCK = False  → connects to real AWS via boto3 (requires aws configure)

Output shape
------------
Every function ultimately returns a list of "scan result" dicts in this
shared format (agreed with Member 2 / risk_scorer.py):

    {
        "entity_name":  "lambda-data-processor",
        "entity_type":  "role",             # role | user | group
        "arn":          "arn:aws:iam::...", # unique AWS identifier
        "policy_name":  "lambda-inline",
        "policy_type":  "inline",           # inline | managed
        "policy_json":  { ... },            # full policy document
        "finding_type": "FULL_ADMIN_ACCESS",# see FINDING TYPES below
        "description":  "...",              # human-readable explanation
        "actions":      ["*"],              # the problematic action list
        "resources":    ["*"],              # the problematic resource list
        "ml_score":     None,               # filled in by risk_scorer.py
        "severity":     None,               # filled in by risk_scorer.py
    }

Finding types (5 total)
-----------------------
FULL_ADMIN_ACCESS                  — Action:* + Resource:*       → always CRITICAL
WILDCARD_ACTION                    — Action:* only               → always CRITICAL
SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE — service:* + Resource:* → HIGH or CRITICAL
SERVICE_WILDCARD_ACTION            — service:* on specific ARN   → MEDIUM
WILDCARD_RESOURCE                  — specific actions + Resource:*→ MEDIUM

Author: Member 1
Sprint: Week 1
"""

import json
import logging
from typing import Optional

# ── configuration ──────────────────────────────────────────────────────────────

USE_MOCK = True  # ← flip to False when AWS credentials are configured

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ── constants ──────────────────────────────────────────────────────────────────

# Services whose wildcard actions are escalated one severity level because
# they enable privilege escalation or high-blast-radius damage.
HIGH_IMPACT_SERVICES = frozenset({
    "iam",           # create users, attach policies → full account takeover
    "ec2",           # spin up resources, move laterally
    "kms",           # decrypt any encrypted data in the account
    "lambda",        # run arbitrary code with other roles' permissions
    "organizations", # affect all child accounts in an AWS Org
    "sts",           # assume any role in the account
})
# AWS-owned service-linked role name prefixes. These roles are created and
# controlled entirely by AWS itself — the wildcard resources inside them are
# by design, not a misconfiguration, and cannot be scoped down by developers.
AWS_MANAGED_ROLE_PREFIXES = (
    "AWSServiceRoleFor",
    "AWSReservedSSO_",
    "OrganizationAccountAccessRole",
)

# AWS-managed policy ARNs always start with this prefix (vs customer-managed
# policies, which start with arn:aws:iam::<account-id>:policy/...).
AWS_MANAGED_POLICY_ARN_PREFIX = "arn:aws:iam::aws:policy/"

# High-privilege AWS-managed policies are NEVER skipped by the managed-policy
# filter, even though AWS authors their content. The risk here isn't the
# policy's wording — it's the decision by someone on your team to attach it.
# A group/user/role with AdministratorAccess attached is functionally
# identical to Action:"*" + Resource:"*" and must always be scanned/flagged.
HIGH_PRIVILEGE_MANAGED_POLICY_ARNS = frozenset({
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
})

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — DATA SOURCE
#  Toggle between mock data (development) and real AWS (production)
# ══════════════════════════════════════════════════════════════════════════════

def _get_iam_client():
    """
    Return a boto3 IAM client.
    Called only when USE_MOCK = False.

    Credentials are read automatically from:
        1. Environment variables (AWS_ACCESS_KEY_ID etc.)
        2. ~/.aws/credentials (set by `aws configure`)
        3. IAM instance profile (if running on EC2/Lambda)
    """
    try:
        import boto3
        return boto3.client("iam")
    except ImportError:
        raise RuntimeError(
            "boto3 is not installed. Run: pip install boto3\n"
            "Or set USE_MOCK = True to use mock data instead."
        )


def _get_all_entities_mock():
    """
    Return roles, users, and groups from mock_data.py.
    Returns a tuple: (roles, users, groups)
    """
    from src.mock_data import MOCK_ROLES, MOCK_USERS, MOCK_GROUPS
    log.info("Running in MOCK mode — using src/mock_data.py")
    return MOCK_ROLES, MOCK_USERS, MOCK_GROUPS


def _get_all_entities_aws():
    """
    Fetch all IAM roles, users, and groups from a live AWS account.

    IMPORTANT: Uses paginators everywhere.
    AWS returns max 100 results per API call. Without paginators,
    you silently miss entities beyond the first 100.
    """
    iam = _get_iam_client()
    log.info("Running in AWS mode — connecting to live IAM account")

    # ── roles ──────────────────────────────────────────────────────────────────
    roles = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]

            if _is_aws_managed_role(role_name):
                log.info("  %-35s SKIPPED (AWS-managed service-linked role)", role_name)
                continue
            role_data = {
                "RoleName":         role_name,
                "RoleId":           role["RoleId"],
                "Arn":              role["Arn"],
                "Description":      role.get("Description", ""),
                "InlinePolicies":   [],
                "AttachedPolicies": [],
            }

            # inline policies attached to this role
            inline_paginator = iam.get_paginator("list_role_policies")
            for inline_page in inline_paginator.paginate(RoleName=role_name):
                for policy_name in inline_page["PolicyNames"]:
                    response = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    role_data["InlinePolicies"].append({
                        "PolicyName":     policy_name,
                        "PolicyDocument": response["PolicyDocument"]
                    })

            # managed (attached) policies
            attached_paginator = iam.get_paginator("list_attached_role_policies")
            for attached_page in attached_paginator.paginate(RoleName=role_name):
                for policy in attached_page["AttachedPolicies"]:
                    is_high_privilege = policy["PolicyArn"] in HIGH_PRIVILEGE_MANAGED_POLICY_ARNS
                    if _is_aws_managed_policy(policy["PolicyArn"]) and not is_high_privilege:
                        continue
                    doc = _fetch_managed_policy_document(iam, policy["PolicyArn"])
                    if doc:
                        role_data["AttachedPolicies"].append({
                            "PolicyName":     policy["PolicyName"],
                            "PolicyArn":      policy["PolicyArn"],
                            "PolicyDocument": doc
                        })

            roles.append(role_data)

    # ── users ──────────────────────────────────────────────────────────────────
    users = []
    user_paginator = iam.get_paginator("list_users")
    for page in user_paginator.paginate():
        for user in page["Users"]:
            user_name = user["UserName"]
            user_data = {
                "UserName":         user_name,
                "UserId":           user["UserId"],
                "Arn":              user["Arn"],
                "InlinePolicies":   [],
                "AttachedPolicies": [],
            }

            # inline policies
            inline_paginator = iam.get_paginator("list_user_policies")
            for inline_page in inline_paginator.paginate(UserName=user_name):
                for policy_name in inline_page["PolicyNames"]:
                    response = iam.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    user_data["InlinePolicies"].append({
                        "PolicyName":     policy_name,
                        "PolicyDocument": response["PolicyDocument"]
                    })

            # attached managed policies
            attached_paginator = iam.get_paginator("list_attached_user_policies")
            for attached_page in attached_paginator.paginate(UserName=user_name):
                for policy in attached_page["AttachedPolicies"]:
                    is_high_privilege = policy["PolicyArn"] in HIGH_PRIVILEGE_MANAGED_POLICY_ARNS
                    if _is_aws_managed_policy(policy["PolicyArn"]) and not is_high_privilege:
                        continue
                    doc = _fetch_managed_policy_document(iam, policy["PolicyArn"])
                    if doc:
                        user_data["AttachedPolicies"].append({
                            "PolicyName":     policy["PolicyName"],
                            "PolicyArn":      policy["PolicyArn"],
                            "PolicyDocument": doc
                        })

            users.append(user_data)

    # ── groups ─────────────────────────────────────────────────────────────────
    groups = []
    group_paginator = iam.get_paginator("list_groups")
    for page in group_paginator.paginate():
        for group in page["Groups"]:
            group_name = group["GroupName"]
            group_data = {
                "GroupName":        group_name,
                "GroupId":          group["GroupId"],
                "Arn":              group["Arn"],
                "InlinePolicies":   [],
                "AttachedPolicies": [],
            }

            # inline policies
            inline_paginator = iam.get_paginator("list_group_policies")
            for inline_page in inline_paginator.paginate(GroupName=group_name):
                for policy_name in inline_page["PolicyNames"]:
                    response = iam.get_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                    group_data["InlinePolicies"].append({
                        "PolicyName":     policy_name,
                        "PolicyDocument": response["PolicyDocument"]
                    })

            # attached managed policies
            # FIXED: was previously calling list_attached_role_policies with
            # RoleName=role_name (leftover from the roles loop above), which
            # silently attached the *last scanned role's* managed policies to
            # every group instead of the group's own. Now correctly uses
            # list_attached_group_policies with GroupName=group_name.
            attached_paginator = iam.get_paginator("list_attached_group_policies")
            for attached_page in attached_paginator.paginate(GroupName=group_name):
                for policy in attached_page["AttachedPolicies"]:
                    is_high_privilege = policy["PolicyArn"] in HIGH_PRIVILEGE_MANAGED_POLICY_ARNS
                    if _is_aws_managed_policy(policy["PolicyArn"]) and not is_high_privilege:
                        continue
                    doc = _fetch_managed_policy_document(iam, policy["PolicyArn"])
                    if doc:
                        group_data["AttachedPolicies"].append({
                            "PolicyName":     policy["PolicyName"],
                            "PolicyArn":      policy["PolicyArn"],
                            "PolicyDocument": doc
                        })

            groups.append(group_data)

    log.info(
        "Fetched %d roles, %d users, %d groups from AWS",
        len(roles), len(users), len(groups)
    )
    return roles, users, groups


def _fetch_managed_policy_document(iam_client, policy_arn: str) -> Optional[dict]:
    """
    Fetch the current active version of a managed policy document.

    AWS managed policies have versioned documents. We always want the
    "default" (current) version, not a historical one.
    """
    try:
        policy_meta = iam_client.get_policy(PolicyArn=policy_arn)
        version_id  = policy_meta["Policy"]["DefaultVersionId"]
        version     = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        return version["PolicyVersion"]["Document"]
    except Exception as exc:
        log.warning("Could not fetch managed policy %s: %s", policy_arn, exc)
        return None

def _is_aws_managed_role(role_name: str) -> bool:
    """
    True if this role is a service-linked role owned and controlled by AWS
    (e.g. AWSServiceRoleForSupport). These should never be flagged — AWS
    manages their content, and Resource:"*" inside them is required, not
    a misconfiguration a developer introduced.
    """
    return role_name.startswith(AWS_MANAGED_ROLE_PREFIXES)


def _is_aws_managed_policy(policy_arn: str) -> bool:
    """
    True if this is an AWS-managed policy (arn:aws:iam::aws:policy/...)
    rather than a customer-managed policy your team wrote. AWS managed
    policies are reviewed and maintained by AWS; flagging most of them
    produces noise without giving your developers anything actionable
    to fix on the policy content itself.

    EXCEPTION: high-privilege AWS-managed policies (AdministratorAccess,
    PowerUserAccess, IAMFullAccess — see HIGH_PRIVILEGE_MANAGED_POLICY_ARNS)
    are never treated as "safe to skip" here. The risk in those cases isn't
    the policy's wording, it's the decision to attach it, and that decision
    was made by someone on your team. Callers should check
    HIGH_PRIVILEGE_MANAGED_POLICY_ARNS BEFORE calling this function so those
    policies are always fetched and scanned regardless of this result.
    """
    return policy_arn.startswith(AWS_MANAGED_POLICY_ARN_PREFIX)
# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — WILDCARD DETECTION
#  Inspect individual policy statements for risky patterns
# ══════════════════════════════════════════════════════════════════════════════

def _normalize(value) -> list:
    """
    IAM policy fields can be a string or a list of strings.
    Normalize to a list so detection logic only needs one code path.

    Examples:
        "s3:*"         → ["s3:*"]
        ["s3:*","ec2:DescribeInstances"] → unchanged
        "*"            → ["*"]
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def detect_wildcards_in_statement(statement: dict) -> list:
    """
    Inspect a single IAM policy Statement block and return
    a list of findings (may be empty if statement is safe).

    Only inspects "Effect": "Allow" statements.
    Deny statements are ignored — they reduce permissions, not expand them.

    Args:
        statement: A single Statement dict from a policy document.

    Returns:
        List of finding dicts. Each finding has:
            finding_type, description, actions, resources
    """
    findings = []

    # Only care about Allow statements
    if statement.get("Effect") != "Allow":
        return findings

    actions   = _normalize(statement.get("Action",   []))
    resources = _normalize(statement.get("Resource", []))
    if not actions or not resources:
        return findings
    # ── classify actions ───────────────────────────────────────────────────────
    has_full_wildcard_action    = "*" in actions
    has_service_wildcard_action = any(
        a.endswith(":*") and not a == "*" for a in actions
    )
    has_wildcard_resource = "*" in resources

    # ── 5 detection rules (most severe first) ──────────────────────────────────

    # RULE 1 — Action:* + Resource:* → complete admin access
    if has_full_wildcard_action and has_wildcard_resource:
        findings.append({
            "finding_type": "FULL_ADMIN_ACCESS",
            "description":  (
                'Statement grants Action:"*" on Resource:"*" — '
                "complete unrestricted access to every AWS service and resource. "
                "If this entity is compromised, an attacker can do anything."
            ),
            "actions":   actions,
            "resources": resources,
        })
        return findings  # no need to check other rules for this statement

    # RULE 2 — Action:* on specific resources
    if has_full_wildcard_action and not has_wildcard_resource:
        findings.append({
            "finding_type": "WILDCARD_ACTION",
            "description":  (
                'Statement grants Action:"*" — all AWS actions across all services. '
                "Even scoped to specific resources, this is extremely dangerous."
            ),
            "actions":   actions,
            "resources": resources,
        })
        return findings

    # RULE 3 — service:* + Resource:*
    if has_service_wildcard_action and has_wildcard_resource:
        wildcard_services = [a for a in actions if a.endswith(":*")]
        findings.append({
            "finding_type": "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE",
            "description":  (
                f"Statement grants full access to {', '.join(wildcard_services)} "
                'on Resource:"*" — all resources of those services, current and future.'
            ),
            "actions":   actions,
            "resources": resources,
        })
        return findings

    # RULE 4 — service:* on specific resources (less critical but still risky)
    if has_service_wildcard_action and not has_wildcard_resource:
        wildcard_services = [a for a in actions if a.endswith(":*")]
        findings.append({
            "finding_type": "SERVICE_WILDCARD_ACTION",
            "description":  (
                f"Statement grants {', '.join(wildcard_services)} — "
                "full access within those services. "
                "Should specify only the individual actions actually needed."
            ),
            "actions":   actions,
            "resources": resources,
        })
        return findings

    # RULE 5 — specific actions on Resource:*
    if has_wildcard_resource and not has_full_wildcard_action:
        from src.validator import action_requires_wildcard_resource
        if all(action_requires_wildcard_resource(a) for a in actions):
            return findings  # AWS requires Resource:"*" for these actions

        findings.append({
            "finding_type": "WILDCARD_RESOURCE",
            "description":  (
                'Statement uses Resource:"*" — actions apply to all resources. '
                "Should be scoped to specific ARNs."
            ),
            "actions":   actions,
            "resources": resources,
        })
    return findings


def scan_policy_document(document: dict) -> list:
    """
    Scan a complete policy document (which may have multiple Statements)
    and collect all wildcard findings across every statement.

    Args:
        document: A full IAM policy document dict with a "Statement" key.

    Returns:
        List of findings across all statements.
    """
    all_findings = []

    statements = document.get("Statement", [])
    # A document can have a single Statement dict or a list
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        findings = detect_wildcards_in_statement(statement)
        all_findings.extend(findings)

    return all_findings


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — ENTITY SCANNING
#  Scan one entity (role / user / group) across all its policies
# ══════════════════════════════════════════════════════════════════════════════

def _scan_entity(entity_name: str, entity_type: str, arn: str,
                 inline_policies: list, attached_policies: list) -> list:
    """
    Scan all policies (inline + managed) for one IAM entity.

    Args:
        entity_name:       Role / user / group name
        entity_type:       "role", "user", or "group"
        arn:               Full AWS ARN of the entity
        inline_policies:   List of inline policy dicts (each has PolicyName + PolicyDocument)
        attached_policies: List of managed policy dicts (each has PolicyName + PolicyDocument)

    Returns:
        List of scan result dicts in the agreed shared format.
    """
    results = []
    all_policies = (
        [(p, "inline")  for p in inline_policies] +
        [(p, "managed") for p in attached_policies]
    )

    for policy, policy_type in all_policies:
        policy_name = policy.get("PolicyName", "unknown-policy")
        document    = policy.get("PolicyDocument", {})
        findings    = scan_policy_document(document)

        for finding in findings:
            results.append({
                # ── identity ───────────────────────────────────────────────────
                "entity_name":  entity_name,
                "entity_type":  entity_type,
                "arn":          arn,
                # ── policy ─────────────────────────────────────────────────────
                "policy_name":  policy_name,
                "policy_type":  policy_type,
                "policy_json":  document,
                # ── finding ────────────────────────────────────────────────────
                "finding_type": finding["finding_type"],
                "description":  finding["description"],
                "actions":      finding["actions"],
                "resources":    finding["resources"],
                # ── to be filled by risk_scorer.py ────────────────────────────
                "ml_score":     None,
                "severity":     None,
            })

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — PUBLIC API
#  The functions cli.py and risk_scorer.py call
# ══════════════════════════════════════════════════════════════════════════════

def scan_all(use_mock: bool = USE_MOCK) -> list:
    """
    Scan the entire IAM account — all roles, users, and groups.

    This is the main entry point called by cli.py.

    Args:
        use_mock: If True (default), use mock data.
                  If False, connect to a real AWS account via boto3.

    Returns:
        List of scan result dicts (see module docstring for shape).
        Only entities with findings are included.
        Empty (compliant) entities are logged but not returned.
    """
    if use_mock:
        roles, users, groups = _get_all_entities_mock()
    else:
        roles, users, groups = _get_all_entities_aws()

    all_results = []

    log.info("Scanning %d roles ...", len(roles))
    for role in roles:
        findings = _scan_entity(
            entity_name      = role["RoleName"],
            entity_type      = "role",
            arn              = role.get("Arn", ""),
            inline_policies  = role.get("InlinePolicies", []),
            attached_policies= role.get("AttachedPolicies", []),
        )
        if findings:
            log.info("  %-35s → %d finding(s)", role["RoleName"], len(findings))
            all_results.extend(findings)
        else:
            log.info("  %-35s → compliant", role["RoleName"])

    log.info("Scanning %d users ...", len(users))
    for user in users:
        findings = _scan_entity(
            entity_name      = user["UserName"],
            entity_type      = "user",
            arn              = user.get("Arn", ""),
            inline_policies  = user.get("InlinePolicies", []),
            attached_policies= user.get("AttachedPolicies", []),
        )
        if findings:
            log.info("  %-35s → %d finding(s)", user["UserName"], len(findings))
            all_results.extend(findings)
        else:
            log.info("  %-35s → compliant", user["UserName"])

    log.info("Scanning %d groups ...", len(groups))
    for group in groups:
        findings = _scan_entity(
            entity_name      = group["GroupName"],
            entity_type      = "group",
            arn              = group.get("Arn", ""),
            inline_policies  = group.get("InlinePolicies", []),
            attached_policies= group.get("AttachedPolicies", []),
        )
        if findings:
            log.info("  %-35s → %d finding(s)", group["GroupName"], len(findings))
            all_results.extend(findings)
        else:
            log.info("  %-35s → compliant", group["GroupName"])

    log.info(
        "Scan complete — %d finding(s) across %d entities",
        len(all_results),
        len(roles) + len(users) + len(groups)
    )
    return all_results


def get_cloudtrail_usage(entity_name: str, use_mock: bool = USE_MOCK) -> list:
    """
    Return the list of API actions actually used by an entity in the last 30 days.
    Used by Module 3 (CloudTrail analyzer) and the AI recommendation engine.

    Args:
        entity_name: The role / user name to look up.
        use_mock:    If True, return mock usage from mock_data.py.

    Returns:
        List of action strings, e.g. ["s3:GetObject", "logs:PutLogEvents"]
        Returns empty list if no usage data found.
    """
    if use_mock:
        from src.mock_data import MOCK_CLOUDTRAIL_USAGE
        return MOCK_CLOUDTRAIL_USAGE.get(entity_name, [])

    # Real CloudTrail lookup (Module 3 implements this fully)
    # Stub here so scanner.py is self-contained for Week 1
    try:
        import boto3
        from datetime import datetime, timedelta, timezone
        cloudtrail = boto3.client("cloudtrail")
        end_time   = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=30)
        events     = []
        paginator  = cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{
                "AttributeKey":   "Username",
                "AttributeValue": entity_name
            }],
            StartTime=start_time,
            EndTime=end_time,
        ):
            for event in page.get("Events", []):
                action = event.get("EventName", "")
                source = event.get("EventSource", "").replace(".amazonaws.com", "")
                if action and source:
                    events.append(f"{source}:{action}")
        return list(set(events))
    except Exception as exc:
        log.warning("CloudTrail lookup failed for %s: %s", entity_name, exc)
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — QUICK MANUAL TEST
#  Run this file directly to verify it works:
#      python -m src.scanner
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AI IAM Enforcer — Scanner Manual Test")
    print("=" * 60)

    results = scan_all()

    print(f"\nTotal findings: {len(results)}\n")
    for r in results:
        print(
            f"[{r['finding_type']}]  "
            f"{r['entity_type'].upper()}: {r['entity_name']}  "
            f"| policy: {r['policy_name']}"
        )
        print(f"  {r['description'][:90]}...")
        print()