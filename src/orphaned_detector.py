"""
orphaned_detector.py — Orphaned Identity Detector
AI IAM Least-Privilege Enforcer

Flags IAM roles and users with no recent activity — unused credentials
are a common attacker target precisely because nobody is watching them.

Uses IAM's native last-used tracking (not CloudTrail), since CloudTrail
Event History only retains 90 days and cannot tell you about a role
that hasn't been used in 200 days.
"""

import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

from src.scanner import _is_aws_managed_role

# Error codes that mean "we couldn't check, not that there's no usage" —
# these should surface as a scan error, not silently look like a clean result.
_PERMISSION_ERROR_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

DEFAULT_ORPHAN_THRESHOLD_DAYS = 90


class OrphanedIdentityDetector:
    """Detect IAM roles and users with no recent (or no) activity."""

    def __init__(self, profile: str = "default", region: str = "eu-central-1",
                 threshold_days: int = DEFAULT_ORPHAN_THRESHOLD_DAYS):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.iam = session.client("iam")
        self.threshold_days = threshold_days

    def scan_roles(self) -> List[Dict[str, Any]]:
        results = []
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                if _is_aws_managed_role(role["RoleName"]):
                    continue
                # list_roles already returns RoleLastUsed + CreateDate —
                # no need for a separate get_role call (and the extra
                # iam:GetRole permission that would require).
                try:
                    results.append(self._check_role(role))
                except Exception as exc:
                    log.error("Failed to check role %s: %s", role.get("RoleName", "?"), exc)
                    results.append(self._error_result(role.get("RoleName", "?"), "role", str(exc)))
        return results

    def scan_users(self) -> List[Dict[str, Any]]:
        results = []
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                # list_users already returns PasswordLastUsed + CreateDate —
                # no need for a separate get_user call (and the extra
                # iam:GetUser permission that would require).
                try:
                    results.append(self._check_user(user))
                except Exception as exc:
                    log.error("Failed to check user %s: %s", user.get("UserName", "?"), exc)
                    results.append(self._error_result(user.get("UserName", "?"), "user", str(exc)))
        return results

    def _check_role(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        role_name = role_data["RoleName"]
        last_used = role_data.get("RoleLastUsed", {}).get("LastUsedDate")
        return self._build_result(role_name, "role", last_used, role_data.get("CreateDate"))

    def _check_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        user_name = user_data["UserName"]
        password_last_used = user_data.get("PasswordLastUsed")
        access_key_last_used = self._get_latest_access_key_usage(user_name)

        candidates = [d for d in [password_last_used, access_key_last_used] if d]
        last_used = max(candidates) if candidates else None

        return self._build_result(user_name, "user", last_used, user_data.get("CreateDate"))

    def _get_latest_access_key_usage(self, user_name: str) -> Optional[datetime]:
        latest = None
        try:
            keys = self.iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
            for key in keys:
                usage = self.iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                last_used_date = usage.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if last_used_date and (latest is None or last_used_date > latest):
                    latest = last_used_date
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in _PERMISSION_ERROR_CODES:
                # Don't silently treat "we're not allowed to check" the same as
                # "we checked and there's no usage" — surface it as a real error
                # so it's not mistaken for a clean/inactive result.
                log.error(
                    "Permission error checking access keys for %s (%s) — "
                    "cannot determine key usage, not safe to report as inactive.",
                    user_name, error_code,
                )
                raise
            log.warning("Could not check access keys for %s: %s", user_name, exc)
        except Exception as exc:
            log.warning("Could not check access keys for %s: %s", user_name, exc)
        return latest

    def _build_result(self, entity_name, entity_type, last_used, created_date) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)

        if last_used is None:
            days_inactive = (now - created_date).days if created_date else None
            status = "never_used"
            # A role/user that was created 5 minutes ago and simply hasn't
            # been used YET is not "orphaned" — it needs the same
            # threshold_days grace period as an inactive identity gets.
            # Only flag it once it's been sitting unused for at least
            # threshold_days, or if we couldn't determine its age at all
            # (in which case we conservatively flag it for manual review).
            is_orphaned = (days_inactive is None) or (days_inactive >= self.threshold_days)
            reason = "Never used since creation" + (f" ({days_inactive} days ago)" if days_inactive is not None else "")
        else:
            days_inactive = (now - last_used).days
            is_orphaned = days_inactive >= self.threshold_days
            status = "inactive" if is_orphaned else "active"
            reason = f"Last used {days_inactive} day(s) ago"

        return {
            "entity_name": entity_name,
            "entity_type": entity_type,
            "last_used": str(last_used) if last_used else None,
            "created_date": str(created_date) if created_date else None,
            "days_inactive": days_inactive,
            "threshold_days": self.threshold_days,
            "status": status,
            "is_orphaned": is_orphaned,
            "reason": reason,
            "recommendation": (
                "Consider deactivating or deleting this identity — unused credentials "
                "are a common attacker target since nobody is watching them."
            ) if is_orphaned else "No action needed.",
        }

    def _error_result(self, entity_name, entity_type, error):
        return {
            "entity_name": entity_name, "entity_type": entity_type,
            "last_used": None, "created_date": None, "days_inactive": None,
            "threshold_days": self.threshold_days, "status": "error",
            "is_orphaned": False, "reason": error,
            "recommendation": "Manual review required.",
        }

    def scan_all(self) -> List[Dict[str, Any]]:
        log.info("Scanning roles for orphaned status...")
        roles = self.scan_roles()
        log.info("Scanning users for orphaned status...")
        users = self.scan_users()

        all_results = roles + users
        orphaned = [r for r in all_results if r["is_orphaned"]]
        orphaned.sort(key=lambda r: r["days_inactive"] or 0, reverse=True)

        log.info("Scan complete — %d orphaned identity(ies) found out of %d checked",
                  len(orphaned), len(all_results))
        return orphaned


if __name__ == "__main__":
    detector = OrphanedIdentityDetector(threshold_days=90)
    orphaned = detector.scan_all()
    print(json.dumps(orphaned, indent=2, default=str))