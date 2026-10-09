

"""
test_orphaned_detector.py — Tests for Orphaned IAM Identity Detector
 
These tests are completely offline.
They mock boto3/IAM calls and test role/user activity classification,
the 90-day threshold, access-key usage, permission errors,
pagination, AWS-managed-role filtering, error handling,
and final orphaned-result sorting.
"""
 
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock
 
import pytest
from botocore.exceptions import ClientError
 
import src.orphaned_detector as od
from src.orphaned_detector import OrphanedIdentityDetector
 
 
@pytest.fixture
def detector(monkeypatch):
    """Create an offline detector with a mocked boto3 session."""
    session = Mock()
    session.client.return_value = Mock()
 
    monkeypatch.setattr(od.boto3, "Session", lambda **kwargs: session)
 
    return OrphanedIdentityDetector(
        profile="default",
        region="eu-central-1",
        threshold_days=90,
    )
 
 
def make_role(name="test-role", last_used=None, created=None):
    """Return a reusable IAM role record."""
    return {
        "RoleName": name,
        "RoleLastUsed": {"LastUsedDate": last_used} if last_used else {},
        "CreateDate": created,
    }
 
 
def make_user(name="test-user", password_last_used=None, created=None):
    """Return a reusable IAM user record."""
    return {
        "UserName": name,
        "PasswordLastUsed": password_last_used,
        "CreateDate": created,
    }
 
 
def permission_error(code="AccessDenied"):
    """Return a representative IAM permission error."""
    return ClientError(
        {"Error": {"Code": code, "Message": "permission denied"}},
        "ListAccessKeys",
    )
 
 
# =========================================================
# __init__() tests
# =========================================================
 
def test_init_uses_default_threshold(monkeypatch):
    """Default threshold should be 90 days."""
    session = Mock()
    session.client.return_value = Mock()
    monkeypatch.setattr(od.boto3, "Session", lambda **kwargs: session)
 
    detector = OrphanedIdentityDetector()
 
    assert detector.threshold_days == 90
 
 
def test_init_accepts_custom_threshold(monkeypatch):
    """Custom threshold should be stored."""
    session = Mock()
    session.client.return_value = Mock()
    monkeypatch.setattr(od.boto3, "Session", lambda **kwargs: session)
 
    detector = OrphanedIdentityDetector(threshold_days=30)
 
    assert detector.threshold_days == 30
 
 
# =========================================================
# _build_result() — never-used identity tests
# =========================================================
 
def test_never_used_recent_identity_is_not_orphaned(detector):
    """A recently created never-used identity should not be orphaned."""
    created = datetime.now(timezone.utc) - timedelta(days=10)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["status"] == "never_used"
    assert result["is_orphaned"] is False
 
 
def test_never_used_identity_at_89_days_is_not_orphaned(detector):
    """89 days of inactivity should remain below the 90-day threshold."""
    created = datetime.now(timezone.utc) - timedelta(days=89)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["is_orphaned"] is False
 
 
def test_never_used_identity_at_90_days_is_orphaned(detector):
    """90 days without any use should meet the threshold."""
    created = datetime.now(timezone.utc) - timedelta(days=90)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["is_orphaned"] is True
 
 
def test_never_used_identity_120_days_is_orphaned(detector):
    """A long-unused identity should be orphaned."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["is_orphaned"] is True
 
 
def test_never_used_identity_records_status(detector):
    """Never-used identities should have never_used status."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["status"] == "never_used"
 
 
def test_never_used_identity_has_reason(detector):
    """Never-used identities should explain why they were flagged."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert "Never used since creation" in result["reason"]
 
 
def test_never_used_identity_has_threshold(detector):
    """Result should expose the configured threshold."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["threshold_days"] == 90
 
 
def test_never_used_identity_records_entity_name(detector):
    """Result should preserve the identity name."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("my-role", "role", None, created)
 
    assert result["entity_name"] == "my-role"
 
 
def test_never_used_identity_records_entity_type(detector):
    """Result should preserve the identity type."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("my-user", "user", None, created)
 
    assert result["entity_type"] == "user"
 
 
def test_never_used_identity_has_recommendation(detector):
    """Orphaned identity should receive a deactivation recommendation."""
    created = datetime.now(timezone.utc) - timedelta(days=120)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert "deactivating" in result["recommendation"].lower()
 
 
# =========================================================
# _build_result() — previously-used identity tests
# =========================================================
 
def test_recently_used_identity_is_active(detector):
    """Recent usage should produce an active result."""
    last_used = datetime.now(timezone.utc) - timedelta(days=10)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["status"] == "active"
    assert result["is_orphaned"] is False
 
 
def test_identity_used_89_days_ago_is_active(detector):
    """89 days since use should remain active."""
    last_used = datetime.now(timezone.utc) - timedelta(days=89)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["status"] == "active"
    assert result["is_orphaned"] is False
 
 
def test_identity_used_90_days_ago_is_inactive(detector):
    """90 days since use should be inactive."""
    last_used = datetime.now(timezone.utc) - timedelta(days=90)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["status"] == "inactive"
    assert result["is_orphaned"] is True
 
 
def test_identity_used_120_days_ago_is_orphaned(detector):
    """Long inactivity should be orphaned."""
    last_used = datetime.now(timezone.utc) - timedelta(days=120)
    created = datetime.now(timezone.utc) - timedelta(days=200)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["is_orphaned"] is True
    assert result["days_inactive"] >= 120
 
 
def test_active_identity_has_no_action_recommendation(detector):
    """Active identities should not receive a deactivation recommendation."""
    last_used = datetime.now(timezone.utc) - timedelta(days=10)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["recommendation"] == "No action needed."
 
 
def test_inactive_identity_has_deactivation_recommendation(detector):
    """Inactive identities should receive a deactivation recommendation."""
    last_used = datetime.now(timezone.utc) - timedelta(days=120)
    created = datetime.now(timezone.utc) - timedelta(days=200)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert "deactivating" in result["recommendation"].lower()
 
 
def test_inactive_identity_reason_mentions_days(detector):
    """Inactive result should explain how long ago it was used."""
    last_used = datetime.now(timezone.utc) - timedelta(days=120)
    created = datetime.now(timezone.utc) - timedelta(days=200)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert "Last used" in result["reason"]
    assert "day(s) ago" in result["reason"]
 
 
def test_build_result_preserves_last_used(detector):
    """Result should preserve the supplied last-used timestamp."""
    last_used = datetime.now(timezone.utc) - timedelta(days=10)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["last_used"] == str(last_used)
 
 
def test_build_result_preserves_created_date(detector):
    """Result should preserve the supplied creation timestamp."""
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", None, created)
 
    assert result["created_date"] == str(created)
 
 
def test_build_result_without_creation_date_is_conservative(detector):
    """Unknown age for a never-used identity should be flagged for review."""
    result = detector._build_result("role-a", "role", None, None)
 
    assert result["is_orphaned"] is True
    assert result["days_inactive"] is None
 
 
def test_build_result_custom_threshold(detector):
    """A custom threshold should control orphan classification."""
    detector.threshold_days = 30
    last_used = datetime.now(timezone.utc) - timedelta(days=31)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("role-a", "role", last_used, created)
 
    assert result["is_orphaned"] is True
    assert result["threshold_days"] == 30
 
 
def test_build_result_user_type_active(detector):
    """Recently used users should be active just like roles."""
    last_used = datetime.now(timezone.utc) - timedelta(days=5)
    created = datetime.now(timezone.utc) - timedelta(days=100)
 
    result = detector._build_result("user-a", "user", last_used, created)
 
    assert result["entity_type"] == "user"
    assert result["status"] == "active"
 
 
# =========================================================
# _check_role() / _check_user() tests
# =========================================================
 
def test_check_role_reads_last_used(detector):
    """RoleLastUsed should be passed into result classification."""
    now = datetime.now(timezone.utc)
    role = make_role(
        last_used=now - timedelta(days=10),
        created=now - timedelta(days=100),
    )
 
    result = detector._check_role(role)
 
    assert result["entity_name"] == "test-role"
    assert result["status"] == "active"
 
 
def test_check_role_without_last_used(detector):
    """A role with no RoleLastUsed value should be treated as never used."""
    role = make_role(
        last_used=None,
        created=datetime.now(timezone.utc) - timedelta(days=120),
    )
 
    result = detector._check_role(role)
 
    assert result["status"] == "never_used"
    assert result["is_orphaned"] is True
 
 
def test_check_role_recent_never_used_is_not_orphaned(detector):
    """A new role that was never used should not be orphaned yet."""
    role = make_role(
        last_used=None,
        created=datetime.now(timezone.utc) - timedelta(days=5),
    )
 
    result = detector._check_role(role)
 
    assert result["status"] == "never_used"
    assert result["is_orphaned"] is False
 
 
def test_check_user_uses_password_activity(detector):
    """Recent password use should make the user active."""
    now = datetime.now(timezone.utc)
    detector._get_latest_access_key_usage = Mock(return_value=None)
 
    user = make_user(
        password_last_used=now - timedelta(days=10),
        created=now - timedelta(days=100),
    )
 
    result = detector._check_user(user)
 
    assert result["entity_name"] == "test-user"
    assert result["status"] == "active"
 
 
def test_check_user_uses_access_key_activity(detector):
    """Recent access-key activity should make the user active."""
    now = datetime.now(timezone.utc)
    detector._get_latest_access_key_usage = Mock(
        return_value=now - timedelta(days=10)
    )
 
    user = make_user(
        password_last_used=None,
        created=now - timedelta(days=100),
    )
 
    result = detector._check_user(user)
 
    assert result["status"] == "active"
 
 
def test_check_user_uses_most_recent_activity(detector):
    """The newest password/access-key activity should determine last_used."""
    now = datetime.now(timezone.utc)
    detector._get_latest_access_key_usage = Mock(
        return_value=now - timedelta(days=30)
    )
 
    user = make_user(
        password_last_used=now - timedelta(days=10),
        created=now - timedelta(days=100),
    )
 
    result = detector._check_user(user)
 
    assert result["days_inactive"] < 30
 
 
def test_check_user_never_used_and_old_is_orphaned(detector):
    """A user with no password or key activity for 120 days is orphaned."""
    now = datetime.now(timezone.utc)
    detector._get_latest_access_key_usage = Mock(return_value=None)
 
    user = make_user(
        password_last_used=None,
        created=now - timedelta(days=120),
    )
 
    result = detector._check_user(user)
 
    assert result["status"] == "never_used"
    assert result["is_orphaned"] is True
 
 
# =========================================================
# Access-key usage tests
# =========================================================
 
def test_access_key_usage_returns_none_when_no_keys(detector):
    """No access keys should return None."""
    detector.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
 
    result = detector._get_latest_access_key_usage("alice")
 
    assert result is None
 
 
def test_access_key_usage_returns_single_key_date(detector):
    """A single used access key should return its last-used date."""
    last_used = datetime.now(timezone.utc) - timedelta(days=5)
 
    detector.iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIA123"}]
    }
    detector.iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": last_used}
    }
 
    result = detector._get_latest_access_key_usage("alice")
 
    assert result == last_used
 
 
def test_access_key_usage_selects_latest_of_multiple_keys(detector):
    """The most recent access-key activity should be returned."""
    older = datetime.now(timezone.utc) - timedelta(days=30)
    newer = datetime.now(timezone.utc) - timedelta(days=5)
 
    detector.iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIAOLD"},
            {"AccessKeyId": "AKIANEW"},
        ]
    }
    detector.iam.get_access_key_last_used.side_effect = [
        {"AccessKeyLastUsed": {"LastUsedDate": older}},
        {"AccessKeyLastUsed": {"LastUsedDate": newer}},
    ]
 
    result = detector._get_latest_access_key_usage("alice")
 
    assert result == newer
 
 
def test_access_key_usage_checks_every_key(detector):
    """Every access key should be queried for last-used data."""
    last_used = datetime.now(timezone.utc) - timedelta(days=5)
 
    detector.iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {"AccessKeyId": "AKIA111"},
            {"AccessKeyId": "AKIA222"},
        ]
    }
    detector.iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {"LastUsedDate": last_used}
    }
 
    detector._get_latest_access_key_usage("alice")
 
    assert detector.iam.get_access_key_last_used.call_count == 2
 
 
def test_access_key_without_usage_is_ignored(detector):
    """An unused access key should not create a last-used date."""
    detector.iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIA123"}]
    }
    detector.iam.get_access_key_last_used.return_value = {
        "AccessKeyLastUsed": {}
    }
 
    result = detector._get_latest_access_key_usage("alice")
 
    assert result is None
 
 
def test_permission_error_is_raised(detector):
    """IAM permission errors must not be mistaken for no activity."""
    detector.iam.list_access_keys.side_effect = permission_error("AccessDenied")
 
    with pytest.raises(ClientError):
        detector._get_latest_access_key_usage("alice")
 
 
def test_permission_error_exception_code_is_preserved(detector):
    """Permission error code should remain available to callers."""
    detector.iam.list_access_keys.side_effect = permission_error(
        "UnauthorizedOperation"
    )
 
    with pytest.raises(ClientError) as exc_info:
        detector._get_latest_access_key_usage("alice")
 
    assert exc_info.value.response["Error"]["Code"] == "UnauthorizedOperation"
 
 
# =========================================================
# Error-result tests
# =========================================================
 
def test_error_result_status(detector):
    """Error results should use error status."""
    result = detector._error_result("role-a", "role", "permission denied")
 
    assert result["status"] == "error"
 
 
def test_error_result_is_not_orphaned(detector):
    """An inability to check an identity must not mark it orphaned."""
    result = detector._error_result("role-a", "role", "permission denied")
 
    assert result["is_orphaned"] is False
 
 
def test_error_result_requires_manual_review(detector):
    """Error results should request manual review."""
    result = detector._error_result("role-a", "role", "permission denied")
 
    assert result["recommendation"] == "Manual review required."
 
 
# =========================================================
# scan_roles() / scan_users() tests
# =========================================================
 
def test_scan_roles_skips_aws_managed_roles(detector, monkeypatch):
    """AWS-managed roles should not be checked as customer identities."""
    detector.iam.get_paginator.return_value.paginate.return_value = [
        {
            "Roles": [
                {"RoleName": "AWSServiceRoleForExample"},
                {"RoleName": "customer-role"},
            ]
        }
    ]
 
    monkeypatch.setattr(
        od,
        "_is_aws_managed_role",
        lambda name: name == "AWSServiceRoleForExample",
    )
 
    detector._check_role = Mock(
        return_value={
            "entity_name": "customer-role",
            "entity_type": "role",
            "is_orphaned": True,
        }
    )
 
    result = detector.scan_roles()
 
    assert len(result) == 1
    detector._check_role.assert_called_once()
 
 
def test_scan_roles_returns_empty_when_no_roles(detector):
    """No IAM roles should produce an empty result list."""
    detector.iam.get_paginator.return_value.paginate.return_value = [
        {"Roles": []}
    ]
 
    result = detector.scan_roles()
 
    assert result == []
 
 
def test_scan_users_checks_each_user(detector):
    """All users returned by IAM pagination should be checked."""
    detector.iam.get_paginator.return_value.paginate.return_value = [
        {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
    ]
 
    detector._check_user = Mock(
        side_effect=[
            {"entity_name": "alice", "is_orphaned": True},
            {"entity_name": "bob", "is_orphaned": False},
        ]
    )
 
    result = detector.scan_users()
 
    assert len(result) == 2
    assert detector._check_user.call_count == 2
 
 
def test_scan_users_returns_empty_when_no_users(detector):
    """No IAM users should produce an empty result list."""
    detector.iam.get_paginator.return_value.paginate.return_value = [
        {"Users": []}
    ]
 
    result = detector.scan_users()
 
    assert result == []
 
 
# =========================================================
# scan_all() tests
# =========================================================
 
def test_scan_all_returns_only_orphaned(detector):
    """scan_all should filter out active identities."""
    detector.scan_roles = Mock(return_value=[
        {"entity_name": "old-role", "is_orphaned": True, "days_inactive": 200},
        {"entity_name": "active-role", "is_orphaned": False, "days_inactive": 10},
    ])
    detector.scan_users = Mock(return_value=[
        {"entity_name": "old-user", "is_orphaned": True, "days_inactive": 100},
    ])
 
    result = detector.scan_all()
 
    assert len(result) == 2
    assert all(item["is_orphaned"] for item in result)
 
 
def test_scan_all_sorts_most_inactive_first(detector):
    """Orphaned identities should be sorted by inactivity descending."""
    detector.scan_roles = Mock(return_value=[
        {"entity_name": "role-a", "is_orphaned": True, "days_inactive": 100},
        {"entity_name": "role-b", "is_orphaned": True, "days_inactive": 300},
    ])
    detector.scan_users = Mock(return_value=[])
 
    result = detector.scan_all()
 
    assert result[0]["entity_name"] == "role-b"
    assert result[1]["entity_name"] == "role-a"
 
 
def test_scan_all_returns_empty_when_none_orphaned(detector):
    """No orphaned identities should produce an empty list."""
    detector.scan_roles = Mock(return_value=[
        {"entity_name": "role-a", "is_orphaned": False, "days_inactive": 10},
    ])
    detector.scan_users = Mock(return_value=[
        {"entity_name": "user-a", "is_orphaned": False, "days_inactive": 20},
    ])
 
    result = detector.scan_all()
 
    assert result == []
 
 
def test_scan_all_combines_roles_and_users(detector):
    """scan_all should inspect both roles and users."""
    detector.scan_roles = Mock(return_value=[
        {"entity_name": "role-a", "is_orphaned": True, "days_inactive": 100},
    ])
    detector.scan_users = Mock(return_value=[
        {"entity_name": "user-a", "is_orphaned": True, "days_inactive": 120},
    ])
 
    result = detector.scan_all()
 
    assert len(result) == 2
    assert detector.scan_roles.called
    assert detector.scan_users.called
 
 
def test_scan_all_preserves_entity_fields(detector):
    """scan_all should return result dictionaries without altering them."""
    item = {"entity_name": "role-a", "is_orphaned": True, "days_inactive": 100}
    detector.scan_roles = Mock(return_value=[item])
    detector.scan_users = Mock(return_value=[])
 
    result = detector.scan_all()
 
    assert result == [item]
 
