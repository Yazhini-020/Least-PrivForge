"""
test_scanner.py — Unit tests for scanner.py (Module 1)

Tests cover all 5 wildcard finding types + edge cases.

Run with:
    python -m pytest tests/test_scanner.py -v
    OR
    python -m unittest tests.test_scanner -v
"""

import sys
import os
import unittest

# Allow imports from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import (
    detect_wildcards_in_statement,
    scan_policy_document,
    scan_all,
    _normalize,
)


class TestNormalize(unittest.TestCase):
    """Test the _normalize helper — string vs list handling."""

    def test_string_becomes_list(self):
        self.assertEqual(_normalize("s3:*"), ["s3:*"])

    def test_list_unchanged(self):
        self.assertEqual(_normalize(["s3:*", "ec2:*"]), ["s3:*", "ec2:*"])

    def test_none_returns_empty(self):
        self.assertEqual(_normalize(None), [])

    def test_star_string(self):
        self.assertEqual(_normalize("*"), ["*"])


class TestRule1FullAdminAccess(unittest.TestCase):
    """
    RULE 1 — Action:* + Resource:* → FULL_ADMIN_ACCESS
    The worst possible policy statement. Complete account compromise.
    """

    def test_detects_full_admin_access(self):
        statement = {
            "Effect":   "Allow",
            "Action":   "*",
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "FULL_ADMIN_ACCESS")

    def test_full_admin_with_list_action(self):
        """Action as a list containing * should also trigger."""
        statement = {
            "Effect":   "Allow",
            "Action":   ["*"],
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "FULL_ADMIN_ACCESS")

    def test_deny_statement_ignored(self):
        """Deny statements reduce permissions — never flag them."""
        statement = {
            "Effect":   "Deny",
            "Action":   "*",
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 0)

    def test_finding_stores_original_actions_and_resources(self):
        """The finding must carry the original actions and resources for the AI engine."""
        statement = {
            "Effect":   "Allow",
            "Action":   "*",
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertIn("*", findings[0]["actions"])
        self.assertIn("*", findings[0]["resources"])


class TestRule2WildcardAction(unittest.TestCase):
    """
    RULE 2 — Action:* on specific resource → WILDCARD_ACTION
    Still dangerous: all AWS actions, but scoped to a named resource.
    """

    def test_wildcard_action_specific_resource(self):
        statement = {
            "Effect":   "Allow",
            "Action":   "*",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "WILDCARD_ACTION")


class TestRule3ServiceWildcardWithWildcardResource(unittest.TestCase):
    """
    RULE 3 — service:* + Resource:* → SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE
    Full access to one service on all resources. High / Critical severity.
    """

    def test_s3_wildcard_on_all_resources(self):
        statement = {
            "Effect":   "Allow",
            "Action":   "s3:*",
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE"
        )

    def test_multiple_service_wildcards_detected(self):
        """Multiple service wildcards like ec2:*, iam:*, s3:* in one statement."""
        statement = {
            "Effect":   "Allow",
            "Action":   ["ec2:*", "iam:*", "s3:*", "lambda:*"],
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE"
        )
        # All 4 service wildcards should be stored
        self.assertIn("ec2:*", findings[0]["actions"])
        self.assertIn("iam:*", findings[0]["actions"])


class TestRule4ServiceWildcardAction(unittest.TestCase):
    """
    RULE 4 — service:* on specific ARN → SERVICE_WILDCARD_ACTION
    Full service access but resource is properly scoped. Medium severity.
    """

    def test_ec2_wildcard_on_specific_resource(self):
        statement = {
            "Effect":   "Allow",
            "Action":   "ec2:*",
            "Resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "SERVICE_WILDCARD_ACTION")


class TestRule5WildcardResource(unittest.TestCase):
    """
    RULE 5 — specific actions on Resource:* → WILDCARD_RESOURCE
    Correct actions, but not scoped to a named resource ARN. Medium severity.
    """

    def test_specific_actions_on_all_resources(self):
        statement = {
            "Effect":   "Allow",
            "Action":   ["s3:GetObject", "s3:PutObject"],
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "WILDCARD_RESOURCE")

    def test_single_action_string_on_all_resources(self):
        """Action as a string (not list) should still be detected."""
        statement = {
            "Effect":   "Allow",
            "Action":   "rds:DescribeDBInstances",
            "Resource": "*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "WILDCARD_RESOURCE")


class TestCompliantStatements(unittest.TestCase):
    """
    Properly scoped statements must produce ZERO findings.
    These are correctly written policies — the tool should not flag them.
    """

    def test_scoped_actions_scoped_resource(self):
        statement = {
            "Effect":   "Allow",
            "Action":   ["s3:GetObject", "s3:ListBucket"],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 0)

    def test_cloudwatch_logs_compliant(self):
        statement = {
            "Effect":   "Allow",
            "Action":   [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:123456789012:*"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 0)

    def test_sns_publish_to_specific_topic(self):
        statement = {
            "Effect":   "Allow",
            "Action":   "sns:Publish",
            "Resource": "arn:aws:sns:ap-south-1:123456789012:db-alerts"
        }
        findings = detect_wildcards_in_statement(statement)
        self.assertEqual(len(findings), 0)


class TestScanPolicyDocument(unittest.TestCase):
    """Test scanning complete policy documents with multiple statements."""

    def test_multi_statement_document(self):
        """A document with one good statement and one bad should return one finding."""
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect":   "Allow",
                    "Action":   ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                },
                {
                    "Effect":   "Allow",
                    "Action":   "*",
                    "Resource": "*"
                }
            ]
        }
        findings = scan_policy_document(document)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_type"], "FULL_ADMIN_ACCESS")

    def test_empty_document(self):
        findings = scan_policy_document({})
        self.assertEqual(len(findings), 0)

    def test_single_statement_as_dict(self):
        """Some AWS policies have Statement as a dict, not a list."""
        document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect":   "Allow",
                "Action":   "s3:*",
                "Resource": "*"
            }
        }
        findings = scan_policy_document(document)
        self.assertEqual(len(findings), 1)


class TestScanAll(unittest.TestCase):
    """Integration test — scan the full mock account."""

    def test_scan_returns_findings(self):
        results = scan_all(use_mock=True)
        self.assertGreater(len(results), 0)

    def test_all_results_have_required_keys(self):
        """Every result must carry all fields the rest of the pipeline needs."""
        required_keys = {
            "entity_name", "entity_type", "arn",
            "policy_name", "policy_type", "policy_json",
            "finding_type", "description", "actions", "resources",
            "ml_score", "severity"
        }
        results = scan_all(use_mock=True)
        for result in results:
            self.assertTrue(
                required_keys.issubset(result.keys()),
                msg=f"Missing keys in result: {required_keys - result.keys()}"
            )

    def test_ml_score_and_severity_start_as_none(self):
        """ml_score and severity must be None — risk_scorer.py fills them in."""
        results = scan_all(use_mock=True)
        for result in results:
            self.assertIsNone(result["ml_score"])
            self.assertIsNone(result["severity"])

    def test_compliant_role_not_in_results(self):
        """s3-backup-reader is correctly scoped and must not appear in findings."""
        results = scan_all(use_mock=True)
        flagged_entities = [r["entity_name"] for r in results]
        self.assertNotIn("s3-backup-reader", flagged_entities)

    def test_full_admin_roles_are_detected(self):
        """lambda-data-processor and admin-break-glass both have Action:* Resource:*."""
        results = scan_all(use_mock=True)
        full_admin = [
            r["entity_name"] for r in results
            if r["finding_type"] == "FULL_ADMIN_ACCESS"
        ]
        self.assertIn("lambda-data-processor", full_admin)
        self.assertIn("admin-break-glass", full_admin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
