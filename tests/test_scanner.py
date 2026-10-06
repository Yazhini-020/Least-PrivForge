"""
test_scanner.py — Unit tests for scanner.py (Module 1)

Tests cover:
- All 5 wildcard finding types
- Input normalization
- Allow/Deny behavior
- Missing and empty fields
- Empty/malformed policy structures
- Multiple statements
- Duplicate and mixed actions/resources
- Mock AWS account scanning

No real AWS account is required.
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


# ============================================================
# NORMALIZATION TESTS
# ============================================================

class TestNormalize(unittest.TestCase):

    def test_string_becomes_list(self):
        self.assertEqual(_normalize("s3:*"), ["s3:*"])

    def test_list_unchanged(self):
        self.assertEqual(
            _normalize(["s3:*", "ec2:*"]),
            ["s3:*", "ec2:*"]
        )

    def test_none_returns_empty(self):
        self.assertEqual(_normalize(None), [])

    def test_star_string(self):
        self.assertEqual(_normalize("*"), ["*"])

    def test_empty_string(self):
        self.assertEqual(_normalize(""), [""])

    def test_empty_list(self):
        self.assertEqual(_normalize([]), [])

    def test_tuple_input(self):
        """
        If the implementation supports tuple-like inputs,
        ensure they don't cause a crash.
        """
        try:
            result = _normalize(("s3:GetObject", "s3:PutObject"))
            self.assertIsNotNone(result)
        except (TypeError, AttributeError):
            self.skipTest("Implementation does not support tuple input")

    def test_integer_input_does_not_crash(self):
        """
        Defensive test for unexpected input.
        """
        try:
            result = _normalize(123)
            self.assertIsNotNone(result)
        except (TypeError, AttributeError):
            pass


# ============================================================
# RULE 1 — FULL ADMIN ACCESS
# ============================================================

class TestRule1FullAdminAccess(unittest.TestCase):

    def test_detects_full_admin_access(self):
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "FULL_ADMIN_ACCESS"
        )

    def test_full_admin_with_list_action(self):
        statement = {
            "Effect": "Allow",
            "Action": ["*"],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "FULL_ADMIN_ACCESS"
        )

    def test_full_admin_with_multiple_actions(self):
        statement = {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "*"
            ],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertGreaterEqual(len(findings), 1)

    def test_deny_statement_ignored(self):
        statement = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_deny_full_admin_with_lowercase_effect(self):
        statement = {
            "Effect": "deny",
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_finding_stores_original_actions_and_resources(self):
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertIn("*", findings[0]["actions"])
        self.assertIn("*", findings[0]["resources"])


# ============================================================
# RULE 2 — WILDCARD ACTION
# ============================================================

class TestRule2WildcardAction(unittest.TestCase):

    def test_wildcard_action_specific_resource(self):
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "WILDCARD_ACTION"
        )

    def test_wildcard_action_multiple_resources(self):
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": [
                "arn:aws:s3:::bucket-a/*",
                "arn:aws:s3:::bucket-b/*"
            ]
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "WILDCARD_ACTION"
        )

    def test_wildcard_action_deny_ignored(self):
        statement = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "arn:aws:s3:::bucket/*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)


# ============================================================
# RULE 3 — SERVICE WILDCARD + WILDCARD RESOURCE
# ============================================================

class TestRule3ServiceWildcardWithWildcardResource(unittest.TestCase):

    def test_s3_wildcard_on_all_resources(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE"
        )

    def test_multiple_service_wildcards_detected(self):
        statement = {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "iam:*",
                "s3:*",
                "lambda:*"
            ],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE"
        )

        self.assertIn("ec2:*", findings[0]["actions"])
        self.assertIn("iam:*", findings[0]["actions"])
        self.assertIn("s3:*", findings[0]["actions"])
        self.assertIn("lambda:*", findings[0]["actions"])

    def test_service_wildcard_specific_resource_not_rule3(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_ACTION"
        )

    def test_deny_service_wildcard_ignored(self):
        statement = {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)


# ============================================================
# RULE 4 — SERVICE WILDCARD ACTION
# ============================================================

class TestRule4ServiceWildcardAction(unittest.TestCase):

    def test_ec2_wildcard_on_specific_resource(self):
        statement = {
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": (
                "arn:aws:ec2:us-east-1:"
                "123456789012:instance/i-1234"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_ACTION"
        )

    def test_lambda_wildcard_specific_function(self):
        statement = {
            "Effect": "Allow",
            "Action": "lambda:*",
            "Resource": (
                "arn:aws:lambda:ap-south-1:"
                "123456789012:function:test"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_ACTION"
        )

    def test_iam_wildcard_specific_role(self):
        statement = {
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": (
                "arn:aws:iam::123456789012:role/test-role"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "SERVICE_WILDCARD_ACTION"
        )


# ============================================================
# RULE 5 — WILDCARD RESOURCE
# ============================================================

class TestRule5WildcardResource(unittest.TestCase):

    def test_specific_actions_on_all_resources(self):
        statement = {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "WILDCARD_RESOURCE"
        )

    def test_single_action_string_on_all_resources(self):
        statement = {
            "Effect": "Allow",
            "Action": "rds:DescribeDBInstances",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "WILDCARD_RESOURCE"
        )

    def test_multiple_specific_actions_on_wildcard_resource(self):
        statement = {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:DescribeSecurityGroups"
            ],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "WILDCARD_RESOURCE"
        )


# ============================================================
# COMPLIANT STATEMENTS
# ============================================================

class TestCompliantStatements(unittest.TestCase):

    def test_scoped_actions_scoped_resource(self):
        statement = {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_cloudwatch_logs_compliant(self):
        statement = {
            "Effect": "Allow",
            "Action": [
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
            "Effect": "Allow",
            "Action": "sns:Publish",
            "Resource": (
                "arn:aws:sns:ap-south-1:"
                "123456789012:db-alerts"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_specific_ec2_action_specific_instance(self):
        statement = {
            "Effect": "Allow",
            "Action": "ec2:StartInstances",
            "Resource": (
                "arn:aws:ec2:ap-south-1:"
                "123456789012:instance/i-123456"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_specific_lambda_action_specific_function(self):
        statement = {
            "Effect": "Allow",
            "Action": "lambda:InvokeFunction",
            "Resource": (
                "arn:aws:lambda:ap-south-1:"
                "123456789012:function/my-function"
            )
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)


# ============================================================
# EDGE CASES — MISSING / EMPTY FIELDS
# ============================================================

class TestMissingAndEmptyFields(unittest.TestCase):

    def test_missing_action(self):
        statement = {
            "Effect": "Allow",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_missing_resource(self):
        statement = {
            "Effect": "Allow",
            "Action": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_missing_effect(self):
        statement = {
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_empty_action_list(self):
        statement = {
            "Effect": "Allow",
            "Action": [],
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_empty_resource_list(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": []
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_empty_statement(self):
        findings = detect_wildcards_in_statement({})

        self.assertEqual(len(findings), 0)

    def test_none_statement(self):
        try:
            findings = detect_wildcards_in_statement(None)
            self.assertEqual(len(findings), 0)
        except (TypeError, AttributeError):
            # Acceptable if implementation requires a dict.
            pass


# ============================================================
# EDGE CASES — DENY
# ============================================================

class TestDenyStatements(unittest.TestCase):

    def test_deny_full_wildcard(self):
        statement = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_deny_service_wildcard(self):
        statement = {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_deny_wildcard_resource(self):
        statement = {
            "Effect": "Deny",
            "Action": "s3:GetObject",
            "Resource": "*"
        }

        findings = detect_wildcards_in_statement(statement)

        self.assertEqual(len(findings), 0)

    def test_mixed_allow_and_deny(self):
        """
        Allow should be detected while Deny should be ignored.
        """
        allow_statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }

        deny_statement = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*"
        }

        allow_findings = detect_wildcards_in_statement(
            allow_statement
        )
        deny_findings = detect_wildcards_in_statement(
            deny_statement
        )

        self.assertEqual(len(allow_findings), 1)
        self.assertEqual(len(deny_findings), 0)


# ============================================================
# POLICY DOCUMENT TESTS
# ============================================================

class TestScanPolicyDocument(unittest.TestCase):

    def test_multi_statement_document(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                },
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "FULL_ADMIN_ACCESS"
        )

    def test_empty_document(self):
        findings = scan_policy_document({})

        self.assertEqual(len(findings), 0)

    def test_empty_statement_list(self):
        document = {
            "Version": "2012-10-17",
            "Statement": []
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 0)

    def test_single_statement_as_dict(self):
        document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 1)

    def test_multiple_risky_statements(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": (
                        "arn:aws:ec2:ap-south-1:"
                        "123456789012:instance/i-123"
                    )
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 3)

    def test_all_compliant_statements(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                },
                {
                    "Effect": "Allow",
                    "Action": "sns:Publish",
                    "Resource": (
                        "arn:aws:sns:ap-south-1:"
                        "123456789012:topic"
                    )
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 0)

    def test_allow_and_deny_in_same_document(self):
        document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["finding_type"],
            "FULL_ADMIN_ACCESS"
        )

    def test_document_without_version(self):
        document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 1)

    def test_unrelated_document_fields_do_not_break_scan(self):
        document = {
            "Version": "2012-10-17",
            "Description": "Test policy",
            "Metadata": {
                "Owner": "security-team"
            },
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }
            ]
        }

        findings = scan_policy_document(document)

        self.assertEqual(len(findings), 0)


# ============================================================
# MOCK ACCOUNT / INTEGRATION TESTS
# ============================================================

class TestScanAll(unittest.TestCase):

    def test_scan_returns_findings(self):
        results = scan_all(use_mock=True)

        self.assertGreater(len(results), 0)

    def test_all_results_have_required_keys(self):
        required_keys = {
            "entity_name",
            "entity_type",
            "arn",
            "policy_name",
            "policy_type",
            "policy_json",
            "finding_type",
            "description",
            "actions",
            "resources",
            "ml_score",
            "severity"
        }

        results = scan_all(use_mock=True)

        for result in results:
            self.assertTrue(
                required_keys.issubset(result.keys()),
                msg=(
                    f"Missing keys in result: "
                    f"{required_keys - result.keys()}"
                )
            )

    def test_ml_score_and_severity_start_as_none(self):
        results = scan_all(use_mock=True)

        for result in results:
            self.assertIsNone(result["ml_score"])
            self.assertIsNone(result["severity"])

    def test_compliant_role_not_in_results(self):
        results = scan_all(use_mock=True)

        flagged_entities = [
            r["entity_name"]
            for r in results
        ]

        self.assertNotIn(
            "s3-backup-reader",
            flagged_entities
        )

    def test_full_admin_roles_are_detected(self):
        results = scan_all(use_mock=True)

        full_admin = [
            r["entity_name"]
            for r in results
            if r["finding_type"] == "FULL_ADMIN_ACCESS"
        ]

        self.assertIn(
            "lambda-data-processor",
            full_admin
        )

        self.assertIn(
            "admin-break-glass",
            full_admin
        )

    def test_findings_have_valid_finding_types(self):
        valid_types = {
            "FULL_ADMIN_ACCESS",
            "WILDCARD_ACTION",
            "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE",
            "SERVICE_WILDCARD_ACTION",
            "WILDCARD_RESOURCE",
        }

        results = scan_all(use_mock=True)

        for result in results:
            self.assertIn(
                result["finding_type"],
                valid_types
            )

    def test_findings_have_non_empty_actions(self):
        results = scan_all(use_mock=True)

        for result in results:
            self.assertTrue(
                result["actions"],
                msg=f"Empty actions for {result['entity_name']}"
            )

    def test_findings_have_non_empty_resources(self):
        results = scan_all(use_mock=True)

        for result in results:
            self.assertTrue(
                result["resources"],
                msg=f"Empty resources for {result['entity_name']}"
            )

    def test_mock_scan_is_repeatable(self):
        """
        Running the mock scanner twice should produce the
        same number of findings.
        """
        first = scan_all(use_mock=True)
        second = scan_all(use_mock=True)

        self.assertEqual(len(first), len(second))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)