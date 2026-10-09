"""
test_ci_gate.py — Tests for M6 CI/CD Security Gate
"""

import os
import json
import pytest
from src.ci_gate import (
    extract_policies_from_file,
    scan_policy_for_ci,
    run_ci_gate,
)

@pytest.fixture
def safe_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-app-bucket/*"
            }
        ]
    }

@pytest.fixture
def unsafe_admin_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

@pytest.fixture
def unsafe_service_wildcard_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }

def test_scan_policy_safe(safe_policy):
    res = scan_policy_for_ci(safe_policy)
    assert res["is_valid"] is True
    assert res["max_severity"] == "NONE"
    assert len(res["findings"]) == 0

def test_scan_policy_unsafe_admin(unsafe_admin_policy):
    res = scan_policy_for_ci(unsafe_admin_policy)
    assert res["is_valid"] is True
    assert res["max_severity"] == "CRITICAL"
    assert any(f["finding_type"] == "FULL_ADMIN_ACCESS" for f in res["findings"])

def test_scan_policy_unsafe_service_wildcard(unsafe_service_wildcard_policy):
    res = scan_policy_for_ci(unsafe_service_wildcard_policy)
    assert res["is_valid"] is True
    assert res["max_severity"] == "HIGH"
    assert any(f["finding_type"] == "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE" for f in res["findings"])

def test_extract_policies_json(tmp_path, safe_policy):
    p_file = tmp_path / "policy.json"
    p_file.write_text(json.dumps(safe_policy))

    extracted = extract_policies_from_file(str(p_file))
    assert len(extracted) == 1
    assert extracted[0]["policy"]["Statement"][0]["Action"] == ["s3:GetObject", "s3:PutObject"]

def test_extract_policies_terraform(tmp_path, safe_policy):
    tf_content = f'''
resource "aws_iam_policy" "test" {{
  name = "test"
  policy = jsonencode({json.dumps(safe_policy)})
}}
'''
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(tf_content)

    extracted = extract_policies_from_file(str(tf_file))
    assert len(extracted) == 1

def test_run_ci_gate_pass(tmp_path, safe_policy):
    p_file = tmp_path / "safe.json"
    p_file.write_text(json.dumps(safe_policy))

    passed, results = run_ci_gate(target_path=str(p_file), fail_threshold="HIGH")
    assert passed is True
    assert results[0]["status"] == "PASS"

def test_run_ci_gate_fail(tmp_path, unsafe_admin_policy):
    p_file = tmp_path / "unsafe.json"
    p_file.write_text(json.dumps(unsafe_admin_policy))

    passed, results = run_ci_gate(target_path=str(p_file), fail_threshold="HIGH")
    assert passed is False
    assert results[0]["status"] == "FAIL"
