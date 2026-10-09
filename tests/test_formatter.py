"""
test_formatter.py — Tests for formatter.py
"""

from src.formatter import export_all

def test_export_all_sanitizes_hyphens(tmp_path):
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}
    paths = export_all(policy, base_name=str(tmp_path / "test-lambda-active"))
    tf = open(paths["terraform"]).read()
    assert 'resource "aws_iam_policy" "test_lambda_active"' in tf
