"""
formatter.py — Policy Output Formatter (Module 5)
AI IAM Least-Privilege Enforcer
"""

import json
import yaml


def to_json(policy: dict) -> str:
    return json.dumps(policy, indent=2)


def to_terraform(policy: dict, resource_name: str = "least_privilege_policy") -> str:
    policy_json = json.dumps(policy, indent=2)
    indented = "\n".join("  " + line for line in policy_json.splitlines())
    return f'''resource "aws_iam_policy" "{resource_name}" {{
  name   = "{resource_name}"
  policy = jsonencode(
{indented}
  )
}}
'''


def to_cloudformation_yaml(policy: dict, logical_id: str = "LeastPrivilegePolicy") -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            logical_id: {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "PolicyDocument": policy,
                    "Description": "Generated least-privilege policy",
                },
            }
        },
    }
    return yaml.dump(template, sort_keys=False, default_flow_style=False)


def export_all(policy: dict, base_name: str = "policy") -> dict:
    """Write all three formats to disk, return the paths."""
    import re
    import os

    dir_part, file_part = os.path.split(base_name)
    safe_file = re.sub(r"[^a-zA-Z0-9_]", "_", file_part)
    safe_path = os.path.join(dir_part, safe_file) if dir_part else safe_file

    paths = {}
    with open(f"{safe_path}.json", "w") as f:
        f.write(to_json(policy))
    paths["json"] = f"{safe_path}.json"

    with open(f"{safe_path}.tf", "w") as f:
        f.write(to_terraform(policy, resource_name=safe_file))
    paths["terraform"] = f"{safe_path}.tf"

    with open(f"{safe_path}.cfn.yaml", "w") as f:
        f.write(to_cloudformation_yaml(policy))
    paths["cloudformation"] = f"{safe_path}.cfn.yaml"

    return paths

if __name__ == "__main__":
    sample = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::bucket/*"}],
    }
    print(to_terraform(sample))
    print(to_cloudformation_yaml(sample))