"""
mock_data.py — Simulated AWS IAM account data for local development.

This file simulates the exact data shape returned by real boto3 IAM calls.
Member 1 uses this while AWS credentials are not yet available.

Switching to live AWS later:
    Change USE_MOCK = True  →  USE_MOCK = False  in scanner.py
    Everything else (detection, scoring, CLI) stays identical.

The account simulated here contains:
    - 3 CRITICAL roles  (full admin, wildcard action, dangerous service wildcard)
    - 1 HIGH role       (service wildcard on all resources)
    - 1 MEDIUM role     (specific actions on Resource:*)
    - 1 COMPLIANT role  (correctly scoped, no issues)
    - 2 IAM users       (one with inline policy, one attached managed policy)
    - 1 IAM group       (with overly broad managed policy)
"""

# ── ROLES ──────────────────────────────────────────────────────────────────────
# Each role mirrors what boto3's get_role() + list_role_policies() returns.

MOCK_ROLES = [
    {
        "RoleName": "lambda-data-processor",
        "RoleId":   "AROA1EXAMPLE001",
        "Arn":      "arn:aws:iam::123456789012:role/lambda-data-processor",
        "Description": "Lambda function that processes S3 upload events",
        "InlinePolicies": [
            {
                "PolicyName": "lambda-data-processor-inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "OverlyBroad",
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ],
        "AttachedPolicies": []
    },
    {
        "RoleName": "ec2-web-server",
        "RoleId":   "AROA1EXAMPLE002",
        "Arn":      "arn:aws:iam::123456789012:role/ec2-web-server",
        "Description": "EC2 instance role for the production web tier",
        "InlinePolicies": [
            {
                "PolicyName": "ec2-web-server-inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                            ],
                            "Resource": "arn:aws:logs:*:123456789012:*"
                        }
                    ]
                }
            }
        ],
        "AttachedPolicies": []
    },
    {
        "RoleName": "ci-cd-deployer",
        "RoleId":   "AROA1EXAMPLE003",
        "Arn":      "arn:aws:iam::123456789012:role/ci-cd-deployer",
        "Description": "Role assumed by GitHub Actions CI/CD pipeline",
        "InlinePolicies": [],
        "AttachedPolicies": [
            {
                "PolicyName": "ci-cd-deployer-managed",
                "PolicyArn":  "arn:aws:iam::123456789012:policy/ci-cd-deployer-managed",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ec2:*",
                                "iam:*",
                                "s3:*",
                                "lambda:*"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ]
    },
    {
        "RoleName": "admin-break-glass",
        "RoleId":   "AROA1EXAMPLE004",
        "Arn":      "arn:aws:iam::123456789012:role/admin-break-glass",
        "Description": "Emergency admin role for on-call engineers (MFA required)",
        "InlinePolicies": [],
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn":  "arn:aws:iam::aws:policy/AdministratorAccess",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ]
    },
    {
        "RoleName": "rds-monitoring-lambda",
        "RoleId":   "AROA1EXAMPLE005",
        "Arn":      "arn:aws:iam::123456789012:role/rds-monitoring-lambda",
        "Description": "Lambda that checks RDS health and publishes CloudWatch metrics",
        "InlinePolicies": [
            {
                "PolicyName": "rds-monitoring-inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "rds:DescribeDBInstances",
                                "cloudwatch:GetMetricData",
                                "cloudwatch:PutMetricData"
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": "sns:Publish",
                            "Resource": "arn:aws:sns:ap-south-1:123456789012:db-alerts"
                        }
                    ]
                }
            }
        ],
        "AttachedPolicies": []
    },
    {
        "RoleName": "s3-backup-reader",
        "RoleId":   "AROA1EXAMPLE006",
        "Arn":      "arn:aws:iam::123456789012:role/s3-backup-reader",
        "Description": "Read-only access for backup verification jobs",
        "InlinePolicies": [
            {
                "PolicyName": "s3-backup-reader-inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "s3:GetObject",
                                "s3:ListBucket"
                            ],
                            "Resource": [
                                "arn:aws:s3:::company-backups",
                                "arn:aws:s3:::company-backups/*"
                            ]
                        }
                    ]
                }
            }
        ],
        "AttachedPolicies": []
    }
]

# ── USERS ──────────────────────────────────────────────────────────────────────

MOCK_USERS = [
    {
        "UserName": "dev-john",
        "UserId":   "AIDA1EXAMPLE001",
        "Arn":      "arn:aws:iam::123456789012:user/dev-john",
        "InlinePolicies": [
            {
                "PolicyName": "dev-john-inline",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
            }
        ],
        "AttachedPolicies": []
    },
    {
        "UserName": "svc-deployment-bot",
        "UserId":   "AIDA1EXAMPLE002",
        "Arn":      "arn:aws:iam::123456789012:user/svc-deployment-bot",
        "InlinePolicies": [],
        "AttachedPolicies": [
            {
                "PolicyName": "deployment-bot-policy",
                "PolicyArn":  "arn:aws:iam::123456789012:policy/deployment-bot-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ecr:GetAuthorizationToken",
                                "ecr:BatchCheckLayerAvailability",
                                "ecr:PutImage",
                                "ecs:UpdateService",
                                "ecs:DescribeServices"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ]
    }
]

# ── GROUPS ─────────────────────────────────────────────────────────────────────

MOCK_GROUPS = [
    {
        "GroupName": "developers",
        "GroupId":   "AGPA1EXAMPLE001",
        "Arn":       "arn:aws:iam::123456789012:group/developers",
        "InlinePolicies": [],
        "AttachedPolicies": [
            {
                "PolicyName": "PowerUserAccess",
                "PolicyArn":  "arn:aws:iam::aws:policy/PowerUserAccess",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "NotAction": [
                                "iam:*",
                                "organizations:*"
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:CreateServiceLinkedRole",
                                "iam:DeleteServiceLinkedRole"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            }
        ]
    }
]

# ── CLOUDTRAIL USAGE ───────────────────────────────────────────────────────────
# Actual API calls made by each entity in the last 30 days.
# Used by Module 3 (CloudTrail analyzer) to ground AI recommendations.

MOCK_CLOUDTRAIL_USAGE = {
    "lambda-data-processor": [
        "s3:GetObject", "s3:PutObject", "s3:GetObject",
        "logs:PutLogEvents", "logs:CreateLogStream", "s3:PutObject",
    ],
    "ec2-web-server": [
        "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        "logs:PutLogEvents", "logs:CreateLogGroup", "logs:CreateLogStream",
    ],
    "ci-cd-deployer": [
        "ec2:DescribeInstances", "ec2:RunInstances",
        "lambda:UpdateFunctionCode", "lambda:GetFunction",
        "s3:PutObject", "s3:GetObject", "iam:GetRole",
    ],
    "admin-break-glass": ["iam:CreateUser", "ec2:RunInstances"],
    "rds-monitoring-lambda": [
        "rds:DescribeDBInstances", "cloudwatch:GetMetricData",
        "cloudwatch:PutMetricData", "sns:Publish",
    ],
    "s3-backup-reader": ["s3:GetObject", "s3:ListBucket"],
    "dev-john": ["s3:GetObject", "ec2:DescribeInstances", "lambda:ListFunctions"],
    "svc-deployment-bot": [
        "ecr:GetAuthorizationToken", "ecr:PutImage", "ecs:UpdateService",
    ],
    "developers": ["s3:GetObject", "ec2:DescribeInstances"],
}
