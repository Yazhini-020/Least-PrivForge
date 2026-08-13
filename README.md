# AI IAM Least-Privilege Enforcer

Automated AWS IAM over-privilege detection and AI-powered remediation for DevSecOps teams.

## What it does

Scans AWS IAM policies across users, roles, and groups, detects over-privileged
wildcard patterns (`Action:*`, `Resource:*`), analyzes actual usage via CloudTrail,
scores risk, and generates least-privilege policy replacements using AI.

## Problem

Developers routinely write over-permissive IAM policies to avoid deployment
friction. Existing tools (AWS Access Analyzer, Prowler, ScoutSuite) detect these
issues but stop there — the remediation burden remains entirely manual.

## Solution

This tool closes the loop: **detect → analyze real usage → generate a fix.**

1. **Scan** — find every over-privileged policy across your AWS account
2. **CloudTrail analysis** — determine what permissions are actually used
3. **Risk scoring** — rank findings by blast radius
4. **AI generation** — produce a validated least-privilege replacement policy
5. **Export** — output as IAM JSON, Terraform HCL, or CloudFormation YAML

## Setup

\`\`\`bash
git clone <your-repo-url>
cd iam-enforcer
python -m venv venv
venv\Scripts\activate       # Windows
pip install -r requirements.txt
copy .env.example .env      # then fill in your Anthropic API key
aws configure                # set up your AWS credentials
\`\`\`

## Usage

\`\`\`bash
# Scan for over-privileged policies
python -m src.cli scan --use-aws

# Full analysis: scan + CloudTrail + risk scoring
python -m src.cli analyze --use-aws
\`\`\`

## Project structure

\`\`\`
src/
├── scanner.py              # M1 — IAM policy scanner
├── cloudtrail_analyzer.py  # M3 — CloudTrail usage analysis
├── risk_scorer.py          # M2 — risk scoring engine
├── validator.py            # policy validation
└── cli.py                  # command-line interface
tests/                       # pytest test suite
\`\`\`

