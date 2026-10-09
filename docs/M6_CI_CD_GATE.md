# M6 – CI/CD Security Gate

## Overview

**M6 (CI/CD Security Gate)** elevates the AWS IAM Least-Privilege Policy Enforcer from a detection and remediation tool to a **pre-merge enforcement system**.

In modern DevSecOps workflows, preventing security regressions before they hit `main` or production branches is critical. M6 ensures that any pull request containing unsafe IAM policy statements (such as `Action: "*"` or `Action: "s3:*"` with `Resource: "*"`) automatically fails CI build checks and is blocked from merging.

---

## Key Features

1. **Multi-Format IaC Scanner**
   - Automatically detects and extracts IAM policies from raw JSON files, CloudFormation YAML/JSON templates, and Terraform `.tf` files (`jsonencode` blocks).
2. **Reuses Core Security Engine**
   - Uses `src/scanner.py` and `src/validator.py` rules so security criteria stay identical across CLI, AI remediations, and CI checks.
3. **Configurable Failure Thresholds**
   - Exit status `0` on clean pass; Exit status `1` on security rule violations.
   - Severity options: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` (default failure threshold: `HIGH`).
4. **GitHub Actions Integration**
   - Out-of-the-box workflow template in `.github/workflows/ci-security-gate.yml`.

---

## Local Usage

Run the CI Security Gate manually on your repository or specific files:

```bash
# Scan repository/exports using CLI
python -m src.cli ci-gate

# Scan a specific file or folder
python -m src.cli ci-gate --path exports/

# Scan with custom severity threshold (e.g. fail on CRITICAL only)
python -m src.cli ci-gate --fail-on CRITICAL

# Include mock IAM entities in the check
python -m src.cli ci-gate --use-mock
```

---

## CI/CD Pipeline Architecture

```text
                  Developer
                      │
                      ▼
               Git Repository
                      │
                      ▼
            Pull Request Created
                      │
                      ▼
          ┌───────────────────────┐
          │ GitHub Actions Runner │
          └───────────┬───────────┘
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
  Run Unit Tests            IAM Security Gate
  (pytest)                  (python -m src.cli ci-gate)
                                    │
                                    ▼
                          Policy Scanner & Validator
                                    │
                   ┌────────────────┴───────────────┐
                   │                                │
                   ▼                                ▼
               Safe Policy                     Risky Policy
             (Exit Code 0)                    (Exit Code 1)
                   │                                │
                   ▼                                ▼
                 PASS                              FAIL
                   │                                │
                   ▼                                ▼
           Required Check Pass            Required Check Fail
                   │                                │
                   ▼                                ▼
            Merge Allowed                    Merge Blocked
```

---

## GitHub Branch Protection Setup

To enforce PR blocking in GitHub:

1. Go to repository **Settings** → **Branches**.
2. Click **Add branch protection rule** (or edit rule for `main`/`master`).
3. Enable **Require status checks to pass before merging**.
4. Search for and select: `IAM Policy Security Check & Unit Tests` (or `iam-security-gate`).
5. Save changes.

Now, any Pull Request introducing an over-privileged IAM policy will fail the check and be prevented from merging into `main`.
