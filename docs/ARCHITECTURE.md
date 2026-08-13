# Architecture — AI IAM Least-Privilege Enforcer

## Overview

The system is a Python CLI tool that scans AWS IAM policies, analyzes real
usage via CloudTrail, scores risk, and (in progress) generates least-privilege
policy replacements using Claude AI. It runs entirely from the command line —
no server, no persistent database, no cloud deployment required.

## Design principle

Every stage is a plain Python function or class operating on shared dict
structures — no framework, no ORM, no hidden state. This keeps each module
independently testable, and keeps the codebase approachable for a two-person
team learning AWS APIs from scratch.

## Pipeline
AWS Account
↓
[M1] Scanner → detects over-privileged policies
↓
[M3] CloudTrail Analyzer → determines actual API usage per role
↓
[M2] Risk Scorer → assigns severity based on blast radius
↓
[M4] AI Generator (WIP) → produces least-privilege replacement via Claude
↓
[Validator] (WIP) → confirms generated policy is valid IAM JSON
↓
[M5] Output Formatter (WIP) → exports JSON / HCL / YAML
↓
[M6] CI/CD Gate (WIP) → blocks PRs introducing wildcard policies
↓
[M7] Streamlit Dashboard (WIP) → visual demo UI

## Module breakdown

### M1 — Scanner (`src/scanner.py`)

Connects to AWS IAM via `boto3`, fetches every role, user, and group along
with their inline and managed policies, and inspects each policy statement
for five wildcard patterns:

| Finding type | Pattern | Severity |
|---|---|---|
| `FULL_ADMIN_ACCESS` | `Action:*` + `Resource:*` | CRITICAL |
| `WILDCARD_ACTION` | `Action:*` on scoped resource | CRITICAL |
| `SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE` | `service:*` + `Resource:*` | HIGH/CRITICAL |
| `SERVICE_WILDCARD_ACTION` | `service:*` on scoped resource | MEDIUM |
| `WILDCARD_RESOURCE` | scoped action + `Resource:*` | MEDIUM |

**Noise filtering:** AWS-owned service-linked roles (`AWSServiceRoleFor*`)
and AWS-managed policies (`arn:aws:iam::aws:policy/...`) are skipped
entirely — their wildcards are by design and not actionable by developers.
This eliminated 7 of 8 false positives found during initial testing.

Two data modes: `use_mock=True` reads from `src/mock_data.py` for offline
development; `use_mock=False` connects to a live AWS account.

### M3 — CloudTrail Analyzer (`src/cloudtrail_analyzer.py`)

Queries `CloudTrail.lookup_events` for a given role over a configurable
window (default 30 days) and extracts the exact set of API actions that
role actually called. This usage data is what will ground M4's AI
recommendations in real behavior instead of guesswork.

Only applies to `entity_type == 'role'` — CloudTrail logs identities that
act (users, roles via STS), not policy containers like groups.

### M2 — Risk Scorer (`src/risk_scorer.py`)

Rule-based scoring (ML/XGBoost planned as a stretch goal). Computes a
0.0–1.0 score per finding based on weighted factors:

- Wildcard action present (0.35)
- Wildcard resource present (0.35)
- Number of distinct services exposed (0.25)
- Admin-level / privilege-escalation actions detected (0.20)
- Entity is internet-facing (0.20)

Score maps to severity: `CRITICAL` ≥0.8, `HIGH` ≥0.6, `MEDIUM` ≥0.4,
else `LOW`. Each policy statement is scored independently — a single
entity with multiple over-privileged statements gets multiple, separately
prioritized findings.

### M4 — AI Policy Generator (planned)

Will send the over-privileged policy plus its CloudTrail usage data to the
Claude API, requesting a minimal replacement policy that covers only the
actions actually observed. Output is validated (see below) before being
returned.

### Validator (planned)

Runs generated policy JSON through structural validation (and optionally
OPA) to confirm syntactic correctness before it's shown to the user. Failed
validations are fed back to the AI generator with the specific error for
regeneration — a closed self-correcting loop.

### M5 — Output Formatter (planned)

Exports the validated replacement policy as raw IAM JSON, Terraform HCL,
or CloudFormation YAML.

### M6 — CI/CD Gate (planned)

GitHub Actions step that scans IAM policy files changed in a pull request
and fails the build if wildcard patterns are introduced.

### M7 — Streamlit Dashboard (planned)

Browser-based visual demo — scan results, before/after policy diffs,
one-click fix generation.

## Data flow contract

Every module downstream of the scanner consumes the same finding shape:

```python
{
    "entity_name":  str,
    "entity_type":  "role" | "user" | "group",
    "arn":          str,
    "policy_name":  str,
    "policy_type":  "inline" | "managed",
    "policy_json":  dict,
    "finding_type": str,
    "description":  str,
    "actions":      list[str],
    "resources":    list[str],
    "ml_score":     float | None,   # filled by risk_scorer
    "severity":     str | None,     # filled by risk_scorer
}
```

Keeping this shape consistent across modules is what lets each team member
build and test their module independently against the same test fixtures.

## Known limitations (current state)

- CloudTrail analysis requires the role to have real API activity; freshly
  created test roles show `action_count: 0` until used.
- Risk scoring is rule-based, not yet ML-driven.
- No AI generation, validation loop, output export, CI/CD gate, or
  dashboard yet — these are the next build phases.