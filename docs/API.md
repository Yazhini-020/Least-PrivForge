# API Reference — AI IAM Least-Privilege Enforcer

Internal module reference. This is a CLI tool, not a hosted API — this
document describes the Python functions/classes each module exposes for
other modules (and the CLI) to call.

---

## `src/scanner.py`

### `scan_all(use_mock: bool = False) -> list[dict]`

Scans the entire IAM account (or mock data) and returns every finding.

**Args**
- `use_mock` — `True` reads from `src/mock_data.py`; `False` connects to
  live AWS via boto3.

**Returns** — list of finding dicts (see shape in ARCHITECTURE.md).
Compliant entities are logged but not included in the returned list.

**Example**
```python
from src.scanner import scan_all

findings = scan_all(use_mock=False)
print(f"{len(findings)} over-privileged policies found")
```

---

### `get_cloudtrail_usage(entity_name: str, use_mock: bool = False) -> list[str]`

Returns the list of API actions used by an entity in the last 30 days.
Lightweight stub — full implementation lives in `cloudtrail_analyzer.py`.

**Args**
- `entity_name` — role or user name to look up
- `use_mock` — `True` returns data from `MOCK_CLOUDTRAIL_USAGE`

**Returns** — list of `"service:Action"` strings, e.g. `["s3:GetObject"]`

---

### `scan_policy_document(document: dict) -> list[dict]`

Scans a single IAM policy document for wildcard findings across all its
statements. Useful for testing detection logic in isolation without a live
AWS connection.

**Args**
- `document` — full policy document dict with a `Statement` key

**Returns** — list of findings (finding_type, description, actions, resources)

---

## `src/cloudtrail_analyzer.py`

### `class CloudTrailAnalyzer(profile='default', region='eu-central-1', days=30)`

**`analyze_role_usage(role_name: str) -> dict`**

Fetches CloudTrail events for a role over the configured window and
returns actual usage statistics.

**Returns**
```python
{
    "role_name":       str,
    "role_arn":        str,
    "actions_used":    list[str],
    "action_count":    int,
    "action_frequency": dict[str, int],
    "last_activity":   str | None,
    "source_ips":      list[str],
    "days_analyzed":   int,
    "status":          "analyzed" | "no_activity",
}
```

**`analyze_multiple_roles(role_names: list[str]) -> list[dict]`**

Runs `analyze_role_usage` across multiple roles, returns list of results.

---

## `src/risk_scorer.py`

### `class RiskScorer()`

**`score_policy(policy_json: dict, entity_type: str = 'role', is_internet_facing: bool = False) -> dict`**

Scores a single policy document.

**Returns**
```python
{
    "score":    float,   # 0.0-1.0
    "severity": str,     # LOW | MEDIUM | HIGH | CRITICAL
    "reasons":  list[str],
    "features": {
        "has_action_wildcard": bool,
        "has_resource_wildcard": bool,
        "num_services": int,
        "num_admin_actions": int,
        "is_internet_facing": bool,
    }
}
```

**`score_multiple_policies(findings: list[dict]) -> list[dict]`**

Scores a batch of findings (as returned by `scan_all`), merges the score
result into each finding dict, and returns the list sorted by score
descending (highest risk first).

---

## `src/validator.py`

### `class PolicyValidator()`

**`validate_policy_json(policy: dict) -> dict`**

Structural validation of IAM policy JSON — checks required fields, valid
`Effect` values, action/resource format.

**Returns**
```python
{
    "is_valid":        bool,
    "errors":          list[str],
    "suggestions":     list[str],
    "statement_count": int,
}
```

---

## `src/cli.py`

Command-line entry points. Run with `python -m src.cli <command>`.

### `scan`

```bash
python -m src.cli scan --use-aws
python -m src.cli scan --use-mock
```

Runs `scan_all()` and prints results as a table. Saves raw findings to
`findings.json`.

### `analyze`

```bash
python -m src.cli analyze --use-aws --region eu-central-1 --days 30
```

Full pipeline: scan → CloudTrail usage → risk scoring. Prints a ranked
risk table and saves the full report to `analysis_report.json`.

**Options**
| Flag | Default | Description |
|---|---|---|
| `--profile` | `default` | AWS credentials profile |
| `--region` | `eu-central-1` | AWS region |
| `--days` | `30` | CloudTrail lookback window |
| `--use-mock` / `--use-aws` | `--use-aws` | Data source |

---

## Planned (not yet implemented)

- `src/ai_generator.py` — `generate_least_privilege_policy(finding, usage_data) -> dict`
- `src/formatter.py` — `to_terraform(policy) -> str`, `to_cloudformation(policy) -> str`