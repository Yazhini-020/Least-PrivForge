"""
ci_gate.py — CI/CD Security Gate (Module 6)
AWS IAM Least-Privilege Policy Enforcer

What this file does
-------------------
Acts as an enforcement checkpoint in CI/CD pipelines (e.g. GitHub Actions).
Scans IAM policy definitions in code (JSON, YAML/CloudFormation, Terraform .tf)
or live/mock IAM entities for dangerous wildcard permissions and structural violations.

Returns exit code 0 if all policies pass security rules.
Returns exit code 1 if any policy fails (contains CRITICAL or HIGH risk wildcards).
"""

import os
import sys
import json
import re
from typing import List, Dict, Any, Tuple
import yaml
from rich.console import Console
from rich.table import Table

from src.validator import PolicyValidator
from src.scanner import scan_policy_document, scan_all

console = Console()

SEVERITY_MAP = {
    "FULL_ADMIN_ACCESS": "CRITICAL",
    "WILDCARD_ACTION": "CRITICAL",
    "SERVICE_WILDCARD_WITH_WILDCARD_RESOURCE": "HIGH",
    "SERVICE_WILDCARD_ACTION": "MEDIUM",
    "WILDCARD_RESOURCE": "MEDIUM",
}

SEVERITY_RANKS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

def extract_json_objects_from_text(text: str) -> List[Dict[str, Any]]:
    """Extract valid JSON objects containing 'Statement' from plain text or TF files."""
    results = []

    # 1. Look for jsonencode(...) blocks in HCL/TF
    jsonencode_blocks = re.findall(r'jsonencode\s*\(\s*(\{[\s\S]*?\})\s*\)', text)
    for block in jsonencode_blocks:
        try:
            obj = json.loads(block)
            if isinstance(obj, dict) and "Statement" in obj:
                results.append(obj)
        except Exception:
            pass

    # 2. Balanced brace search starting at every '{' in text
    if not results:
        for start_idx in range(len(text)):
            if text[start_idx] == '{':
                brace_level = 0
                for end_idx in range(start_idx, len(text)):
                    if text[end_idx] == '{':
                        brace_level += 1
                    elif text[end_idx] == '}':
                        brace_level -= 1
                        if brace_level == 0:
                            candidate = text[start_idx:end_idx + 1]
                            if '"Statement"' in candidate or "'Statement'" in candidate:
                                try:
                                    obj = json.loads(candidate)
                                    if isinstance(obj, dict) and "Statement" in obj:
                                        if obj not in results:
                                            results.append(obj)
                                except Exception:
                                    pass
                            break
    return results


def find_policies_in_dict_or_list(data: Any, source_path: str) -> List[Dict[str, Any]]:
    """Recursively search a parsed dict or list for IAM policy documents."""
    policies = []

    if isinstance(data, dict):
        if "Statement" in data:
            statements = data["Statement"]
            if isinstance(statements, (list, dict)):
                policies.append({"source": source_path, "policy": data})
                return policies
        for key, value in data.items():
            policies.extend(find_policies_in_dict_or_list(value, source_path))

    elif isinstance(data, list):
        for item in data:
            policies.extend(find_policies_in_dict_or_list(item, source_path))

    return policies


def extract_policies_from_file(file_path: str) -> List[Dict[str, Any]]:
    """Parse a file (.json, .yaml, .yml, .tf) and return all IAM policies found within it."""
    policies = []
    if not os.path.isfile(file_path):
        return policies

    ext = os.path.splitext(file_path)[1].lower()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if ext == ".json":
            try:
                data = json.loads(content)
                policies.extend(find_policies_in_dict_or_list(data, file_path))
            except json.JSONDecodeError:
                pass

        elif ext in (".yaml", ".yml"):
            try:
                data = yaml.safe_load(content)
                policies.extend(find_policies_in_dict_or_list(data, file_path))
            except Exception:
                pass

        elif ext == ".tf":
            extracted = extract_json_objects_from_text(content)
            for p in extracted:
                policies.append({"source": file_path, "policy": p})

    except Exception as e:
        console.print(f"[yellow]Warning: Could not read file {file_path}: {e}[/yellow]")

    return policies


def scan_policy_for_ci(policy_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and scan a single policy dict for CI security check.
    Returns details on validity and findings.
    """
    validator = PolicyValidator()
    val_result = validator.validate_policy_json(policy_dict)

    if not val_result["is_valid"]:
        return {
            "is_valid": False,
            "errors": val_result["errors"],
            "findings": [],
            "max_severity": "CRITICAL"
        }

    raw_findings = scan_policy_document(policy_dict)
    processed_findings = []
    max_severity = "NONE"
    max_rank = 0

    for f in raw_findings:
        ftype = f["finding_type"]
        sev = SEVERITY_MAP.get(ftype, "MEDIUM")
        rank = SEVERITY_RANKS.get(sev, 1)

        if rank > max_rank:
            max_rank = rank
            max_severity = sev

        processed_findings.append({
            "finding_type": ftype,
            "severity": sev,
            "description": f["description"],
            "actions": f["actions"],
            "resources": f["resources"],
        })

    return {
        "is_valid": True,
        "errors": [],
        "findings": processed_findings,
        "max_severity": max_severity
    }


def run_ci_gate(
    target_path: str = None,
    fail_threshold: str = "HIGH",
    scan_mock_entities: bool = False
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Main runner for CI/CD Security Gate.

    Args:
        target_path: File or directory to scan for policy files.
        fail_threshold: Minimum severity to fail the CI build ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        scan_mock_entities: If True, also includes scanner.scan_all(use_mock=True).

    Returns:
        (passed: bool, summary_results: list)
    """
    fail_rank = SEVERITY_RANKS.get(fail_threshold.upper(), 3)
    policy_targets = []

    if target_path:
        if os.path.isfile(target_path):
            policy_targets.extend(extract_policies_from_file(target_path))
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                if any(part.startswith(".") for part in root.split(os.sep)):
                    continue
                for file in files:
                    if file.endswith((".json", ".yaml", ".yml", ".tf")):
                        full_p = os.path.join(root, file)
                        policy_targets.extend(extract_policies_from_file(full_p))

    mock_findings = []
    if scan_mock_entities or not target_path:
        mock_findings = scan_all(use_mock=True)

    results = []
    has_failure = False

    for item in policy_targets:
        src = item["source"]
        pol = item["policy"]
        analysis = scan_policy_for_ci(pol)

        is_failed = False
        if not analysis["is_valid"]:
            is_failed = True
        else:
            sev_rank = SEVERITY_RANKS.get(analysis["max_severity"], 0)
            if sev_rank >= fail_rank:
                is_failed = True

        if is_failed:
            has_failure = True

        results.append({
            "source": src,
            "policy": pol,
            "is_valid": analysis["is_valid"],
            "errors": analysis["errors"],
            "findings": analysis["findings"],
            "max_severity": analysis["max_severity"],
            "status": "FAIL" if is_failed else "PASS"
        })

    for f in mock_findings:
        ftype = f["finding_type"]
        sev = SEVERITY_MAP.get(ftype, "HIGH")
        sev_rank = SEVERITY_RANKS.get(sev, 0)
        is_failed = sev_rank >= fail_rank
        if is_failed:
            has_failure = True

        results.append({
            "source": f"Mock Entity: {f['entity_name']} ({f['policy_name']})",
            "policy": f.get("policy_json", {}),
            "is_valid": True,
            "errors": [],
            "findings": [{
                "finding_type": ftype,
                "severity": sev,
                "description": f["description"],
                "actions": f["actions"],
                "resources": f["resources"],
            }],
            "max_severity": sev,
            "status": "FAIL" if is_failed else "PASS"
        })

    passed = not has_failure
    return passed, results


def render_ci_report(passed: bool, results: List[Dict[str, Any]], fail_threshold: str):
    """Print human-friendly Rich table and summary report for CI console."""
    console.print("\n[bold blue]==========================================[/bold blue]")
    console.print("[bold blue]       M6 -- IAM CI/CD SECURITY GATE       [/bold blue]")
    console.print("[bold blue]==========================================[/bold blue]\n")

    if not results:
        console.print("[yellow][!] No IAM policies found to scan.[/yellow]")
        return

    table = Table(title="CI Security Gate Audit Results", show_header=True, header_style="bold", expand=True)
    table.add_column("Source / File", style="cyan", overflow="fold")
    table.add_column("Status", style="bold", width=8)
    table.add_column("Max Severity", style="magenta", width=12)
    table.add_column("Findings / Details", style="white", overflow="fold")

    for r in results:
        status_str = f"[bold red]FAIL[/bold red]" if r["status"] == "FAIL" else f"[bold green]PASS[/bold green]"
        
        details = []
        if not r["is_valid"]:
            details.append("[red]Invalid Policy Structure/Syntax:[/red] " + "; ".join(r["errors"]))
        for f in r["findings"]:
            details.append(f"[{f['severity']}] {f['finding_type']}: {f['description']}")

        detail_text = "\n".join(details) if details else "[green]No over-privileged wildcards detected.[/green]"

        table.add_row(
            r["source"],
            status_str,
            r["max_severity"],
            detail_text
        )

    console.print(table)
    console.print()

    if passed:
        console.print(f"[bold green][PASS] CI SECURITY GATE PASSED[/bold green] -- All policies satisfy least-privilege enforcement rules (Threshold: {fail_threshold}).")
    else:
        console.print(f"[bold red][FAIL] CI SECURITY GATE FAILED[/bold red] -- Insecure wildcard IAM permissions detected (Threshold: {fail_threshold}).")
        console.print("[bold red]Action Required:[/bold red] Fix excessive permissions before merging into protected branches.")
