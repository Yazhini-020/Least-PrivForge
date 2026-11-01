import os
import json
import logging
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from dotenv import load_dotenv

load_dotenv()
console = Console()


@click.group()
def cli():
    """LeastPrivForge — AI-Driven Cloud Least-Privilege Enforcement System"""
    pass


@cli.command()
@click.option('--profile', default='default', help='AWS profile')
@click.option('--region', default='eu-central-1', help='AWS region')
@click.option('--days', default=30, help='CloudTrail days to analyze')
@click.option('--use-mock/--use-aws', default=True, help='Use mock data or real AWS')
def fix(profile, region, days, use_mock):
    """Execute Full LeastPrivForge Pipeline: Scan → Correlate → Score → Remediate → Diff → Orphan Check"""
    
    # 1. Silence noisy AWS / library logs so terminal output remains clean
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('boto3').setLevel(logging.ERROR)
    logging.getLogger('urllib3').setLevel(logging.ERROR)
    logging.getLogger('src').setLevel(logging.WARNING)
    logging.getLogger().setLevel(logging.WARNING)

    console.print()
    console.print(Panel.fit(
        "[bold white]🛡️ LEASTPRIVFORGE: END-TO-END LEAST-PRIVILEGE PIPELINE[/bold white]\n"
        "[dim]Behavioral IAM Grounding •XGBoost RiskScore • Generative AI Remediation[/dim]",
        border_style="cyan"
    ))
    console.print()

    from src.scanner import scan_all
    from src.cloudtrail_analyzer import CloudTrailAnalyzer
    from src.temporal_analyzer import TemporalAccessAnalyzer
    from src.risk_scorer import RiskScorer
    from src.ai_generator import generate_for_findings
    from src.orphaned_detector import OrphanedIdentityDetector
    from src.diff_viewer import build_diff, render_text
    from src.formatter import export_all

    # -------------------------------------------------------------
    # [1/5] SCANNING IAM ENTITIES
    # -------------------------------------------------------------
    with console.status("[cyan]Phase 1: Scanning AWS IAM policies for wildcards...[/cyan]", spinner="dots"):
        findings = scan_all(use_mock=use_mock)

    if not findings:
        console.print("[bold green]✓ Phase 1: Clean account! No over-privileged policies found.[/bold green]\n")
        return

    console.print(f"[bold green]✓ Phase 1 Complete:[/bold green] Discovered [bold cyan]{len(findings)}[/bold cyan] over-privileged entity findings.")

    # -------------------------------------------------------------
    # [2/5] CLOUDTRAIL BEHAVIORAL CORRELATION
    # -------------------------------------------------------------
    usage_data_map = {}
    seen_roles = set()
    with console.status(f"[cyan]Phase 2: Ingesting & correlating CloudTrail logs (last {days} days)...[/cyan]", spinner="dots"):
        analyzer = CloudTrailAnalyzer(profile=profile, region=region, days=days)
        for f in findings:
            if f['entity_type'] == 'role' and f['entity_name'] not in seen_roles:
                seen_roles.add(f['entity_name'])
                usage_data_map[f['entity_name']] = analyzer.analyze_role_usage(f['entity_name'])

    console.print(f"[bold green]✓ Phase 2 Complete:[/bold green] Correlated runtime API events for [bold cyan]{len(seen_roles)}[/bold cyan] active roles.")

    # -------------------------------------------------------------
    # [3/5] TEMPORAL ACCESS PROFILING
    # -------------------------------------------------------------
    temporal_payload_map = {}
    temporal_results = []
    with console.status("[cyan]Phase 3: Profiling temporal activity patterns...[/cyan]", spinner="dots"):
        temporal_analyzer = TemporalAccessAnalyzer()
        for role_name in seen_roles:
            timestamps = analyzer.get_action_timestamps(role_name)
            if not timestamps:
                continue
            t_res = temporal_analyzer.analyze(timestamps)
            temporal_payload_map[role_name] = temporal_analyzer.build_ai_payload(t_res)
            temporal_results.append({
                "role": role_name,
                "events": t_res.get("total_events", len(timestamps)),
                "hours": f"{t_res.get('min_hour', 0):02d}:00 - {t_res.get('max_hour', 23):02d}:59 UTC",
                "ratio": f"{t_res.get('business_hours_ratio', 1.0) * 100:.0f}%",
                "off_hours": t_res.get("off_hours_events", 0)
            })

    console.print(f"[bold green]✓ Phase 3 Complete:[/bold green] Temporal access profiling complete.")

    # -------------------------------------------------------------
    # [4/5] PREDICTIVE MACHINE LEARNING RISK SCORING
    # -------------------------------------------------------------
    with console.status("[cyan]Phase 4: Running 16-feature XGBoost risk scoring...[/cyan]", spinner="dots"):
        scorer = RiskScorer()
        findings = scorer.score_multiple_policies(findings, usage_data_map)

    console.print(f"[bold green]✓ Phase 4 Complete:[/bold green] Calibrated ML breach risk ratings evaluated.")

    # -------------------------------------------------------------
    # [5/5] AI-POWERED POLICY SYNTHESIS & VALIDATION
    # -------------------------------------------------------------
    with console.status("[bold cyan]Phase 5: Synthesizing verified least-privilege replacement policies via AI...[/bold cyan]", spinner="dots"):
        results = generate_for_findings(findings, usage_data_map, temporal_payload_map)

    console.print(f"[bold green]✓ Phase 5 Complete:[/bold green] Remediation generation and verification complete.\n")

    # =============================================================
    # PRESENTATION SECTION 1: RISK & PIPELINE ASSESSMENT TABLE
    # =============================================================
    summary_table = Table(title="📊 Discovered Entitlements & XGBoost Risk Ratings", show_header=True, header_style="bold magenta", expand=True)
    summary_table.add_column("Entity Name", style="bold cyan", width=24)
    summary_table.add_column("Type", style="white", width=8)
    summary_table.add_column("Vulnerability Flagged", style="yellow")
    summary_table.add_column("XGBoost Risk", justify="center", width=16)
    summary_table.add_column("Remediation Status", justify="center", width=22)

    for r in results:
        sev = r.get('severity', 'UNKNOWN')
        score = r.get('score', 0.0)
        sev_color = "red" if sev in ("CRITICAL", "HIGH") else "yellow" if sev == "MEDIUM" else "green"
        rec = r.get('ai_recommendation', {})

        if rec.get('success'):
            status_text = "[bold green]✓ Remediated & Exported[/bold green]"
        elif "No CloudTrail activity" in rec.get('explanation', ''):
            status_text = "[dim yellow]⚠ Dormant (0 Activity)[/dim yellow]"
        else:
            status_text = "[dim]Manual Review (Admin/Group)[/dim]"

        summary_table.add_row(
            r['entity_name'],
            r.get('entity_type', 'role').upper(),
            r['finding_type'].replace('_', ' '),
            f"[{sev_color}]{sev} ({score:.2f})[/{sev_color}]",
            status_text
        )

    console.print(summary_table)
    console.print()

    # =============================================================
    # PRESENTATION SECTION 2: TEMPORAL ACCESS PATTERNS TABLE
    # =============================================================
    if temporal_results:
        t_table = Table(title="⏰ Temporal Working Hours & Access Windows", show_header=True, header_style="bold blue", expand=True)
        t_table.add_column("IAM Role", style="cyan")
        t_table.add_column("Observed Events", justify="right", style="green")
        t_table.add_column("Active Hours (UTC)", style="white")
        t_table.add_column("Business Hours %", justify="right", style="yellow")
        t_table.add_column("Off-Hours Anomalies", justify="right", style="magenta")

        for t in temporal_results:
            t_table.add_row(t['role'], str(t['events']), t['hours'], t['ratio'], str(t['off_hours']))

        console.print(t_table)
        console.print()

    # =============================================================
    # PRESENTATION SECTION 3: BEFORE VS AFTER POLICY DIFF
    # =============================================================
    remediated_count = 0
    for r in results:
        rec = r.get('ai_recommendation', {})
        if rec.get('success'):
            remediated_count += 1
            os.makedirs('exports', exist_ok=True)
            export_paths = export_all(rec['policy'], base_name=f"exports/{r['entity_name']}")

            diff_dict = build_diff(r)
            console.print(Panel(
                f"[bold green]Transformation for Role: {r['entity_name']}[/bold green]\n"
                f"• [bold red]Removed Wildcards:[/bold red] {', '.join(rec.get('removed_actions', ['*']))}\n"
                f"• [bold green]Retained Actions:[/bold green] Grounded in verified CloudTrail events\n"
                f"• [bold cyan]Multi-IaC Exports:[/bold cyan] {export_paths['json']}, {export_paths['terraform']}, {export_paths['cloudformation']}\n\n"
                f"{render_text(diff_dict)}",
                title=f"🔍 Policy Diff Viewer — {r['entity_name']}",
                border_style="green"
            ))
            console.print()

    # =============================================================
    # PRESENTATION SECTION 4: ORPHANED & INACTIVE IDENTITIES
    # =============================================================
    try:
        logging.getLogger().setLevel(logging.CRITICAL)  # Silence permission denial traces during key scans
        detector = OrphanedIdentityDetector(profile=profile, region=region, threshold_days=90)
        orphaned_list = detector.scan_all()
        if orphaned_list:
            orph_table = Table(title="⚠ Inactive & Orphaned Identifiers (>90 Days Inactive)", show_header=True, header_style="bold red", expand=True)
            orph_table.add_column("Entity Name", style="cyan")
            orph_table.add_column("Type", style="magenta")
            orph_table.add_column("Status", style="red")
            orph_table.add_column("Recommended Action", style="green")

            for o in orphaned_list:
                orph_table.add_row(o['entity_name'], o['entity_type'].upper(), o['status'], o['recommendation'])

            console.print(orph_table)
            console.print()
        else:
            console.print("[bold green]✓ Orphaned Check:[/bold green] No completely inactive roles detected.\n")
    except Exception:
        pass

    with open('fixes_report.json', 'w') as fh:
        json.dump(results, fh, indent=2, default=str)

    console.print(Panel(
        f"[bold green]✔ Pipeline Execution Successfully Finished![/bold green]\n"
        f"• Evaluated: [cyan]{len(results)}[/cyan] findings across live AWS infrastructure\n"
        f"• Remediated: [cyan]{remediated_count}[/cyan] active roles pruned to least privilege\n"
        f"• Stored Report: [yellow]fixes_report.json[/yellow] & [yellow]exports/[/yellow]",
        border_style="cyan"
    ))
    console.print()


@cli.command(name='ci-gate')
@click.option('--path', default=None, help='File or directory path to scan')
@click.option('--fail-on', default='HIGH', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], case_sensitive=False), help='Minimum risk severity to trigger CI check failure')
@click.option('--use-mock/--no-mock', default=False, help='Include mock identities in scan')
def ci_gate(path, fail_on, use_mock):
    """M6 — CI/CD Security Gate: Check IAM policies for unsafe wildcards in Pull Requests"""
    import sys
    from src.ci_gate import run_ci_gate, render_ci_report

    passed, results = run_ci_gate(
        target_path=path,
        fail_threshold=fail_on,
        scan_mock_entities=use_mock
    )

    render_ci_report(passed, results, fail_on)

    if not passed:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    cli()