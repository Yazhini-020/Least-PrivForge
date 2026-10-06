import json
import click
from rich.console import Console
from rich.table import Table

from src.scanner import scan_all
from src.cloudtrail_analyzer import CloudTrailAnalyzer
from src.risk_scorer import RiskScorer
from src.validator import PolicyValidator
from dotenv import load_dotenv
load_dotenv()
console = Console()


@click.group()
def cli():
    """AI IAM Least-Privilege Enforcer"""
    pass


@cli.command()
@click.option('--use-mock/--use-aws', default=True, help='Use mock data or real AWS')
def scan(use_mock):
    """Scan AWS IAM policies for over-privileged patterns"""
    console.print("[bold blue]🔍 Scanning IAM policies...[/bold blue]\n")

    findings = scan_all(use_mock=use_mock)

    if not findings:
        console.print("[bold green]✓ No over-privileged policies found![/bold green]")
        return

    console.print(f"[bold red]⚠ Found {len(findings)} finding(s)[/bold red]\n")

    table = Table(title="Over-Privileged Policies", show_header=True, header_style="bold")
    table.add_column("Entity", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Finding", style="red")
    table.add_column("Policy", style="green")

    for f in findings:
        table.add_row(
            f['entity_name'],
            f['entity_type'].upper(),
            f['finding_type'],
            f['policy_name']
        )

    console.print(table)

    with open('findings.json', 'w') as fh:
        json.dump(findings, fh, indent=2, default=str)
    console.print("\n[bold]📁 Raw findings saved to findings.json[/bold]")


@cli.command()
@click.option('--profile', default='default', help='AWS profile')
@click.option('--region', default='eu-central-1', help='AWS region')
@click.option('--days', default=30, help='CloudTrail days to analyze')
@click.option('--use-mock/--use-aws', default=True, help='Use mock data or real AWS')
def analyze(profile, region, days, use_mock):
    """Full analysis: scan → CloudTrail → risk score"""

    console.print("[bold blue]🔍 Phase 2: Full Analysis[/bold blue]\n")

    # Step 1: Scan — uses scan_all(), matching your team's scanner.py
    console.print("[1/3] Scanning IAM policies...")
    findings = scan_all(use_mock=use_mock)
    console.print(f"[green]✓ Found {len(findings)} finding(s)[/green]\n")

    if not findings:
        console.print("[bold green]No over-privileged policies to analyze.[/bold green]")
        return

    # Step 2: CloudTrail analysis
    console.print("[2/3] Analyzing CloudTrail usage...")
    analyzer = CloudTrailAnalyzer(profile=profile, region=region, days=days)

    usage_data = {}
    seen_roles = set()
    for finding in findings:
        if finding['entity_type'] == 'role' and finding['entity_name'] not in seen_roles:
            role_name = finding['entity_name']
            seen_roles.add(role_name)
            usage = analyzer.analyze_role_usage(role_name)
            usage_data[role_name] = usage
            console.print(f"  → {role_name}: {usage.get('action_count', 0)} unique actions")

    console.print("[green]✓ CloudTrail analysis complete[/green]\n")

    # Step 3: Risk scoring — ML (XGBoost), rule-based fallback if no model
    console.print("[3/3] Risk scoring...")
    scorer = RiskScorer()
    scored_findings = scorer.score_multiple_policies(findings, usage_data)
    console.print("[green]✓ Risk scoring complete[/green]\n")

    # Display
    console.print("[bold red]RISK ASSESSMENT[/bold red]\n")
    table = Table(
    title="Over-Privileged Policies (Ranked by Risk)",
    show_header=True,
    header_style="bold",
    expand=True  )
    table.add_column("Entity", style="cyan", overflow="fold", min_width=20)
    table.add_column("Finding", style="red", overflow="fold", min_width=18)
    table.add_column("Severity", style="red", width=10)
    table.add_column("Score", style="yellow", width=7)
    table.add_column("Actions Used", style="green", width=14)

    for finding in scored_findings[:10]:
        role_name = finding['entity_name']
        usage = usage_data.get(role_name, {})
        table.add_row(
            role_name,
            finding['finding_type'],
            finding['severity'],
            f"{finding['score']:.2f}",
            f"{usage.get('action_count', 0)} actions"
        )

    console.print(table)

    report = {
        'timestamp': str(__import__('datetime').datetime.now()),
        'total_findings': len(findings),
        'scored_findings': scored_findings,
        'usage_data': usage_data
    }
    with open('analysis_report.json', 'w') as fh:
        json.dump(report, fh, indent=2, default=str)

    console.print("\n[bold]📊 Full report saved to analysis_report.json[/bold]")
@cli.command()
@click.option('--profile', default='default', help='AWS profile')
@click.option('--region', default='eu-central-1', help='AWS region')
@click.option('--days', default=30, help='CloudTrail days to analyze')
@click.option('--use-mock/--use-aws', default=True, help='Use mock data or real AWS')
def fix(profile, region, days, use_mock):
    """Full pipeline: scan → CloudTrail → risk score → AI-generate fixes"""

    from src.ai_generator import generate_for_findings
    from src.scanner import scan_all
    from src.cloudtrail_analyzer import CloudTrailAnalyzer
    from src.risk_scorer import RiskScorer
    from src.temporal_analyzer import TemporalAccessAnalyzer

    console.print("[bold blue]🔍 Full Pipeline: Scan → Analyze → Generate Fixes[/bold blue]\n")

    console.print("[1/5] Scanning IAM policies...")
    findings = scan_all(use_mock=use_mock)
    console.print(f"[green]✓ Found {len(findings)} finding(s)[/green]\n")

    if not findings:
        console.print("[bold green]No over-privileged policies found. Nothing to fix.[/bold green]")
        return

    console.print("[2/5] Analyzing CloudTrail usage...")
    analyzer = CloudTrailAnalyzer(profile=profile, region=region, days=days)
    usage_data_map = {}
    seen_roles = set()
    for f in findings:
        if f['entity_type'] == 'role' and f['entity_name'] not in seen_roles:
            seen_roles.add(f['entity_name'])
            usage_data_map[f['entity_name']] = analyzer.analyze_role_usage(f['entity_name'])
    console.print(f"[green]✓ CloudTrail analysis complete[/green]\n")

    console.print("[3/5] Analyzing temporal access patterns...")
    temporal_analyzer = TemporalAccessAnalyzer()
    temporal_payload_map = {}
    for role_name in seen_roles:
        timestamps = analyzer.get_action_timestamps(role_name)
        if not timestamps:
            continue
        temporal_result = temporal_analyzer.analyze(timestamps)
        temporal_payload_map[role_name] = temporal_analyzer.build_ai_payload(temporal_result)
    console.print(f"[green]✓ Temporal analysis complete[/green]\n")

    console.print("[4/5] Risk scoring...")
    scorer = RiskScorer()
    findings = scorer.score_multiple_policies(findings, usage_data_map)
    for f in findings:
        console.print(f"  → {f['entity_name']} — {f['finding_type']}: [bold]{f['severity']}[/bold] (score: {f['score']:.2f}, method: {f.get('method', '?')})")
    console.print(f"[green]✓ Risk scoring complete[/green]\n")

    console.print("[5/5] Generating AI-powered least-privilege fixes...")
    with console.status("[bold blue]Calling AI model — this can take a few minutes per policy...", spinner="dots"):
        results = generate_for_findings(findings, usage_data_map, temporal_payload_map)
    console.print(f"[green]✓ Generation complete[/green]\n")

    # Display results
    for r in results:
        rec = r['ai_recommendation']
        console.print(f"\n[bold cyan]{r['entity_name']}[/bold cyan] — {r['finding_type']} [{r.get('severity', '?')}]")
        if rec.get('skipped'):
            console.print(f"[yellow]⚠ Skipped: {rec['explanation']}[/yellow]")
        elif rec['success']:
            console.print(f"[green]✓ Fix generated (confidence: {rec['confidence']})[/green]")
            console.print(f"  Explanation: {rec['explanation']}")
            console.print(f"  Removed actions: {', '.join(rec['removed_actions']) if rec['removed_actions'] else 'none listed'}")
        else:
            console.print(f"[red]✗ Generation failed: {rec['explanation']}[/red]")

    with open('fixes_report.json', 'w') as fh:
        json.dump(results, fh, indent=2, default=str)
    console.print(f"\n[bold]📁 Full report with generated policies saved to fixes_report.json[/bold]")
@cli.command()
@click.option('--profile', default='default', help='AWS profile')
@click.option('--region', default='eu-central-1', help='AWS region')
@click.option('--threshold-days', default=90, help='Days of inactivity before flagging as orphaned')
def orphaned(profile, region, threshold_days):
    """Detect orphaned IAM roles/users with no recent activity"""
    from src.orphaned_detector import OrphanedIdentityDetector

    console.print("[bold blue]🔍 Scanning for orphaned identities...[/bold blue]\n")
    detector = OrphanedIdentityDetector(profile=profile, region=region, threshold_days=threshold_days)
    orphaned_list = detector.scan_all()

    if not orphaned_list:
        console.print(f"[bold green]✓ No orphaned identities found (threshold: {threshold_days} days)[/bold green]")
        return

    console.print(f"[bold red]⚠ Found {len(orphaned_list)} orphaned identity(ies)[/bold red]\n")

    table = Table(title="Orphaned Identities", show_header=True, header_style="bold", expand=True)
    table.add_column("Entity", style="cyan", overflow="fold")
    table.add_column("Type", style="magenta", width=8)
    table.add_column("Status", style="red", width=14)
    table.add_column("Days Inactive", style="yellow", width=14)
    table.add_column("Recommendation", style="green", overflow="fold")

    for o in orphaned_list:
        table.add_row(
            o['entity_name'], o['entity_type'].upper(), o['status'],
            str(o['days_inactive']) if o['days_inactive'] is not None else "N/A",
            o['recommendation']
        )

    console.print(table)
    with open('orphaned_report.json', 'w') as fh:
        json.dump(orphaned_list, fh, indent=2, default=str)
    console.print("\n[bold]📁 Full report saved to orphaned_report.json[/bold]")


@cli.command()
@click.option('--profile', default='default', help='AWS profile')
@click.option('--region', default='eu-central-1', help='AWS region')
@click.option('--days', default=30, help='CloudTrail days to analyze')
@click.option('--role', default=None, help='Specific role name (default: first over-privileged role found)')
@click.option('--use-mock/--use-aws', default=True, help='Use mock data or real AWS (for role auto-selection)')
def temporal(profile, region, days, role, use_mock):
    """Analyze WHEN a role's permissions are actually used"""
    from src.temporal_analyzer import TemporalAccessAnalyzer

    console.print("[bold blue]🔍 Analyzing temporal access patterns...[/bold blue]\n")

    target_role = role
    if not target_role:
        findings = scan_all(use_mock=use_mock)
        role_names = sorted({f['entity_name'] for f in findings if f['entity_type'] == 'role'})
        if not role_names:
            console.print("[bold green]No over-privileged roles found — nothing to analyze.[/bold green]")
            return
        target_role = role_names[0]

    console.print(f"Target role: [cyan]{target_role}[/cyan]\n")

    analyzer = CloudTrailAnalyzer(profile=profile, region=region, days=days)
    events_by_role = analyzer._get_events_for_multiple_roles([target_role])
    matched_events = events_by_role.get(target_role, [])
    timestamps = [
        {"action": p["action"], "event_time": p["event_time"]}
        for p in (analyzer._process_event_once(e) for e in matched_events)
        if p["action"] and p["event_time"]
    ]

    if not timestamps:
        console.print("[yellow]No CloudTrail activity found for this role in the given window.[/yellow]")
        return

    temporal_analyzer = TemporalAccessAnalyzer()
    result = temporal_analyzer.analyze(timestamps)
    notes = temporal_analyzer.build_insight_notes(result)

    table = Table(title=f"Temporal Access Patterns — {target_role}", show_header=True, header_style="bold", expand=True)
    table.add_column("Action", style="cyan", overflow="fold")
    table.add_column("Count", style="yellow", width=7)
    table.add_column("Hours Used", style="green", overflow="fold")
    table.add_column("Business Hours Only", style="magenta", width=18)
    table.add_column("Rarely Used", style="red", width=12)

    for action, info in result['per_action'].items():
        table.add_row(
            action, str(info['count']),
            ', '.join(str(h) for h in info['hours_used']),
            "Yes" if info['business_hours_only'] else "No",
            "Yes" if info['is_rarely_used'] else "No"
        )

    console.print(table)
    if notes:
        console.print("\n[bold]Insights:[/bold]")
        for note in notes:
            console.print(f"  • {note}")

    with open('temporal_report.json', 'w') as fh:
        json.dump(result, fh, indent=2, default=str)
    console.print("\n[bold]📁 Full report saved to temporal_report.json[/bold]")


if __name__ == '__main__':
    cli()