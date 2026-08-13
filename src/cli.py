import json
import click
from rich.console import Console
from rich.table import Table

from src.scanner import scan_all
from src.cloudtrail_analyzer import CloudTrailAnalyzer
from src.risk_scorer import RiskScorer
from src.validator import PolicyValidator

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
@click.option('--use-mock/--use-aws', default=False, help='Use mock data or real AWS')
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

    # Step 3: Risk scoring — adapt to your scanner.py's field names
    console.print("[3/3] Risk scoring...")
    scorer = RiskScorer()

    scored_findings = []
    for f in findings:
        result = scorer.score_policy(
            f['policy_json'],
            entity_type=f['entity_type'],
            is_internet_facing=False
        )
        scored_findings.append({**f, **result})

    scored_findings.sort(key=lambda x: x['score'], reverse=True)
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
@click.option('--use-mock/--use-aws', default=False, help='Use mock data or real AWS')
def fix(profile, region, days, use_mock):
    """Full pipeline: scan → CloudTrail → risk score → AI-generate fixes"""

    from src.ai_generator import generate_for_findings
    from src.scanner import scan_all
    from src.cloudtrail_analyzer import CloudTrailAnalyzer
    from src.risk_scorer import RiskScorer

    console.print("[bold blue]🔍 Full Pipeline: Scan → Analyze → Generate Fixes[/bold blue]\n")

    console.print("[1/4] Scanning IAM policies...")
    findings = scan_all(use_mock=use_mock)
    console.print(f"[green]✓ Found {len(findings)} finding(s)[/green]\n")

    if not findings:
        console.print("[bold green]No over-privileged policies found. Nothing to fix.[/bold green]")
        return

    console.print("[2/4] Analyzing CloudTrail usage...")
    analyzer = CloudTrailAnalyzer(profile=profile, region=region, days=days)
    usage_data_map = {}
    seen_roles = set()
    for f in findings:
        if f['entity_type'] == 'role' and f['entity_name'] not in seen_roles:
            seen_roles.add(f['entity_name'])
            usage_data_map[f['entity_name']] = analyzer.analyze_role_usage(f['entity_name'])
    console.print(f"[green]✓ CloudTrail analysis complete[/green]\n")

    console.print("[3/4] Risk scoring...")
    scorer = RiskScorer()
    for f in findings:
        result = scorer.score_policy(f['policy_json'], entity_type=f['entity_type'])
        f.update(result)
    console.print(f"[green]✓ Risk scoring complete[/green]\n")

    console.print("[4/4] Generating AI-powered least-privilege fixes (this may take a moment)...")
    results = generate_for_findings(findings, usage_data_map)
    console.print(f"[green]✓ Generation complete[/green]\n")

    # Display results
    for r in results:
        rec = r['ai_recommendation']
        console.print(f"\n[bold cyan]{r['entity_name']}[/bold cyan] — {r['finding_type']} [{r.get('severity', '?')}]")

        if rec['success']:
            console.print(f"[green]✓ Fix generated (confidence: {rec['confidence']})[/green]")
            console.print(f"  Explanation: {rec['explanation']}")
            console.print(f"  Removed actions: {', '.join(rec['removed_actions']) if rec['removed_actions'] else 'none listed'}")
        else:
            console.print(f"[red]✗ Generation failed: {rec['explanation']}[/red]")

    with open('fixes_report.json', 'w') as fh:
        json.dump(results, fh, indent=2, default=str)
    console.print(f"\n[bold]📁 Full report with generated policies saved to fixes_report.json[/bold]")
if __name__ == '__main__':
    cli()