#!/usr/bin/env python3
"""
Bug Bounty Automation Tool - Main Entry Point
"""
import click
from rich.console import Console
from rich.table import Table
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from utils.logger import setup_logger

console = Console()
logger = None


@click.group()
@click.option('--config', '-c', default='config.yaml', help='Path to configuration file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(config, verbose):
    """Bug Bounty Automation Tool - Automate security testing and reconnaissance"""
    global logger
    
    # Setup logger
    log_level = 'DEBUG' if verbose else 'INFO'
    logger = setup_logger(level=log_level)
    
    # Load configuration
    try:
        Config.load(config)
        logger.info(f"Configuration loaded from {config}")
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--output', '-o', help='Output directory for results')
def recon(target, output):
    """Run reconnaissance on target domain"""
    console.print(f"[bold cyan]Starting reconnaissance on {target}[/bold cyan]")
    
    from modules.recon.subdomain_enum import SubdomainEnumerator
    from modules.recon.port_scan import PortScanner
    from modules.recon.tech_detect import TechDetector
    from modules.recon.crawler import WebCrawler
    
    # Subdomain enumeration
    console.print("\n[yellow]1. Enumerating subdomains...[/yellow]")
    enum = SubdomainEnumerator(target)
    subdomains = enum.run()
    console.print(f"[green]Found {len(subdomains)} subdomains[/green]")
    
    # Port scanning
    console.print("\n[yellow]2. Scanning ports...[/yellow]")
    scanner = PortScanner(target)
    ports = scanner.run()
    console.print(f"[green]Found {len(ports)} open ports[/green]")
    
    # Technology detection
    console.print("\n[yellow]3. Detecting technologies...[/yellow]")
    detector = TechDetector(target)
    techs = detector.run()
    console.print(f"[green]Detected {len(techs)} technologies[/green]")
    
    # Web crawling
    console.print("\n[yellow]4. Crawling URLs...[/yellow]")
    crawler = WebCrawler(target)
    urls = crawler.run()
    console.print(f"[green]Found {len(urls)} URLs[/green]")
    
    console.print("\n[bold green]✓ Reconnaissance completed![/bold green]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--severity', '-s', default='medium', help='Minimum severity level')
def scan(target, severity):
    """Run vulnerability scans on target"""
    console.print(f"[bold cyan]Starting vulnerability scan on {target}[/bold cyan]")
    
    from modules.scan.nuclei_scanner import NucleiScanner
    from modules.scan.headers import HeaderAnalyzer
    from modules.scan.secrets import SecretScanner
    
    # Nuclei scanning
    console.print("\n[yellow]1. Running Nuclei scans...[/yellow]")
    nuclei = NucleiScanner(target)
    vulns = nuclei.run(severity=severity)
    console.print(f"[green]Found {len(vulns)} vulnerabilities[/green]")
    
    # Header analysis
    console.print("\n[yellow]2. Analyzing security headers...[/yellow]")
    headers = HeaderAnalyzer(target)
    issues = headers.run()
    console.print(f"[green]Found {len(issues)} header issues[/green]")
    
    # Secret scanning
    console.print("\n[yellow]3. Scanning for secrets...[/yellow]")
    secrets = SecretScanner(target)
    found = secrets.run()
    console.print(f"[green]Found {len(found)} potential secrets[/green]")
    
    console.print("\n[bold green]✓ Vulnerability scan completed![/bold green]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
def full(target):
    """Run full pipeline (recon + scan)"""
    console.print(f"[bold magenta]Starting full pipeline on {target}[/bold magenta]")
    
    # Run reconnaissance
    from click.testing import CliRunner
    runner = CliRunner()
    
    console.print("\n[bold]Phase 1: Reconnaissance[/bold]")
    runner.invoke(recon, ['--target', target])
    
    console.print("\n[bold]Phase 2: Vulnerability Scanning[/bold]")
    runner.invoke(scan, ['--target', target])
    
    console.print("\n[bold green]✓ Full pipeline completed![/bold green]")


@cli.command()
@click.option('--target', '-t', required=True, help='Target domain')
@click.option('--format', '-f', default='html', type=click.Choice(['json', 'html', 'pdf', 'markdown']))
@click.option('--output', '-o', help='Output file path')
def report(target, format, output):
    """Generate report for target"""
    console.print(f"[bold cyan]Generating {format.upper()} report for {target}[/bold cyan]")
    
    from modules.report.generator import ReportGenerator
    
    generator = ReportGenerator(target)
    report_path = generator.generate(format=format, output=output)
    
    console.print(f"[bold green]✓ Report generated: {report_path}[/bold green]")


@cli.command()
@click.option('--target', '-t', help='Target domain (optional, uses config if not specified)')
@click.option('--interval', '-i', default='24h', help='Scan interval (e.g., 24h, 12h, 1d)')
def monitor(target, interval):
    """Start continuous monitoring"""
    console.print(f"[bold cyan]Starting continuous monitoring (interval: {interval})[/bold cyan]")
    
    from modules.scheduler import Scheduler
    
    scheduler = Scheduler()
    scheduler.start(target=target, interval=interval)


@cli.command()
@click.option('--host', default='0.0.0.0', help='API host')
@click.option('--port', default=8000, help='API port')
def api(host, port):
    """Start API server and dashboard"""
    console.print(f"[bold cyan]Starting API server on {host}:{port}[/bold cyan]")
    
    from modules.report.dashboard import app
    import uvicorn
    
    uvicorn.run(app, host=host, port=port)


@cli.command()
def list_targets():
    """List configured targets"""
    config = Config.get()
    
    table = Table(title="Configured Targets")
    table.add_column("Domain", style="cyan")
    table.add_column("Scope", style="green")
    table.add_column("Exclude", style="red")
    table.add_column("Enabled", style="yellow")
    
    for target in config.get('targets', []):
        table.add_row(
            target.get('domain', 'N/A'),
            ', '.join(target.get('scope', [])),
            ', '.join(target.get('exclude', [])),
            '✓' if target.get('enabled', False) else '✗'
        )
    
    console.print(table)


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--auto', is_flag=True, help='Automatically exploit all found vulnerabilities')
@click.option('--dry-run', is_flag=True, help='Show what would be exploited without executing')
@click.option('--cve', help='Target specific CVE (e.g., CVE-2021-41773)')
@click.option('--severity', '-s', multiple=True, default=['critical', 'high'], help='CVE severity filter')
def exploit(target, auto, dry_run, cve, severity):
    """Run automated exploitation pipeline: Recon → Detection → Exploitation"""
    console.print(f"[bold magenta]🎯 Exploit Pipeline for {target}[/bold magenta]")
    
    if dry_run:
        console.print("[yellow]⚠️  DRY RUN MODE - No actual exploits will be executed[/yellow]")
    elif auto:
        console.print("[red]⚠️  AUTO MODE - Will automatically exploit vulnerabilities[/red]")
    
    from modules.exploit.orchestrator import ExploitOrchestrator
    import json
    
    # Create orchestrator
    config = Config.get()
    orchestrator = ExploitOrchestrator(target, config=config)
    
    # Run full pipeline
    results = orchestrator.run_full_pipeline(auto_exploit=auto, dry_run=dry_run)
    
    # Display summary
    console.print("\n" + "=" * 60)
    console.print("[bold]📊 EXECUTIVE SUMMARY[/bold]")
    console.print("=" * 60)
    
    summary = results.get('summary', {})
    
    # Create summary table
    table = Table(show_header=False, box=None)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("🎯 Target", summary.get('target', 'N/A'))
    table.add_row("🔍 Technologies Detected", str(summary.get('technologies_detected', 0)))
    table.add_row("📁 Paths Discovered", str(summary.get('paths_discovered', 0)))
    table.add_row("🔓 CVEs Found", str(summary.get('cves_found', 0)))
    table.add_row("💥 Exploitable CVEs", str(summary.get('exploitable_cves', 0)))
    table.add_row("✅ Successful Exploits", str(summary.get('successful_exploits', 0)))
    
    risk_colors = {
        'critical': 'red',
        'high': 'orange1',
        'medium': 'yellow',
        'low': 'green'
    }
    risk_level = summary.get('risk_level', 'low')
    table.add_row("⚠️  Risk Level", f"[{risk_colors.get(risk_level, 'white')}]{risk_level.upper()}[/{risk_colors.get(risk_level, 'white')}]")
    
    console.print(table)
    
    # Save results
    output_dir = Path('./reports')
    output_dir.mkdir(exist_ok=True)
    
    output_file = output_dir / f"exploit_{target.replace('://', '_').replace('/', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    console.print(f"\n[green]✓ Full results saved to: {output_file}[/green]")
    
    # Show next steps
    if not auto and not dry_run and summary.get('exploitable_cves', 0) > 0:
        console.print("\n[yellow]💡 Next steps:[/yellow]")
        console.print("  • Run with --dry-run to see what would be exploited")
        console.print("  • Run with --auto to automatically exploit vulnerabilities")


@cli.command()
def version():
    """Show version information"""
    console.print("[bold]Bug Bounty Automation Tool[/bold]")
    console.print("Version: 1.0.0")
    console.print("Author: Security Team")


if __name__ == '__main__':
    cli()
