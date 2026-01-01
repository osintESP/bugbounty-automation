#!/usr/bin/env python3
"""
Simple test of the exploit framework - Tests individual components
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'src'))

from modules.recon.fingerprint import Fingerprinter
from modules.recon.path_discovery import PathDiscovery
from modules.scan.cve_matcher import CVEMatcher
from modules.exploit.exploit_db import ExploitDB
from rich.console import Console
from rich.table import Table

console = Console()

def test_fingerprinting():
    """Test fingerprinting module"""
    console.print("\n[bold cyan]Testing Fingerprinting Module[/bold cyan]")
    console.print("=" * 60)
    
    target = "http://vulnerable-app:5000"
    fp = Fingerprinter(target)
    result = fp.run()
    
    table = Table(title="Fingerprint Results")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Server", result.get('server', 'Unknown'))
    table.add_row("Language", result.get('language', 'Unknown'))
    table.add_row("Framework", result.get('framework', 'Unknown'))
    table.add_row("Confidence", f"{result.get('confidence', 0):.1%}")
    
    console.print(table)
    return result

def test_path_discovery():
    """Test path discovery module"""
    console.print("\n[bold cyan]Testing Path Discovery Module[/bold cyan]")
    console.print("=" * 60)
    
    target = "http://vulnerable-app:5000"
    pd = PathDiscovery(target, threads=5)
    paths = pd.run(technologies=['Apache', 'PHP'])
    
    console.print(f"[green]✓ Discovered {len(paths)} paths[/green]")
    
    if paths:
        console.print("\nTop 10 paths:")
        for path in paths[:10]:
            console.print(f"  • {path['path']} [{path['status']}] - {path.get('reason', '')}")
    
    return paths

def test_exploit_db():
    """Test exploit database"""
    console.print("\n[bold cyan]Testing Exploit Database[/bold cyan]")
    console.print("=" * 60)
    
    db = ExploitDB()
    summary = db.export_exploit_summary()
    
    table = Table(title="Exploit Database Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    
    table.add_row("Total Exploits", str(summary['total_exploits']))
    table.add_row("CVE-Specific", str(summary['cve_specific']))
    table.add_row("Generic", str(summary['generic']))
    table.add_row("Path Traversal", str(summary['by_type']['path_traversal']))
    table.add_row("RCE", str(summary['by_type']['rce']))
    table.add_row("Info Disclosure", str(summary['by_type']['information_disclosure']))
    
    console.print(table)
    
    console.print("\n[bold]Available Exploits:[/bold]")
    for exploit_id in summary['exploits']:
        exploit = db.get_exploit(exploit_id)
        console.print(f"  • {exploit_id}: {exploit.get('name')}")
    
    return db

def test_generic_exploits():
    """Test generic exploits against target"""
    console.print("\n[bold cyan]Testing Generic Exploits[/bold cyan]")
    console.print("=" * 60)
    
    from modules.exploit.exploit_engine import ExploitEngine
    
    target = "http://vulnerable-app:5000"
    db = ExploitDB()
    engine = ExploitEngine(target, dry_run=False)
    
    # Test exposed .env
    env_exploit = db.get_exploit('EXPOSED_ENV')
    console.print(f"\n[yellow]Testing: {env_exploit['name']}[/yellow]")
    result = engine.execute_exploit(env_exploit)
    
    if result['success']:
        console.print(f"[green]✓ SUCCESS![/green]")
        for payload in result['successful_payloads']:
            console.print(f"  • {payload['name']}: {payload.get('successful_url')}")
    else:
        console.print(f"[red]✗ Failed[/red]")
    
    # Test exposed .git
    git_exploit = db.get_exploit('EXPOSED_GIT')
    console.print(f"\n[yellow]Testing: {git_exploit['name']}[/yellow]")
    result = engine.execute_exploit(git_exploit)
    
    if result['success']:
        console.print(f"[green]✓ SUCCESS![/green]")
        for payload in result['successful_payloads']:
            console.print(f"  • {payload['name']}: {payload.get('successful_url')}")
    else:
        console.print(f"[red]✗ Failed[/red]")
    
    return engine.export_results()

def main():
    console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
    console.print("[bold magenta]🧪 EXPLOIT FRAMEWORK - COMPONENT TESTS[/bold magenta]")
    console.print("[bold magenta]" + "=" * 70 + "[/bold magenta]")
    
    # Test each component
    fingerprint = test_fingerprinting()
    paths = test_path_discovery()
    exploit_db = test_exploit_db()
    exploit_results = test_generic_exploits()
    
    # Final summary
    console.print("\n" + "=" * 70)
    console.print("[bold green]✅ ALL TESTS COMPLETED[/bold green]")
    console.print("=" * 70)
    
    console.print(f"\n[cyan]Fingerprinting:[/cyan] ✓ Detected {fingerprint.get('confidence', 0):.0%} confidence")
    console.print(f"[cyan]Path Discovery:[/cyan] ✓ Found {len(paths)} paths")
    console.print(f"[cyan]Exploit Database:[/cyan] ✓ {exploit_db.export_exploit_summary()['total_exploits']} exploits loaded")
    console.print(f"[cyan]Exploitation:[/cyan] ✓ {exploit_results.get('successful', 0)}/{exploit_results.get('total_exploits', 0)} successful")
    
    console.print("\n[bold green]🎉 Framework is operational![/bold green]\n")

if __name__ == "__main__":
    main()
