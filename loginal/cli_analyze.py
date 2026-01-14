from .analyze.url import URLAnalyzer
from rich.console import Console
from rich.panel import Panel
from rich.json import JSON

console = Console()

def run_analyze_url(target: str, field: str = None):
    """
    Run URL analysis logic for CLI.
    """
    analyzer = URLAnalyzer()
    
    # Heuristic: is target a file?
    try:
        with open(target, 'r') as f:
            # Analyze line by line (simple version)
            # Logic: extract everything that looks like a URL
            # For now, MVP assumes target is a single URL string directly
             pass
    except FileNotFoundError:
        pass

    # Treat target as URL string
    console.print(f"[bold blue]Analyzing URL:[/bold blue] {target}")
    result = analyzer.analyze(target)
    
    # Pretty print
    console.print(JSON.from_data(result))
    
    if "decoded_payloads" in result:
        console.print("\n[bold green]🔓 Decoded Payloads:[/bold green]")
        for d in result["decoded_payloads"]:
            console.print(f"   [yellow]{d['key']}[/yellow]: {d['value']}")
            
    if "extracted_iocs" in result:
        console.print("\n[bold red]💀 IOCs Found:[/bold red]")
        for ioc in result["extracted_iocs"]:
            console.print(f"   - {ioc['type']}: {ioc['value']}")
