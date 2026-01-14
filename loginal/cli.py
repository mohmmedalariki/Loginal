import argparse
import sys
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Loginal - Security Log Analysis Framework")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest and normalize logs")
    ingest_parser.add_argument("source", help="Path to log file or directory")
    ingest_parser.add_argument("--format", choices=["text", "json", "syslog"], default="text", help="Input format")
    ingest_parser.add_argument("--query", "-q", help="Filter query (e.g. 'user=root' or 'failed')")
    ingest_parser.add_argument("--detect", "-d", action="store_true", help="Enable detection rules")
    ingest_parser.add_argument("--export-csv", help="Export path for CSV")
    ingest_parser.add_argument("--export-html", help="Export path for HTML")
    ingest_parser.add_argument("--anomaly", action="store_true", help="Run statistical anomaly detection")
    ingest_parser.add_argument("--correlate", action="store_true", help="Run correlation engine on detections")
    ingest_parser.add_argument("--rules-dir", help="Path to Sigma rules directory")

    # SQL command
    sql_parser = subparsers.add_parser("sql", help="Run SQL queries on logs")
    sql_parser.add_argument("source", help="Log source")
    sql_parser.add_argument("query", help="SQL Query (Table name is 'logs')")
    sql_parser.add_argument("--format", choices=["text", "json", "evtx", "syslog"], default="text", help="Input format")

    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze artifacts (URL, etc.)")
    analyze_sub = analyze_parser.add_subparsers(dest="analyze_command", help="Analysis type")
    
    url_parser = analyze_sub.add_parser("url", help="Analyze URL string")
    url_parser.add_argument("target", help="URL or string to analyze")

    # GUI command
    gui_parser = subparsers.add_parser("gui", help="Launch the Desktop GUI")

    args = parser.parse_args()

    if args.command is None:
        console.print(Panel.fit("[bold red]Loginal[/bold red]\n\nA modular security log analysis framework.\nUse [bold]--help[/bold] to see available commands.", title="Welcome"))
        sys.exit(0)
        
    if args.command == "analyze":
        if args.analyze_command == "url":
            from .cli_analyze import run_analyze_url
            run_analyze_url(args.target)
        else:
            analyze_parser.print_help()

    if args.command == "gui":
        import subprocess
        import os
        import sys
        
        # Get path to dashboard.py relative to this cli file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dashboard_path = os.path.join(base_dir, "gui", "dashboard.py")
        
        console.print(f"[green]Launching Loginal Dashboard...[/green]")
        console.print(f"[dim]Running: streamlit run {dashboard_path}[/dim]")
        
        try:
            # Use sys.executable -m streamlit to avoid PATH issues
            subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path], check=True)
        except subprocess.CalledProcessError as e:
             console.print(f"[bold red]Error launching dashboard:[/bold red] {e}")
        except KeyboardInterrupt:
             console.print("\n[yellow]Dashboard stopped.[/yellow]")

    if args.command == "ingest":
        from .ingest.text import TextIngester
        from .ingest.json_log import JSONIngester
        from .ingest.evtx import EVTXIngester
        from .normalize.converters import normalize_event
        from .query.engine import QueryEngine
        from .detect.rules import DetectionEngine
        from .visualize.tui import print_event, print_detection_alert
        from .export.writers import write_csv, write_html
        
        # Phase 4 Imports
        from .detect.sigma_loader import SigmaLoader
        from .detect.correlation import CorrelationEngine, CorrelatedAlert

        console.print(f"[green]Ingesting logs from:[/green] {args.source}")
        
        # 1. Select Ingester
        if args.format == "json":
            ingester = JSONIngester()
        elif args.format == "evtx":
            ingester = EVTXIngester()
        else:
            ingester = TextIngester()  # Default and 'syslog'
            
        try:
            raw_stream = ingester.ingest(args.source)
        except Exception as e:
            console.print(f"[bold red]Error opening source:[/bold red] {e}")
            return

        # 2. Setup Engines
        query_engine = QueryEngine()
        detection_engine = DetectionEngine()
        detection_engine.load_defaults()
        
        # Load external Sigma rules if any (hardcoded path or via arg in future)
        if args.rules_dir:
             sigma_loader = SigmaLoader()
             extra_rules = sigma_loader.load_from_directory(args.rules_dir)
             detection_engine.rules.extend(extra_rules)
             console.print(f"[blue]Loaded {len(extra_rules)} Sigma rules from {args.rules_dir}[/blue]")

        # 3. Stream Pipeline
        count = 0
        detections_count = 0
        
        all_detections = []
        events_for_export = []
        capture_for_export = bool(args.export_csv or args.export_html or args.anomaly or args.correlate)

        for raw_doc in raw_stream:
            # Normalize
            fmt = "evtx" if args.format == "evtx" else args.format
            event = normalize_event(raw_doc, fmt)
            
            # Query Filter
            pass_filter = True
            if args.query:
                if not list(query_engine.filter([event], args.query)):
                    pass_filter = False
            
            if not pass_filter:
                continue

            # Detect
            if args.detect:
                for alert in detection_engine.analyze([event]):
                    print_detection_alert(alert)
                    detections_count += 1
                    if args.correlate:
                         all_detections.append(alert)

            # Visualize
            print_event(event)
            count += 1
            
            if capture_for_export:
                events_for_export.append(event)

        # 4. Export
        if args.export_csv:
            write_csv(events_for_export, args.export_csv)
            console.print(f"[blue]Exported CSV to {args.export_csv}[/blue]")
        
        if args.export_html:
            write_html(events_for_export, args.export_html)
            console.print(f"[blue]Exported HTML to {args.export_html}[/blue]")

        console.print(f"\n[bold]Processed {count} events. Found {detections_count} alerts.[/bold]")
        
        # 4b. Correlation Engine usage
        if args.detect and args.correlate and all_detections:
             console.print("\n[bold magenta]Running Correlation Engine...[/bold magenta]")
             correlator = CorrelationEngine()
             corr_alerts = 0
             for c_alert in correlator.correlate(all_detections):
                 console.print(Panel(f"[bold red]{c_alert.title}[/bold red]\nSource count: {len(c_alert.sources)}", title="🔗 Correlated Incident", border_style="red"))
                 corr_alerts += 1
             if corr_alerts == 0:
                 console.print("[dim]No correlated incidents found.[/dim]")
        
        # 5. Anomaly Detection (Batch)
        if args.anomaly:
            from .detect.anomaly import frequency_anomaly
            console.print("\n[bold magenta]Analysis: Checking for frequency anomalies...[/bold magenta]")
            
            target_events = events_for_export
            if not target_events and not capture_for_export:
                 console.print("[yellow]Warning: Anomaly detection requires buffering. Next time use --anomaly with buffering enabled (implicitly done now).[/yellow]")
            
            if target_events:
                # Analyze common fields
                for field in ["event_type", "host", "user"]:
                    for anomaly in frequency_anomaly(target_events, field=field):
                        console.print(f"[bold red]⚡ ANOMALY ({anomaly['field']}):[/bold red] Value '{anomaly['value']}' seen {anomaly['count']} times (Avg: {anomaly['average']:.1f})")
            else:
                 console.print("[dim]No events buffered for anomaly detection.[/dim]")

    elif args.command == "sql":
        from .ingest.text import TextIngester
        from .ingest.json_log import JSONIngester
        from .ingest.evtx import EVTXIngester
        from .normalize.converters import normalize_event
        from .query.sql import SQLEngine
        from rich.table import Table
        
        console.print(f"[green]Loading logs into SQL Engine...[/green]")
        
        # Ingest all first (Batch mode)
        # TODO: Support multiple files or globbing in future
        if args.format == "json":
            ingester = JSONIngester()
        elif args.format == "evtx":
            ingester = EVTXIngester()
        else:
            ingester = TextIngester()

        events = []
        try:
            for raw in ingester.ingest(args.source):
                events.append(normalize_event(raw, args.format))
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
            return

        engine = SQLEngine()
        engine.load_events(events)
        
        console.print(f"[bold]Executing SQL:[/bold] {args.query}")
        try:
            # simple print of results
            results = engine.execute(args.query)
            
            table = Table(title="SQL Results")
            if results:
                # We don't know column names easily from fetchall without description
                # DuckDB cursor description hack or just index
                for i in range(len(results[0])):
                    table.add_column(f"Col {i}")
                
                for row in results:
                    table.add_row(*[str(x) for x in row])
                
                console.print(table)
            else:
                console.print("[yellow]No results found.[/yellow]")
                
        except Exception as e:
            console.print(f"[bold red]SQL Error:[/bold red] {e}")

if __name__ == "__main__":
    main()
