from rich.console import Console
from rich.table import Table
from rich.text import Text
from typing import List
from ..normalize.schema import LogEvent
from ..detect.rules import Detection

console = Console()

def print_event(event: LogEvent):
    """
    Print a single event row.
    """
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    # Color code based on some heuristics or event type
    style = "white"
    if "error" in event.message.lower() or "failed" in event.message.lower():
        style = "red"
    elif "warn" in event.message.lower():
        style = "yellow"
        
    console.print(f"[{style}]{timestamp} | {event.host} | {event.event_type} | {event.message}[/{style}]")

def print_detection_alert(detection: Detection):
    """
    Print a security alert.
    """
    console.print()
    console.print(f"[bold red]🚨 ALERT: {detection.rule_name} ({detection.severity})[/bold red]")
    if detection.tags:
         console.print(f"   [yellow]Tags:[/yellow] {', '.join(detection.tags)}")
    console.print(f"   [red]Event:[/red] {detection.event.message}")
    console.print(f"   [dim]Desc:  {detection.description}[/dim]")
    console.print()

def print_events_table(events: List[LogEvent]):
    """
    Print a batch of events as a table.
    """
    table = Table(title="Log Events Snippet")
    table.add_column("Timestamp", style="cyan", no_wrap=True)
    table.add_column("Host", style="magenta")
    table.add_column("Type", style="green")
    table.add_column("Message")

    for e in events:
        table.add_row(
            e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            e.host,
            e.event_type,
            e.message
        )

    console.print(table)
