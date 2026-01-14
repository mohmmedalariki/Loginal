from typing import Iterable
import csv
import json
from ..normalize.schema import LogEvent

def write_csv(events: Iterable[LogEvent], path: str):
    """
    Write events to a CSV file.
    """
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "host", "event_type", "message", "source"])
        for event in events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.host,
                event.event_type,
                event.message,
                event.source
            ])

def write_json(events: Iterable[LogEvent], path: str):
    """
    Write events to a JSON Lines file.
    """
    with open(path, 'w', encoding='utf-8') as f:
        for event in events:
            f.write(event.to_json() + "\n")

def write_html(events: Iterable[LogEvent], path: str):
    """
    Write a simple HTML report.
    """
    # Buffer events to simple list for MVP report (careful with memory)
    # limit to 1000 for safety in prototype
    sample = []
    count = 0
    for e in events:
        count += 1
        if len(sample) < 1000:
            sample.append(e)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>LogSec Report</title>
        <style>
            body {{ font-family: sans-serif; margin: 2rem; background: #f4f4f4; }}
            table {{ border-collapse: collapse; width: 100%; background: white; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #333; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h1>LogSec Analysis Report</h1>
        <p>Total Events Processed: {count}</p>
        <p>Showing first {len(sample)} events</p>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Host</th>
                    <th>Type</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
    """
    
    for e in sample:
        html_content += f"""
            <tr>
                <td>{e.timestamp}</td>
                <td>{e.host}</td>
                <td>{e.event_type}</td>
                <td>{e.message}</td>
            </tr>
        """
        
    html_content += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_content)
