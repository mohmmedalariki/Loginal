from typing import Dict, Any, Optional
from datetime import datetime
import re
from .schema import LogEvent

# Basic regex for syslog (very simplified)
# May 11 10:40:48 scorpio sshd[2050]: Failed password for invalid user...
SYSLOG_REGEX = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)$')

def normalize_syslog(data: Dict[str, Any]) -> LogEvent:
    raw = data.get("raw_text", "")
    match = SYSLOG_REGEX.match(raw)
    
    if match:
        timestamp_str, host, service, message = match.groups()
        # Mock year 2024 for simplicity as syslog often lacks year
        # In a real tool, we'd guess the year or use file mtime
        try:
            timestamp = datetime.strptime(f"2024 {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            timestamp = datetime.now()
            
        return LogEvent(
            timestamp=timestamp,
            source=data.get("source_path", "unknown"),
            source_type="syslog",
            host=host,
            event_type=service,  # Use service name (e.g. sshd) as event type
            message=message,
            original_data=data,
            metadata={"service": service}
        )
    else:
        # Fallback for unparseable lines
        return LogEvent(
            timestamp=datetime.now(),
            source=data.get("source_path", "unknown"),
            source_type="syslog_raw",
            host="unknown",
            event_type="unknown",
            message=raw,
            original_data=data
        )

def normalize_json(data: Dict[str, Any]) -> LogEvent:
    # Try to find common timestamp fields
    ts_str = data.get("timestamp") or data.get("time") or data.get("eventTime")
    timestamp = datetime.now()
    if ts_str:
        try:
            timestamp = datetime.fromisoformat(str(ts_str).replace('Z', '+00:00'))
        except (ValueError, TypeError):
            pass

    message = data.get("message") or data.get("msg") or str(data)
    host = data.get("host") or data.get("hostname") or "unknown"
    event_type = data.get("event_type") or data.get("eventName") or "json_event"
    
    return LogEvent(
        timestamp=timestamp,
        source=data.get("_metadata", {}).get("source_path", "json"),
        source_type="json",
        host=host,
        event_type=event_type,
        message=message,
        user=data.get("user") or data.get("username"),
        original_data=data
    )

def normalize_event(data: Dict[str, Any], fmt: str) -> LogEvent:
    if fmt == "text" or fmt == "syslog":
        return normalize_syslog(data)
    elif fmt == "json":
        return normalize_json(data)
    else:
        # Generic fallback
        return LogEvent(
            timestamp=datetime.now(),
            source=data.get("source_path", "unknown"),
            source_type="unknown",
            host="unknown",
            event_type="unknown",
            message=str(data.get("raw_text", data)),
            original_data=data
        )
