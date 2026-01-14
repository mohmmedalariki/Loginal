from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional
import json

@dataclass
class LogEvent:
    """
    Normalized security event representation.
    """
    timestamp: datetime
    source: str              # File path or source identifier
    source_type: str         # e.g., 'syslog', 'json', 'evtx'
    host: str                # Hostname or IP
    event_type: str          # Normalized event type if available
    message: str             # Human-readable message
    user: Optional[str] = None
    original_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON, handling datetime objects."""
        def default(o):
            if isinstance(o, datetime):
                return o.isoformat()
            return str(o)
        return json.dumps(self.__dict__, default=default)
