from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class GUILogEvent:
    """
    Represents a normalized log event for the GUI.

    Attributes:
        id: Unique identifier for the event (e.g., hash or sequence).
        timestamp: Time the event occurred.
        host: Originating hostname.
        source: Log source (e.g., 'auth.log', 'cloudtrail').
        event_type: Normalized event type (e.g., 'SSH Failed Login').
        user: Associated user if any.
        message: Human-readable description.
        severity: Criticality level (low, medium, high, critical).
        metadata: Additional raw fields.
    """
    id: str
    timestamp: datetime
    host: str
    source: str
    event_type: str
    message: str
    severity: str = "low"
    user: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts the event to a dictionary for AG Grid consumption."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "source": self.source,
            "event_type": self.event_type,
            "user": self.user or "-",
            "message": self.message,
            "severity": self.severity,
        }
