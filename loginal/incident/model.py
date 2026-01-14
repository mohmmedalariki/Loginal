from dataclasses import dataclass, field
from typing import List, Dict, Optional
import datetime
import uuid

@dataclass
class Provenance:
    """Deterministic Facts about the detection."""
    rule_name: str
    severity: str
    matched_fields: List[str]
    entities: List[str] # IPs, Users, Hosts
    log_samples: List[str] # Top 3 representative logs

@dataclass
class Incident:
    """Core Incident Record."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = "New Incident"
    created_at: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    status: str = "New" # New, Investigating, Closed
    
    provenance: Provenance = None
    
    # AI Analysis Cache
    bulk_summary: Optional[Dict] = None
    expert_analysis: Optional[Dict] = None
    
    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at,
            "status": self.status,
            "provenance": self.provenance.__dict__ if self.provenance else {},
            "bulk_summary": self.bulk_summary,
            "expert_analysis": self.expert_analysis
        }
