from dataclasses import dataclass, field
from typing import List, Dict, Optional
import datetime

@dataclass
class EnrichmentResult:
    """Standardized Enrichment Result."""
    ioc: str
    kind: str # ip, domain, url, hash
    reputation: str # malicious, suspicious, benign, unknown
    confidence: float # 0.0 to 1.0
    malicious_votes: int
    sources: List[str]
    cached_at: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    details: Dict = field(default_factory=dict) # Raw provider data
    
    def to_dict(self):
        return {
            "ioc": self.ioc,
            "kind": self.kind,
            "reputation": self.reputation,
            "confidence": self.confidence,
            "malicious_votes": self.malicious_votes,
            "sources": self.sources,
            "cached_at": self.cached_at,
            "details": self.details
        }
