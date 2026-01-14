from abc import ABC, abstractmethod
from typing import Dict
from ..model import EnrichmentResult

class IOCProvider(ABC):
    
    def __init__(self, api_key: str):
        self.api_key = api_key

    @abstractmethod
    def enrich(self, ioc: str, kind: str) -> Dict:
        """Return raw data from provider."""
        pass
    
    @abstractmethod
    def normalize(self, raw_data: Dict, ioc: str, kind: str) -> EnrichmentResult:
        """Convert raw data to standard result."""
        pass
