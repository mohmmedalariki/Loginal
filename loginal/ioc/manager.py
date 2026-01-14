from typing import List, Dict, Optional
import os
from .model import EnrichmentResult
from .cache import IOCCache
from .providers.virustotal import VirusTotalProvider

class IOCManager:
    """Orchestrates Enrichment."""
    
    # Hardcoded key as requested
class IOCManager:
    """Orchestrates Enrichment."""
    
    def __init__(self, vt_api_key: str = None):
        self.cache = IOCCache()
        self.providers = []
        
        # Use provided key
        if vt_api_key:
            self.providers.append(VirusTotalProvider(vt_api_key))
            
    def enrich(self, ioc: str, kind: str, force=False) -> EnrichmentResult:
        # 1. Check Cache
        if not force:
            cached = self.cache.get(ioc)
            if cached:
                return cached
        
        # 2. Mock Mode (If no keys)
        if not self.providers:
            return self._mock_enrich(ioc, kind)
            
        # 3. Call Providers (Just VT for now)
        # In future, aggregate multiple results
        provider = self.providers[0]
        raw = provider.enrich(ioc, kind)
        result = provider.normalize(raw, ioc, kind)
        
        # 4. Save
        self.cache.set(result)
        return result

    def _mock_enrich(self, ioc: str, kind: str) -> EnrichmentResult:
        """Demo data if no API keys."""
        import random
        is_bad = random.random() > 0.7
        return EnrichmentResult(
            ioc=ioc,
            kind=kind,
            reputation="malicious" if is_bad else "clean",
            confidence=0.9 if is_bad else 0.0,
            malicious_votes=12 if is_bad else 0,
            sources=["demo_mock"],
            details={"note": "This is simulated data. Add API Key to config for real data."}
        )
