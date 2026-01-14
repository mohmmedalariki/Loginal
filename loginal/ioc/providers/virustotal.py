import requests
import time
from typing import Dict
from .base import IOCProvider
from ..model import EnrichmentResult

class VirusTotalProvider(IOCProvider):
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def enrich(self, ioc: str, kind: str) -> Dict:
        headers = {"x-apikey": self.api_key}
        endpoint = ""
        
        if kind == "ip":
            endpoint = f"/ip_addresses/{ioc}"
        elif kind == "domain":
            endpoint = f"/domains/{ioc}"
        elif kind == "hash":
            endpoint = f"/files/{ioc}"
        else:
            return {"error": "Unsupported kind"}
            
        try:
            resp = requests.get(f"{self.BASE_URL}{endpoint}", headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"not_found": True}
            elif resp.status_code == 429:
                return {"error": "Rate limit exceeded"}
            else:
                return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def normalize(self, raw_data: Dict, ioc: str, kind: str) -> EnrichmentResult:
        if "error" in raw_data:
            return EnrichmentResult(ioc, kind, "unknown", 0.0, 0, ["virustotal"], details={"error": raw_data["error"]})
        
        if raw_data.get("not_found"):
             return EnrichmentResult(ioc, kind, "not_found", 0.0, 0, ["virustotal"], details={"status": "Not found in VT"})

        # Parse Analysis
        try:
            attrs = raw_data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            
            score = 0.0
            reputation = "benign"
            
            if malicious > 0 or suspicious > 0:
                score = (malicious * 1.0 + suspicious * 0.5) / (total if total > 0 else 1)
                score = min(score * 5, 1.0) # Boost score: 20% detection = 100% confidence
            
            if malicious >= 2:
                reputation = "malicious"
            elif malicious == 1 or suspicious >= 2:
                reputation = "suspicious"
            elif total > 0:
                reputation = "clean"
                
            return EnrichmentResult(
                ioc=ioc,
                kind=kind,
                reputation=reputation,
                confidence=round(score, 2),
                malicious_votes=malicious,
                sources=["virustotal"],
                details={
                    "stats": stats,
                    "tags": attrs.get("tags", [])[:5],
                    "link": f"https://www.virustotal.com/gui/{kind.replace('_addresses','')}/{ioc}"
                }
            )
        except Exception as e:
             return EnrichmentResult(ioc, kind, "error", 0.0, 0, ["virustotal"], details={"parse_error": str(e)})
