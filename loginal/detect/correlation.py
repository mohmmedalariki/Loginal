from typing import List, Dict, Any, Iterator
from datetime import timedelta
from collections import defaultdict
from .rules import Detection
from ..normalize.schema import LogEvent

class CorrelatedAlert:
    def __init__(self, title: str, detections: List[Detection]):
        self.title = title
        self.detections = detections
        self.severity = "critical" if any(d.severity in ["high", "critical"] for d in detections) else "high"
        self.count = len(detections)
        self.sources = list(set(d.event.source for d in detections))

class CorrelationEngine:
    """
    Correlates detections based on simple heuristics (Time Window, Grouping).
    MVP: Brute Force Detector (Many failures for same user/host).
    """

    def correlate(self, detections: List[Detection], window_seconds: int = 60) -> Iterator[CorrelatedAlert]:
        if not detections:
            return

        # 1. Group by Host
        host_groups = defaultdict(list)
        for d in detections:
            host_groups[d.event.host].append(d)

        # 2. Analyze groups
        for host, group in host_groups.items():
            # Sort by time
            group.sort(key=lambda d: d.event.timestamp)
            
            # Simple Brute Force correlation:
            # If we see > 5 "Failed Login" events in window
            failed_logins = [d for d in group if "Failed Login" in d.rule_name]
            
            if failed_logins:
                # Sliding window check
                start_idx = 0
                for i in range(len(failed_logins)):
                    # Check window from start_idx to i
                    window_start = failed_logins[start_idx].event.timestamp
                    current_time = failed_logins[i].event.timestamp
                    
                    # While window is too large, shrink from left
                    while (current_time - window_start).total_seconds() > window_seconds and start_idx < i:
                        start_idx += 1
                        window_start = failed_logins[start_idx].event.timestamp

                    # Check count in window
                    count_in_window = i - start_idx + 1
                    if count_in_window >= 3: # Low threshold for demo
                        # Create alert for this cluster
                        cluster = failed_logins[start_idx : i+1]
                        yield CorrelatedAlert(
                            title=f"Potential Brute Force on {host} ({count_in_window} failures)",
                            detections=cluster
                        )
                        # Skip ahead to avoid duplicate alerts for same cluster? 
                        # For MVP we might yield redundant ones, but let's just break for this host
                        # or improve sliding window logic.
                        # Simple: return and move to next host
                        break
