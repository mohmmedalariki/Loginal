from typing import List, Dict, Any, Iterator
from collections import Counter
from ..normalize.schema import LogEvent

def frequency_anomaly(events: List[LogEvent], field: str = "event_type", threshold: float = 2.0) -> Iterator[Dict[str, Any]]:
    """
    Detect statistical anomalies in field frequency.
    Uses a simple Mean + Threshold * StdDev approach (Z-score-ish) or 
    just simple outlier detection if distribution is assumed normal.
    
    For a MVP, we'll detecting items that appear significantly more often than the average 
    unique item, which might indicate a flood/spike.
    
    Args:
        events: List of LogEvents
        field: Field to analyze (e.g. 'event_type', 'host', 'user')
        threshold: Multiplier for detection (e.g. > 2x average)
        
    Yields:
        Anomaly dict
    """
    if not events:
        return

    # Extract values
    values = []
    for e in events:
        val = getattr(e, field, None)
        if val:
            values.append(str(val))
            
    if not values:
        return

    counts = Counter(values)
    total_items = len(values)
    unique_items = len(counts)
    
    if unique_items < 2:
        return # Not enough variance to detect anomaly
        
    avg_count = total_items / unique_items
    
    # Simple spike detection: if count > threshold * average
    for val, count in counts.items():
        if count > (avg_count * threshold):
            yield {
                "anomaly_type": "frequency_spike",
                "field": field,
                "value": val,
                "count": count,
                "average": avg_count,
                "severity": "high" if count > avg_count * 5 else "medium"
            }
