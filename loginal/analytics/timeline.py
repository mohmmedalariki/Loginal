from typing import Iterator, List, Iterable
import heapq
from ..normalize.schema import LogEvent

def merge_sorted_events(iterators: List[Iterator[LogEvent]]) -> Iterator[LogEvent]:
    """
    Merge multiple sorted streams of LogEvents into a single sorted stream.
    Assumes each input iterator is already sorted by timestamp (standard for logs).
    """
    # heapq.merge requires the inputs to be sorted.
    # We use a key to sort by timestamp.
    return heapq.merge(*iterators, key=lambda e: e.timestamp)

def timeline_analysis(events: Iterable[LogEvent]) -> Iterator[LogEvent]:
    """
    Pass-through for now, but place to add windowing or sequencing logic.
    """
    yield from events
