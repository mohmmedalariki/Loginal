from typing import Iterator, List, Optional
import re
from ..normalize.schema import LogEvent

class QueryEngine:
    """
    Executes queries against a stream of LogEvents.
    """
    def __init__(self):
        pass

    def filter(self, events: Iterator[LogEvent], query: Optional[str] = None) -> Iterator[LogEvent]:
        """
        Filter events based on a simple query string.
        Supported syntax:
        - "key=value" (Exact match on field)
        - "term" (Text search in message)
        - "key~regex" (Regex match on field)
        """
        if not query:
            yield from events
            return

        # Simple parsing for MVP
        # e.g. "user=root" or "failed password"
        if "=" in query:
            key, val = query.split("=", 1)
            for event in events:
                if str(getattr(event, key, "")) == val:
                    yield event
        elif "~" in query:
            key, pattern = query.split("~", 1)
            regex = re.compile(pattern, re.IGNORECASE)
            for event in events:
                if regex.search(str(getattr(event, key, ""))):
                    yield event
        else:
            # Full text search in message
            term = query.lower()
            for event in events:
                if term in event.message.lower():
                    yield event
