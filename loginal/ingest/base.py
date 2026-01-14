from abc import ABC, abstractmethod
from typing import Iterator, Dict, Any

class LogIngester(ABC):
    """
    Abstract base class for all log ingesters.
    ADAPTER PATTERN: Ingesters adapt raw log sources to a stream of dictionaries.
    """
    
    @abstractmethod
    def ingest(self, source_path: str) -> Iterator[Dict[str, Any]]:
        """
        Stream logs from source_path.
        Yields raw dictionaries that will later be normalized.
        """
        pass
