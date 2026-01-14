from typing import Iterator, Dict, Any
import os
from .base import LogIngester

class TextIngester(LogIngester):
    """
    Ingests plain text files line-by-line.
    Useful for syslog, auth.log, apache access logs (raw).
    """
    def ingest(self, source_path: str) -> Iterator[Dict[str, Any]]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"File not found: {source_path}")

        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                yield {
                    "raw_text": line,
                    "line_number": line_no,
                    "source_path": source_path
                }
