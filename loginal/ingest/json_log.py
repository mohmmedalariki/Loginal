from typing import Iterator, Dict, Any
import json
import os
from .base import LogIngester

class JSONIngester(LogIngester):
    """
    Ingests line-delimited JSON logs (NDJSON).
    Common in CloudTrail, Kubernetes, etc.
    """
    def ingest(self, source_path: str) -> Iterator[Dict[str, Any]]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"File not found: {source_path}")

        with open(source_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if isinstance(data, dict):
                        # Inject metadata
                        data['_metadata'] = {
                            "line_number": line_no,
                            "source_path": source_path
                        }
                        yield data
                except json.JSONDecodeError:
                    # In a real tool, we might log a warning or result in a 'parse_error' event
                    yield {
                        "error": "json_decode_error",
                        "raw_text": line,
                        "line_number": line_no,
                        "source_path": source_path
                    }
