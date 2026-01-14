from typing import Iterator, Dict, Any, Optional
import os
from datetime import datetime
from .base import LogIngester

# Try to import Evtx, handle if missing
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    _HAS_EVTX = True
except ImportError:
    _HAS_EVTX = False

class EVTXIngester(LogIngester):
    """
    Ingests Windows Event Log files (.evtx).
    Requires 'python-evtx' library.
    """
    def ingest(self, source_path: str) -> Iterator[Dict[str, Any]]:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"File not found: {source_path}")

        if not _HAS_EVTX:
            # Fallback/Mock for environments without python-evtx
            # In production, we'd raise an error or warn heavily.
            yield {
                "error": "missing_dependency",
                "message": "python-evtx library not installed. Cannot parse .evtx files.",
                "source_path": source_path
            }
            return

        try:
            with Evtx(source_path) as log:
                for i, record in enumerate(log.records()):
                    # record.xml() returns the XML string of the event
                    # ideally we parse this XML to dict, but for now passing as raw text/xml
                    # In a real tool we'd use 'xmltodict' or lxml here.
                    yield {
                        "raw_text": record.xml(),
                        "offset": record.offset(),
                        "event_record_id": record.record_num(),
                        "timestamp": record.timestamp(), # python-evtx returns datetime
                        "source_path": source_path,
                        "is_evtx": True
                    }
        except Exception as e:
            yield {
                "error": "evtx_parse_error",
                "message": str(e),
                "source_path": source_path
            }
