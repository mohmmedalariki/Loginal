import asyncio
import os
import random
import uuid
from datetime import datetime
from typing import AsyncIterator, List, Optional

from .models import GUILogEvent
from ..ingest.text import TextIngester
from ..ingest.json_log import JSONIngester
from ..normalize.converters import normalize_event
from ..detect.rules import DetectionEngine

class LogService:
    """
    Base service for retrieving log data.
    """
    async def stream_logs(self, source: Optional[str] = None) -> AsyncIterator[GUILogEvent]:
        """Yields log events as they arrive."""
        raise NotImplementedError

class MockLogService(LogService):
    """
    Generates synthetic security logs for UI testing.
    """
    HOSTS = ["server-01", "db-prod", "firewall-edge", "workstation-hq"]
    USERS = ["admin", "root", "jdoe", "service_account"]
    EVENT_TYPES = [
        ("SSH Successful Login", "low"),
        ("SSH Failed Login", "medium"),
        ("Sudo Command", "low"),
        ("File Access Denied", "medium"),
        ("Malware Detected", "critical"),
        ("Outbound Traffic Spike", "high"),
    ]

    async def stream_logs(self, source: Optional[str] = None) -> AsyncIterator[GUILogEvent]:
        """Yields random log events."""
        while True:
            await asyncio.sleep(random.uniform(0.1, 0.8))
            event_type, severity = random.choice(self.EVENT_TYPES)
            
            if event_type == "SSH Failed Login" and random.random() < 0.3:
                for _ in range(random.randint(2, 5)):
                    yield self._create_event("SSH Failed Login", "medium")
                    await asyncio.sleep(0.05)
            
            yield self._create_event(event_type, severity)

    def _create_event(self, event_type: str, severity: str) -> GUILogEvent:
        return GUILogEvent(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(),
            host=random.choice(self.HOSTS),
            source="mock_stream",
            event_type=event_type,
            user=random.choice(self.USERS),
            message=f"Detected {event_type} event on interface eth0",
            severity=severity
        )

class RealLogService(LogService):
    """
    Ingests actual log files using Loginal's core pipeline.
    """
    def __init__(self):
        self.detection_engine = DetectionEngine()
        self.detection_engine.load_defaults()

    async def stream_logs(self, source: str) -> AsyncIterator[GUILogEvent]:
        """
        Reads from a file and yields events. 
        Note: This is a finite stream, unlike the mock.
        """
        if not source or not os.path.exists(source):
            print(f"Source not found: {source}")
            return

        # Determine format (simple heuristic)
        # Determine format (simple heuristic)
        if source.lower().endswith(".evtx"):
            fmt = "evtx"
        elif source.lower().endswith(".json"):
            fmt = "json"
        elif source.lower().endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "text"
        print(f"Ingesting {source} as {fmt}...")
        
        # Select Ingester
        if fmt == "csv":
            # CSV Handling using pandas directly
            import pandas as pd
            
            def process_csv():
                results = []
                try:
                    df = pd.read_csv(source)
                    # Normalize columns
                    df.columns = [c.lower() for c in df.columns]

                    # Try to normalize standard columns
                    for _, row in df.iterrows():
                        # Map known columns or fallback
                        ts_val = row.get('timestamp') or row.get('time') or row.get('date') or datetime.now()
                        if isinstance(ts_val, str):
                            try:
                                ts = pd.to_datetime(ts_val)
                            except:
                                ts = datetime.now()
                        else:
                            ts = ts_val

                        msg = row.get('message') or row.get('msg') or row.get('data') or str(row.to_dict())
                        host = row.get('host') or row.get('hostname') or row.get('ip') or 'unknown'
                        evt = row.get('event_type') or row.get('event') or 'CSV Event'
                        severity = row.get('severity') or row.get('level') or 'low'
                        
                        gui_event = GUILogEvent(
                            id=str(uuid.uuid4())[:8],
                            timestamp=ts,
                            host=host,
                            source=source,
                            event_type=evt,
                            user=row.get('user') or 'unknown',
                            message=msg,
                            severity=severity,
                            metadata=row.to_dict()
                        )
                        results.append(gui_event)
                except Exception as e:
                    print(f"CSV Error: {e}")
                return results

            loop = asyncio.get_event_loop()
            events = await loop.run_in_executor(None, process_csv)
            for event in events:
                yield event
                await asyncio.sleep(0.001)
            return

        if fmt == "json":
            ingester = JSONIngester()
        elif fmt == "evtx":
            from ..ingest.evtx import EVTXIngester
            ingester = EVTXIngester()
        else:
            ingester = TextIngester()

        # Ingest and Process
        # We run this in a thread executor to avoid blocking the async event loop
        loop = asyncio.get_event_loop()
        
        # Generator wrapper to run sync code
        def process():
            results = []
            try:
                for raw_doc in ingester.ingest(source):
                    # Normalize
                    event = normalize_event(raw_doc, fmt)
                    
                    # Detect
                    severity = "low"
                    alerts = list(self.detection_engine.analyze([event]))
                    if alerts:
                        # Pick highest severity
                        severity = "critical" # simplify for GUI
                        # Or map from alert.severity if available
                    
                    # Convert to GUI Model
                    gui_event = GUILogEvent(
                        id=str(uuid.uuid4())[:8],
                        timestamp=event.timestamp,
                        host=event.host,
                        source=event.source,
                        event_type=alerts[0].title if alerts else "Log Event",
                        user=event.user,
                        message=str(event.original_data)[:200], # truncate
                        severity=severity if alerts else "low",
                        metadata=event.original_data
                    )
                    results.append(gui_event)
                print(f"Processed {len(results)} events.")
            except Exception as e:
                print(f"Error processing {source}: {e}")
                import traceback
                traceback.print_exc()
            return results

        # Run pipeline
        events = await loop.run_in_executor(None, process)
        
        for event in events:
            yield event
            # Small yield to allow UI to update during heavy valid processing
            await asyncio.sleep(0.001)
