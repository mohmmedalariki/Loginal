import sqlite3
import json
import os
import datetime
from typing import Optional
from .model import EnrichmentResult

class IOCCache:
    """SQLite Cache for Enrichment Results."""
    
    def __init__(self, db_path: str = None):
        if not db_path:
            home = os.path.expanduser("~/.loginal")
            os.makedirs(home, exist_ok=True)
            db_path = os.path.join(home, "ioc.db")
            
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    kind TEXT,
                    fetched_at TIMESTAMP,
                    data TEXT
                )
            """)
            
    def get(self, ioc: str, ttl_hours=24) -> Optional[EnrichmentResult]:
        now = datetime.datetime.now()
        with self.conn:
            cursor = self.conn.execute("SELECT fetched_at, data FROM cache WHERE key = ?", (ioc,))
            row = cursor.fetchone()
            
            if row:
                fetched_at = datetime.datetime.fromisoformat(row[0])
                if (now - fetched_at).total_seconds() < (ttl_hours * 3600):
                    data = json.loads(row[1])
                    return EnrichmentResult(**data)
                else:
                    # Expired
                    return None
        return None

    def set(self, result: EnrichmentResult):
        now = datetime.datetime.now()
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache (key, kind, fetched_at, data) VALUES (?, ?, ?, ?)",
                (result.ioc, result.kind, now.isoformat(), json.dumps(result.to_dict()))
            )

    def stats(self):
        cursor = self.conn.execute("SELECT count(*) FROM cache")
        return cursor.fetchone()[0]
        
    def clear(self):
        with self.conn:
            self.conn.execute("DELETE FROM cache")
