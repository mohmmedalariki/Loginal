import sqlite3
import json
import os
from typing import Dict, List, Any, Optional

class MetadataStore:
    """
    SQLite backend for mapping Vector IDs to Log Events.
    Schema: id (int PK), timestamp (str), host (str), user (str), severity (str), data (json)
    """
    
    def __init__(self, db_path: str = None):
        if not db_path:
            # Default to user's home dir
            home = os.path.expanduser("~/.loginal")
            os.makedirs(home, exist_ok=True)
            db_path = os.path.join(home, "semantic.db")
            
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            # Check if table needs migration (simple drop/create mechanism for this demo)
            # In prod, use ALTER TABLE or migration scripts
            try:
                # Try selecting new columns, if fail, drop table
                self.conn.execute("SELECT host FROM meta LIMIT 1")
            except:
                self.conn.execute("DROP TABLE IF EXISTS meta")

            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    host TEXT,
                    user TEXT,
                    severity TEXT,
                    event_type TEXT,
                    data TEXT
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON meta(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON meta(host)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_sev ON meta(severity)")

    def add_batch(self, start_id: int, events: List[Dict]):
        """
        Add a batch of log metadata with indexed fields.
        """
        rows = []
        for i, event in enumerate(events):
            vid = start_id + i
            ts = event.get('timestamp', '')
            host = str(event.get('host', ''))
            user = str(event.get('user', ''))
            sev = str(event.get('severity', ''))
            etype = str(event.get('event_type', ''))
            
            # Serialize full event to JSON
            rows.append((vid, ts, host, user, sev, etype, json.dumps(event)))
            
        with self.conn:
            self.conn.executemany("""
                INSERT OR REPLACE INTO meta (id, timestamp, host, user, severity, event_type, data) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, rows)

    def get_batch(self, ids: List[int]) -> List[Dict]:
        """
        Retrieve metadata for a list of vector IDs.
        """
        if not ids:
            return []
            
        placeholders = ",".join("?" * len(ids))
        
        # Order by CASE statement to preserve rank from FAISS?
        # For now, simplest retrieve
        cursor = self.conn.execute(f"SELECT data FROM meta WHERE id IN ({placeholders})", ids)
        
        results = []
        id_map = {} # buffer to restore order
        
        # If we need to preserve order, we need to select ID too
        cursor = self.conn.execute(f"SELECT id, data FROM meta WHERE id IN ({placeholders})", ids)
        
        rows = cursor.fetchall()
        row_map = {r[0]: json.loads(r[1]) for r in rows}
        
        # Reconstruct in order of 'ids'
        final_list = []
        found_ids = set()
        for i in ids:
            if i in row_map:
                final_list.append(row_map[i])
                found_ids.add(i)
                
        return final_list

    def filter_ids(self, 
                   host: Optional[str] = None, 
                   user: Optional[str] = None, 
                   time_start: Optional[str] = None,
                   time_end: Optional[str] = None) -> List[int]:
        """
        Return Set of IDs matching filters. Used for Hybrid Search post-filtering or pre-filtering.
        """
        query = "SELECT id FROM meta WHERE 1=1"
        params = []
        
        if host:
            query += " AND host = ?"
            params.append(host)
        if user:
            query += " AND user = ?"
            params.append(user)
        if time_start:
            query += " AND timestamp >= ?"
            params.append(time_start)
        if time_end:
            query += " AND timestamp <= ?"
            params.append(time_end)
            
        cursor = self.conn.execute(query, params)
        return [r[0] for r in cursor]

    def clear(self):
        with self.conn:
            self.conn.execute("DELETE FROM meta")

    def count(self):
        return self.conn.execute("SELECT count(*) FROM meta").fetchone()[0]
