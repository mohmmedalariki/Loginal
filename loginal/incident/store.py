import sqlite3
import json
import os
from .model import Incident, Provenance

class IncidentStore:
    """SQLite backend for Incidents."""
    
    def __init__(self, db_path: str = None):
        if not db_path:
            home = os.path.expanduser("~/.loginal")
            os.makedirs(home, exist_ok=True)
            db_path = os.path.join(home, "incidents.db")
            
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    created_at TEXT,
                    status TEXT,
                    data TEXT
                )
            """)

    def save_incident(self, incident: Incident):
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO incidents (id, created_at, status, data) VALUES (?, ?, ?, ?)",
                (incident.id, incident.created_at, incident.status, json.dumps(incident.to_dict()))
            )

    def list_incidents(self):
        cursor = self.conn.execute("SELECT data FROM incidents ORDER BY created_at DESC")
        results = []
        for row in cursor:
            try:
                d = json.loads(row[0])
                # Reconstruct object
                inc = Incident(
                    id=d['id'], title=d['title'], created_at=d['created_at'], status=d['status']
                )
                if d.get('provenance'):
                    inc.provenance = Provenance(**d['provenance'])
                inc.bulk_summary = d.get('bulk_summary')
                inc.expert_analysis = d.get('expert_analysis')
                results.append(inc)
            except Exception as e:
                print(f"Error loading incident: {e}")
        return results
        
    def get_incident(self, id: str):
        cursor = self.conn.execute("SELECT data FROM incidents WHERE id = ?", (id,))
        row = cursor.fetchone()
        if row:
            d = json.loads(row[0])
            inc = Incident(
                id=d['id'], title=d['title'], created_at=d['created_at'], status=d['status']
            )
            if d.get('provenance'):
                inc.provenance = Provenance(**d['provenance'])
            inc.bulk_summary = d.get('bulk_summary')
            inc.expert_analysis = d.get('expert_analysis')
            return inc
        return None

    def delete_incident(self, id: str):
        with self.conn:
            self.conn.execute("DELETE FROM incidents WHERE id = ?", (id,))
