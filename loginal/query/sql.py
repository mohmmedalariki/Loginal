import sqlite3
from typing import Iterator, List, Any
from ..normalize.schema import LogEvent

try:
    import duckdb
    _HAS_DUCKDB = True
except ImportError:
    _HAS_DUCKDB = False

class SQLEngine:
    """
    In-memory SQL engine using DuckDB (preferred) or SQLite (fallback).
    """
    def __init__(self):
        self.use_duckdb = _HAS_DUCKDB
        if self.use_duckdb:
            self.con = duckdb.connect(database=':memory:')
        else:
            self.con = sqlite3.connect(':memory:')

    def load_events(self, events: List[LogEvent]):
        """
        Load events into DB.
        """
        # Create table
        create_sql = """
            CREATE TABLE logs (
                timestamp TEXT,
                host TEXT,
                event_type TEXT,
                message TEXT,
                source TEXT,
                user_name TEXT
            )
        """
        if self.use_duckdb:
            self.con.execute("CREATE TABLE logs (timestamp TIMESTAMP, host VARCHAR, event_type VARCHAR, message VARCHAR, source VARCHAR, user_name VARCHAR)")
        else:
            self.con.execute(create_sql)
        
        # Prepare data
        data = []
        for e in events:
            # SQLite needs ISO strings for timestamps usually if we want readable dates, 
            # though it doesn't have native datetime type like PG/DuckDB.
            ts_val = e.timestamp if self.use_duckdb else e.timestamp.isoformat()
            data.append((
                ts_val,
                e.host,
                e.event_type,
                e.message,
                e.source,
                e.user
            ))
            
        # Bulk insert
        if self.use_duckdb:
            self.con.executemany("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)", data)
        else:
            self.con.executemany("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)", data)
            self.con.commit()

    def execute(self, query: str) -> List[Any]:
        """
        Execute SQL query and return results.
        """
        if self.use_duckdb:
            return self.con.execute(query).fetchall()
        else:
            cursor = self.con.execute(query)
            return cursor.fetchall()
