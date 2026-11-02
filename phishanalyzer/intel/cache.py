"""SQLite cache so repeated lookups don't spend API quota."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, path: Path, ttl_hours: float):
        self.ttl = ttl_hours * 3600
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, ts REAL, value TEXT)")
        self._db.commit()

    def get(self, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute("SELECT ts, value FROM cache WHERE key = ?", (key,)).fetchone()
        if row and time.time() - row[0] < self.ttl:
            return json.loads(row[1])
        return None

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?)", (key, time.time(), json.dumps(value)))
            self._db.commit()
