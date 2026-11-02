"""SQLite case log: deduplication, processed Outlook items and history."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from .models import CaseResult


class CaseStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY, created TEXT, verdict TEXT, score INTEGER, confidence TEXT,
                subject TEXT, sender TEXT, reporter TEXT, dedupe_key TEXT, report_path TEXT, source TEXT);
            CREATE INDEX IF NOT EXISTS ix_cases_dedupe ON cases(dedupe_key);
            CREATE TABLE IF NOT EXISTS processed_items (entry_id TEXT PRIMARY KEY, processed TEXT, case_ids TEXT);
            CREATE TABLE IF NOT EXISTS reported_items (entry_id TEXT PRIMARY KEY, reported TEXT);
            CREATE TABLE IF NOT EXISTS logged_items (entry_id TEXT PRIMARY KEY, logged TEXT);
            CREATE TABLE IF NOT EXISTS alerted (key TEXT PRIMARY KEY, alerted TEXT);
            CREATE TABLE IF NOT EXISTS logged_cases (case_id TEXT PRIMARY KEY, day TEXT, json_path TEXT, shared_html TEXT);
        """)
        self.db.commit()

    def was_alerted(self, key: str) -> bool:
        return self.db.execute("SELECT 1 FROM alerted WHERE key = ?", (key,)).fetchone() is not None

    def mark_alerted(self, key: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO alerted VALUES (?, ?)", (key, datetime.now().isoformat(timespec="seconds")))
        self.db.commit()

    def is_logged(self, entry_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM logged_items WHERE entry_id = ?", (entry_id,)).fetchone() is not None

    def mark_logged(self, entry_ids: list[str], cases: list[tuple[str, str, str]]) -> None:
        """cases = [(case_id, result.json path, shared html path)]"""
        now = datetime.now()
        self.db.executemany("INSERT OR REPLACE INTO logged_items VALUES (?, ?)",
                            [(e, now.isoformat(timespec="seconds")) for e in entry_ids])
        self.db.executemany("INSERT OR REPLACE INTO logged_cases VALUES (?, ?, ?, ?)",
                            [(c, now.date().isoformat(), j, h) for c, j, h in cases])
        self.db.commit()

    def logged_cases_for(self, day: str) -> list[tuple[str, str]]:
        return self.db.execute("SELECT json_path, shared_html FROM logged_cases WHERE day = ? ORDER BY case_id",
                               (day,)).fetchall()

    def is_reported(self, entry_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM reported_items WHERE entry_id = ?", (entry_id,)).fetchone() is not None

    def mark_reported(self, entry_ids: list[str]) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        self.db.executemany("INSERT OR REPLACE INTO reported_items VALUES (?, ?)", [(e, now) for e in entry_ids])
        self.db.commit()

    @staticmethod
    def dedupe_key(result: CaseResult) -> str:
        return (result.original.get("message_id") or "").strip().lower() or result.message_sha256

    def find_duplicate(self, key: str) -> str:
        if not key:
            return ""
        row = self.db.execute("SELECT case_id FROM cases WHERE dedupe_key = ? ORDER BY created LIMIT 1", (key,)).fetchone()
        return row[0] if row else ""

    def add_case(self, result: CaseResult, key: str, report_path: Path) -> None:
        o = result.original
        self.db.execute("INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            result.case_id, datetime.now().isoformat(timespec="seconds"), result.verdict, result.score,
            result.confidence, o.get("subject", ""), o.get("from_address", ""), result.reported_by, key,
            str(report_path), result.source))
        self.db.commit()

    def is_processed(self, entry_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM processed_items WHERE entry_id = ?", (entry_id,)).fetchone() is not None

    def mark_processed(self, entry_id: str, case_ids: list[str]) -> None:
        self.db.execute("INSERT OR REPLACE INTO processed_items VALUES (?,?,?)",
                        (entry_id, datetime.now().isoformat(timespec="seconds"), ",".join(case_ids)))
        self.db.commit()
