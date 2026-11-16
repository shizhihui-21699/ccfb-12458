"""SQLite 持久化：保存扫描快照与发现记录。"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    system TEXT NOT NULL,
    root TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    overall_score INTEGER,
    level TEXT,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    system TEXT NOT NULL,
    asset_type TEXT, language TEXT, file_path TEXT, line INTEGER,
    algorithm TEXT, category TEXT, variant_raw TEXT, rule_id TEXT,
    confidence TEXT, severity TEXT, weak INTEGER, pq_status TEXT,
    pq_note TEXT, context TEXT, key_usage TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save_scan(self, inventory) -> int:
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(inventory.to_dict(), ensure_ascii=False)
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans(system, root, scanned_at, finding_count, overall_score, level, payload)"
                " VALUES (?,?,?,?,?,?,?)",
                (inventory.system, inventory.root, now, len(inventory.findings),
                 inventory.readiness.overall, inventory.readiness.level, payload))
            scan_id = cur.lastrowid
            c.executemany(
                "INSERT INTO findings(scan_id, system, asset_type, language, file_path, line,"
                " algorithm, category, variant_raw, rule_id, confidence, severity, weak,"
                " pq_status, pq_note, context, key_usage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, f.system, f.asset_type.value, f.language, f.file_path, f.line,
                  f.algorithm, f.category, f.variant_raw, f.rule_id, f.confidence.value,
                  f.severity.value, int(f.weak), f.pq_status, f.pq_note, f.context, f.key_usage)
                 for f in inventory.findings])
        return scan_id

    def list_scans(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, system, root, scanned_at, finding_count, overall_score, level"
                " FROM scans ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_scan_payload(self, scan_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT payload FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def latest_scan_id(self, system: str) -> int | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM scans WHERE system=? ORDER BY id DESC LIMIT 1", (system,)).fetchone()
        return row["id"] if row else None

    def all_latest_payloads(self) -> list[dict]:
        out = []
        for row in self.list_scans():
            payload = self.get_scan_payload(row["id"])
            if payload:
                out.append(payload)
        return out
