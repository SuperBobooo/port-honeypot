from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .crypto import FrameCrypto


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  os TEXT NOT NULL DEFAULT '',
  arch TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  listen_ports_json TEXT NOT NULL DEFAULT '[]',
  stealth_mode INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER NOT NULL,
  last_heartbeat INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  source_ip TEXT NOT NULL,
  source_port INTEGER,
  target_port INTEGER NOT NULL,
  mode TEXT NOT NULL,
  content_cipher TEXT NOT NULL DEFAULT '',
  content_size INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_events_ts ON attack_events(ts);
CREATE INDEX IF NOT EXISTS idx_attack_events_node ON attack_events(node_id);
CREATE INDEX IF NOT EXISTS idx_attack_events_source ON attack_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_attack_events_port ON attack_events(target_port);
CREATE TABLE IF NOT EXISTS server_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  dedupe_key TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_history_key ON alert_history(event_type, dedupe_key, ts);
CREATE TABLE IF NOT EXISTS node_commands (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id TEXT NOT NULL,
  command TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  delivered_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_node_commands_pending ON node_commands(node_id, delivered_at, id);
"""


class Database:
    def __init__(self, path: str | Path, crypto: FrameCrypto):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.crypto = crypto
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def log(self, level: str, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO server_logs(ts, level, message) VALUES (?, ?, ?)",
                (int(time.time()), level.upper(), message),
            )
            self._conn.commit()

    def upsert_node(self, node: dict[str, Any], peer_ip: str) -> None:
        now = int(time.time())
        ports = node.get("listen_ports") or []
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO nodes(
                  node_id, hostname, ip, os, arch, version, listen_ports_json,
                  stealth_mode, online, first_seen, last_heartbeat
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                  hostname=excluded.hostname,
                  ip=excluded.ip,
                  os=excluded.os,
                  arch=excluded.arch,
                  version=excluded.version,
                  listen_ports_json=excluded.listen_ports_json,
                  stealth_mode=excluded.stealth_mode,
                  online=1,
                  last_heartbeat=excluded.last_heartbeat
                """,
                (
                    str(node["node_id"]),
                    str(node.get("hostname", "")),
                    peer_ip,
                    str(node.get("os", "")),
                    str(node.get("arch", "")),
                    str(node.get("version", "")),
                    json.dumps(ports),
                    1 if node.get("stealth_mode") else 0,
                    now,
                    now,
                ),
            )
            self._conn.commit()

    def heartbeat(self, node_id: str, peer_ip: str, listen_ports: list[int] | None = None) -> None:
        now = int(time.time())
        with self._lock:
            if listen_ports is None:
                self._conn.execute(
                    "UPDATE nodes SET ip=?, online=1, last_heartbeat=? WHERE node_id=?",
                    (peer_ip, now, node_id),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE nodes
                    SET ip=?, online=1, last_heartbeat=?, listen_ports_json=?
                    WHERE node_id=?
                    """,
                    (peer_ip, now, json.dumps(listen_ports), node_id),
                )
            self._conn.commit()

    def mark_stale_nodes_offline(self, timeout_seconds: int) -> list[dict[str, Any]]:
        cutoff = int(time.time()) - timeout_seconds
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM nodes WHERE online=1 AND last_heartbeat < ?",
                (cutoff,),
            ).fetchall()
            if rows:
                self._conn.execute(
                    "UPDATE nodes SET online=0 WHERE online=1 AND last_heartbeat < ?",
                    (cutoff,),
                )
                self._conn.commit()
            return [self._node_row_to_dict(row) for row in rows]

    def insert_events(self, node_id: str, events: list[dict[str, Any]]) -> int:
        now = int(time.time())
        rows = []
        for event in events:
            content = str(event.get("content", ""))
            cipher = ""
            if content:
                cipher = base64.b64encode(self.crypto.encrypt(content.encode("utf-8"))).decode("ascii")
            rows.append(
                (
                    node_id,
                    int(event.get("ts") or now),
                    str(event.get("source_ip", "")),
                    _as_optional_int(event.get("source_port")),
                    int(event.get("target_port") or 0),
                    str(event.get("mode", "general")),
                    cipher,
                    len(content.encode("utf-8")),
                    now,
                )
            )
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO attack_events(
                  node_id, ts, source_ip, source_port, target_port, mode,
                  content_cipher, content_size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            self._conn.commit()
        return len(rows)

    def query_events(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        where = []
        args: list[Any] = []
        if filters.get("node_id"):
            where.append("node_id = ?")
            args.append(filters["node_id"])
        if filters.get("source_ip"):
            where.append("source_ip LIKE ?")
            args.append(f"%{filters['source_ip']}%")
        if filters.get("target_port"):
            where.append("target_port = ?")
            args.append(int(filters["target_port"]))
        if filters.get("from_ts"):
            where.append("ts >= ?")
            args.append(int(filters["from_ts"]))
        if filters.get("to_ts"):
            where.append("ts <= ?")
            args.append(int(filters["to_ts"]))
        sql = "SELECT * FROM attack_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(min(int(filters.get("limit") or 200), 2000))
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._event_row_to_dict(row) for row in rows]

    def list_nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM nodes ORDER BY online DESC, last_heartbeat DESC").fetchall()
        nodes = [self._node_row_to_dict(row) for row in rows]
        for node in nodes:
            node["pending_commands"] = self.pending_command_count(str(node["node_id"]))
        return nodes

    def stats(self) -> dict[str, Any]:
        with self._lock:
            node_count = self._conn.execute("SELECT COUNT(*) AS c FROM nodes").fetchone()["c"]
            online_count = self._conn.execute("SELECT COUNT(*) AS c FROM nodes WHERE online=1").fetchone()["c"]
            event_count = self._conn.execute("SELECT COUNT(*) AS c FROM attack_events").fetchone()["c"]
            top_ips = self._conn.execute(
                """
                SELECT source_ip, COUNT(*) AS count
                FROM attack_events
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()
            top_ports = self._conn.execute(
                """
                SELECT target_port, COUNT(*) AS count
                FROM attack_events
                GROUP BY target_port
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()
            trend = self._conn.execute(
                """
                SELECT (ts / 3600) * 3600 AS bucket, COUNT(*) AS count
                FROM attack_events
                WHERE ts >= ?
                GROUP BY bucket
                ORDER BY bucket ASC
                """,
                (int(time.time()) - 24 * 3600,),
            ).fetchall()
        return {
            "nodes": node_count,
            "online_nodes": online_count,
            "events": event_count,
            "top_ips": [dict(row) for row in top_ips],
            "top_ports": [dict(row) for row in top_ports],
            "trend": [dict(row) for row in trend],
        }

    def recent_server_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM server_logs ORDER BY ts DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def last_alert_ts(self, event_type: str, dedupe_key: str) -> int | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT ts FROM alert_history
                WHERE event_type=? AND dedupe_key=?
                ORDER BY ts DESC
                LIMIT 1
                """,
                (event_type, dedupe_key),
            ).fetchone()
        return None if row is None else int(row["ts"])

    def record_alert(self, event_type: str, dedupe_key: str, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO alert_history(ts, event_type, dedupe_key, message) VALUES (?, ?, ?, ?)",
                (int(time.time()), event_type, dedupe_key, message),
            )
            self._conn.commit()

    def enqueue_command(self, node_id: str, command: str, payload: dict[str, Any] | None = None) -> int:
        payload = payload or {}
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO node_commands(node_id, command, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (node_id, command, json.dumps(payload), int(time.time())),
            )
            self._conn.commit()
            command_id = int(cursor.lastrowid)
        self.log("INFO", f"queued command {command} for node {node_id}")
        return command_id

    def pop_pending_commands(self, node_id: str, limit: int = 20) -> list[dict[str, Any]]:
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM node_commands
                WHERE node_id=? AND delivered_at IS NULL
                ORDER BY id ASC
                LIMIT ?
                """,
                (node_id, limit),
            ).fetchall()
            ids = [int(row["id"]) for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"UPDATE node_commands SET delivered_at=? WHERE id IN ({placeholders})",
                    (now, *ids),
                )
                self._conn.commit()
        commands: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"] or "{}")
            except json.JSONDecodeError:
                payload = {}
            commands.append(
                {
                    "id": int(row["id"]),
                    "command": row["command"],
                    "payload": payload,
                    "created_at": int(row["created_at"]),
                }
            )
        return commands

    def pending_command_count(self, node_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM node_commands WHERE node_id=? AND delivered_at IS NULL",
                (node_id,),
            ).fetchone()
        return int(row["c"])

    def _event_row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        content = ""
        if value.get("content_cipher"):
            try:
                encrypted = base64.b64decode(value["content_cipher"].encode("ascii"))
                content = self.crypto.decrypt(encrypted).decode("utf-8", errors="replace")
            except Exception:
                content = "<decrypt failed>"
        value["content"] = content
        value.pop("content_cipher", None)
        return value

    @staticmethod
    def _node_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        try:
            value["listen_ports"] = json.loads(value.pop("listen_ports_json") or "[]")
        except json.JSONDecodeError:
            value["listen_ports"] = []
        value["online"] = bool(value["online"])
        value["stealth_mode"] = bool(value["stealth_mode"])
        return value


def _as_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)
