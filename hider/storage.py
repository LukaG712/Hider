"""SQLite storage for Hider secrets and configurations."""

import os
import sqlite3
from datetime import datetime
from typing import Any

from hider.models import Config, Secret


class Storage:
    """SQLite-backed storage for secrets and configs."""

    def __init__(self, db_path: str = "/app/data/hider.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    id TEXT PRIMARY KEY,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    service TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS configs (
                    id TEXT PRIMARY KEY,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT NOT NULL,
                    service TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.commit()

    # ─── Secrets ──────────────────────────────────────────────

    def create_secret(self, secret: Secret, encrypted_value: str) -> Secret:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO secrets (id, key, value, service, description, created_at, updated_at, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(secret.id), secret.key, encrypted_value, secret.service,
                    secret.description, secret.created_at.isoformat(),
                    secret.updated_at.isoformat(), secret.version,
                ),
            )
            conn.commit()
        return secret

    def get_secret(self, key: str) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM secrets WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            return dict(row)

    def list_secrets(self, service: str | None = None) -> list[dict]:
        with self._get_conn() as conn:
            if service:
                rows = conn.execute(
                    "SELECT * FROM secrets WHERE service = ? ORDER BY created_at DESC",
                    (service,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM secrets ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

    def update_secret(self, key: str, **fields: Any) -> dict | None:
        with self._get_conn() as conn:
            existing = conn.execute("SELECT * FROM secrets WHERE key = ?", (key,)).fetchone()
            if existing is None:
                return None
            existing_dict = dict(existing)
            updatable = {"value", "description"}
            for k, v in fields.items():
                if k in updatable:
                    existing_dict[k] = v
            existing_dict["updated_at"] = datetime.utcnow().isoformat()
            existing_dict["version"] = existing_dict.get("version", 1) + 1
            conn.execute(
                "UPDATE secrets SET value=?, description=?, updated_at=?, version=? WHERE key=?",
                (
                    existing_dict["value"], existing_dict["description"],
                    existing_dict["updated_at"], existing_dict["version"], key,
                ),
            )
            conn.commit()
            return existing_dict

    def delete_secret(self, key: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM secrets WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0

    # ─── Configs ──────────────────────────────────────────────

    def create_config(self, config: Config) -> Config:
        with self._get_conn() as conn:
            conn.execute(
                "INSERT INTO configs (id, key, value, service, description, created_at, updated_at, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(config.id), config.key, str(config.value), config.service,
                    config.description, config.created_at.isoformat(),
                    config.updated_at.isoformat(), config.version,
                ),
            )
            conn.commit()
        return config

    def get_config(self, key: str) -> dict | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM configs WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            return dict(row)

    def list_configs(self, service: str | None = None) -> list[dict]:
        with self._get_conn() as conn:
            if service:
                rows = conn.execute(
                    "SELECT * FROM configs WHERE service = ? ORDER BY created_at DESC",
                    (service,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM configs ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]

    def update_config(self, key: str, **fields: Any) -> dict | None:
        with self._get_conn() as conn:
            existing = conn.execute("SELECT * FROM configs WHERE key = ?", (key,)).fetchone()
            if existing is None:
                return None
            existing_dict = dict(existing)
            updatable = {"value", "description"}
            for k, v in fields.items():
                if k in updatable:
                    existing_dict[k] = v
            existing_dict["updated_at"] = datetime.utcnow().isoformat()
            existing_dict["version"] = existing_dict.get("version", 1) + 1
            conn.execute(
                "UPDATE configs SET value=?, description=?, updated_at=?, version=? WHERE key=?",
                (
                    existing_dict["value"], existing_dict["description"],
                    existing_dict["updated_at"], existing_dict["version"], key,
                ),
            )
            conn.commit()
            return existing_dict

    def delete_config(self, key: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.execute("DELETE FROM configs WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0
