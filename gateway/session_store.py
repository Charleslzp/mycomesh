from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SessionStore:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_key TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    title TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_sessions_user_workspace_task
                ON sessions(user_id, workspace_id, task_id, updated_at)
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_key TEXT,
                    user_id TEXT NOT NULL DEFAULT 'local-user',
                    workspace_id TEXT NOT NULL DEFAULT 'default-workspace',
                    task_id TEXT NOT NULL DEFAULT 'default-task',
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    message_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            _ensure_column(conn, "messages", "session_key", "TEXT")
            _ensure_column(conn, "messages", "user_id", "TEXT NOT NULL DEFAULT 'local-user'")
            _ensure_column(conn, "messages", "workspace_id", "TEXT NOT NULL DEFAULT 'default-workspace'")
            _ensure_column(conn, "messages", "task_id", "TEXT NOT NULL DEFAULT 'default-task'")
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_agent_session_id
                ON messages(agent_id, session_id, id)
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_session_key_id
                ON messages(session_key, id)
                """
            )

    def history(self, agent_id: str, session_id: str, limit: int) -> list[dict[str, Any]]:
        return self.history_for_session_key(
            make_session_key(
                user_id="local-user",
                workspace_id="default-workspace",
                task_id=session_id,
                agent_id=agent_id,
                session_id=session_id,
            ),
            limit,
            fallback_agent_id=agent_id,
            fallback_session_id=session_id,
        )

    def history_for_session_key(
        self,
        session_key: str,
        limit: int,
        fallback_agent_id: str | None = None,
        fallback_session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if fallback_agent_id and fallback_session_id:
                rows = conn.execute(
                    """
                    SELECT message_json
                    FROM (
                        SELECT id, message_json
                        FROM messages
                        WHERE session_key = ?
                           OR (session_key IS NULL AND agent_id = ? AND session_id = ?)
                        ORDER BY id DESC
                        LIMIT ?
                    )
                    ORDER BY id ASC
                    """,
                    (session_key, fallback_agent_id, fallback_session_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT message_json
                    FROM (
                        SELECT id, message_json
                        FROM messages
                        WHERE session_key = ?
                        ORDER BY id DESC
                        LIMIT ?
                    )
                    ORDER BY id ASC
                    """,
                    (session_key, limit),
                ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def append(self, agent_id: str, session_id: str, messages: list[dict[str, Any]]) -> None:
        self.append_turn(
            user_id="local-user",
            workspace_id="default-workspace",
            task_id=session_id,
            agent_id=agent_id,
            session_id=session_id,
            messages=messages,
        )

    def append_turn(
        self,
        user_id: str,
        workspace_id: str,
        task_id: str,
        agent_id: str,
        session_id: str,
        messages: list[dict[str, Any]],
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if not messages:
            return

        now = datetime.now(timezone.utc).isoformat()
        session_key = make_session_key(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            agent_id=agent_id,
            session_id=session_id,
        )
        rows = [
            (
                session_key,
                user_id,
                workspace_id,
                task_id,
                agent_id,
                session_id,
                json.dumps(message, ensure_ascii=False),
                now,
            )
            for message in messages
        ]
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO sessions(
                        session_key,
                        user_id,
                        workspace_id,
                        task_id,
                        agent_id,
                        session_id,
                        title,
                        metadata_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_key) DO UPDATE SET
                        updated_at = excluded.updated_at,
                        metadata_json = excluded.metadata_json
                    """,
                    (
                        session_key,
                        user_id,
                        workspace_id,
                        task_id,
                        agent_id,
                        session_id,
                        _session_title(messages),
                        json.dumps(metadata or {}, ensure_ascii=False),
                        now,
                        now,
                    ),
                )
                conn.executemany(
                    """
                    INSERT INTO messages(
                        session_key,
                        user_id,
                        workspace_id,
                        task_id,
                        agent_id,
                        session_id,
                        message_json,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )

    def clear(self, agent_id: str, session_id: str) -> int:
        return self.clear_session_key(
            make_session_key(
                user_id="local-user",
                workspace_id="default-workspace",
                task_id=session_id,
                agent_id=agent_id,
                session_id=session_id,
            ),
            fallback_agent_id=agent_id,
            fallback_session_id=session_id,
        )

    def clear_session_key(
        self,
        session_key: str,
        fallback_agent_id: str | None = None,
        fallback_session_id: str | None = None,
    ) -> int:
        with self._lock:
            with self._connect() as conn:
                if fallback_agent_id and fallback_session_id:
                    cursor = conn.execute(
                        """
                        DELETE FROM messages
                        WHERE session_key = ?
                           OR (session_key IS NULL AND agent_id = ? AND session_id = ?)
                        """,
                        (session_key, fallback_agent_id, fallback_session_id),
                    )
                else:
                    cursor = conn.execute(
                        "DELETE FROM messages WHERE session_key = ?",
                        (session_key,),
                    )
                conn.execute("DELETE FROM sessions WHERE session_key = ?", (session_key,))
                return int(cursor.rowcount)

    def list_sessions(
        self,
        user_id: str | None = None,
        workspace_id: str | None = None,
        task_id: str | None = None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[str] = []
        if user_id:
            where.append("s.user_id = ?")
            params.append(user_id)
        if workspace_id:
            where.append("s.workspace_id = ?")
            params.append(workspace_id)
        if task_id:
            where.append("s.task_id = ?")
            params.append(task_id)

        query = """
            SELECT
                s.session_key,
                s.user_id,
                s.workspace_id,
                s.task_id,
                s.agent_id,
                s.session_id,
                s.title,
                COUNT(m.id) AS message_count,
                s.updated_at
            FROM sessions s
            LEFT JOIN messages m ON m.session_key = s.session_key
        """
        if where:
            query += " WHERE " + " AND ".join(where)
        query += """
            GROUP BY s.session_key
            ORDER BY s.updated_at DESC
        """

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "session_key": row[0],
                "user_id": row[1],
                "workspace_id": row[2],
                "task_id": row[3],
                "agent_id": row[4],
                "session_id": row[5],
                "title": row[6],
                "message_count": row[7],
                "updated_at": row[8],
            }
            for row in rows
        ]


def make_session_key(
    user_id: str,
    workspace_id: str,
    task_id: str,
    agent_id: str,
    session_id: str,
) -> str:
    return "\x1f".join([user_id, workspace_id, task_id, agent_id, session_id])


def _session_title(messages: list[dict[str, Any]]) -> str | None:
    for message in messages:
        if message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content[:120]
        if isinstance(content, list):
            text_parts = [
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]
            title = " ".join(part for part in text_parts if part).strip()
            if title:
                return title[:120]
    return None


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {
        row[1]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
