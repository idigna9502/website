import os
import sqlite3
from typing import Any, Optional

import bcrypt


DB_PATH = os.environ.get("IDIGNA_DB_PATH") or os.path.join(
    os.path.dirname(__file__), "idigna.sqlite3"
)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sponsors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                plain_password TEXT NOT NULL,
                color TEXT NOT NULL,
                logo TEXT,
                message TEXT,
                type TEXT
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                date TEXT NOT NULL
            );
            """
        )


def get_sponsor_by_id(sponsor_id: str) -> Optional[sqlite3.Row]:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM sponsors WHERE id = ?", (sponsor_id,))
        return cur.fetchone()


def get_all_sponsors() -> list[sqlite3.Row]:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM sponsors ORDER BY name COLLATE NOCASE")
        return cur.fetchall()


def create_sponsor(
    sponsor_id: str,
    name: str,
    plain_password: str,
    color: str,
    logo: Optional[str],
    message: Optional[str],
    type: Optional[str],
) -> None:
    password_hash = bcrypt.hashpw(
        plain_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO sponsors (id, name, password_hash, plain_password, color, logo, message, type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (sponsor_id, name, password_hash, plain_password, color, logo, message, type),
        )


def update_sponsor(sponsor_id: str, **fields: Any) -> None:
    allowed = {"name", "color", "logo", "message", "type", "password_hash", "plain_password"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return

    with _connect() as conn:
        if "name" in updates:
            conn.execute("UPDATE sponsors SET name = ? WHERE id = ?", (updates["name"], sponsor_id))
        if "color" in updates:
            conn.execute("UPDATE sponsors SET color = ? WHERE id = ?", (updates["color"], sponsor_id))
        if "logo" in updates:
            conn.execute("UPDATE sponsors SET logo = ? WHERE id = ?", (updates["logo"], sponsor_id))
        if "message" in updates:
            conn.execute("UPDATE sponsors SET message = ? WHERE id = ?", (updates["message"], sponsor_id))
        if "type" in updates:
            conn.execute("UPDATE sponsors SET type = ? WHERE id = ?", (updates["type"], sponsor_id))
        if "password_hash" in updates:
            conn.execute(
                "UPDATE sponsors SET password_hash = ? WHERE id = ?",
                (updates["password_hash"], sponsor_id),
            )
        if "plain_password" in updates:
            conn.execute(
                "UPDATE sponsors SET plain_password = ? WHERE id = ?",
                (updates["plain_password"], sponsor_id),
            )


def delete_sponsor(sponsor_id: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM sponsors WHERE id = ?", (sponsor_id,))


def verify_sponsor_password(plain_password: str) -> Optional[sqlite3.Row]:
    if not plain_password:
        return None
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM sponsors")
        rows = cur.fetchall()
        for row in rows:
            try:
                if bcrypt.checkpw(
                    plain_password.encode("utf-8"), row["password_hash"].encode("utf-8")
                ):
                    return row
            except Exception:
                continue
    return None


def get_all_updates() -> list[sqlite3.Row]:
    with _connect() as conn:
        cur = conn.execute("SELECT * FROM updates ORDER BY date DESC, id DESC")
        return cur.fetchall()


def create_update(title: str, body: str, date: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO updates (title, body, date) VALUES (?, ?, ?)",
            (title, body, date),
        )


def delete_update(update_id: int) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM updates WHERE id = ?", (update_id,))
