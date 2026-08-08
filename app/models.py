"""SQLite helpers for recording toolkit usage statistics."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def init_db(database_path: str) -> None:
    """Create the usage table when the application starts."""
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()


def log_usage(database_path: str, tool_name: str, risk_score: int = 0) -> None:
    """Store an individual tool usage event."""
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO tool_usage (tool_name, risk_score, created_at) VALUES (?, ?, ?)",
            (tool_name, risk_score, datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()


def dashboard_metrics(database_path: str) -> dict:
    """Return aggregate usage metrics for the dashboard."""
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        usage_rows = connection.execute(
            "SELECT tool_name, COUNT(*) AS total FROM tool_usage GROUP BY tool_name ORDER BY total DESC"
        ).fetchall()
        risk_rows = connection.execute(
            "SELECT tool_name, AVG(risk_score) AS average_risk FROM tool_usage GROUP BY tool_name"
        ).fetchall()
        total = connection.execute("SELECT COUNT(*) AS total FROM tool_usage").fetchone()["total"]

    return {
        "usage": [dict(row) for row in usage_rows],
        "risk": [dict(row) for row in risk_rows],
        "total": total,
    }
