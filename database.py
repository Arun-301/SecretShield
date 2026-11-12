
import sqlite3
import json
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent / "secretshield.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_path TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status TEXT NOT NULL,
            total_secrets INTEGER NOT NULL,
            findings_json TEXT NOT NULL DEFAULT '[]'
        )
    """)

    # Upgrade existing databases without deleting saved records.
    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(scan_history)"
        ).fetchall()
    }

    if "findings_json" not in columns:
        connection.execute("""
            ALTER TABLE scan_history
            ADD COLUMN findings_json TEXT NOT NULL DEFAULT '[]'
        """)

    connection.commit()
    connection.close()


def save_scan(
    project_path,
    scan_date,
    status,
    total_secrets,
    findings
):
    connection = get_connection()

    findings_json = json.dumps(findings)

    connection.execute(
        """
        INSERT INTO scan_history (
            project_path,
            scan_date,
            status,
            total_secrets,
            findings_json
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            project_path,
            scan_date,
            status,
            total_secrets,
            findings_json
        )
    )

    connection.commit()
    connection.close()


def get_all_scans():
    connection = get_connection()

    scans = connection.execute(
        """
        SELECT *
        FROM scan_history
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    results = []

    for scan in scans:
        record = dict(scan)

        record["findings"] = json.loads(
            record.pop("findings_json", "[]")
        )

        results.append(record)

    return results
