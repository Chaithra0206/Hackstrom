"""Unit tests for database initialization, schema integrity, and security constraints."""

from pathlib import Path
import sqlite3
import pytest
from app.db import get_db_connection, init_db


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Fixture providing a temporary SQLite database path."""
    db_file = tmp_path / "test_module4.db"
    return str(db_file)


def test_schema_no_blob_columns(temp_db: str) -> None:
    """Verify that neither audit_log nor receipts contains BLOB or binary storage columns.

    Enforces the privacy rule: raw image bytes must NEVER be stored in the database.
    """
    init_db(temp_db)

    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()

        for table_name in ("audit_log", "receipts"):
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            assert len(columns) > 0, f"Table {table_name} must have columns"

            for col in columns:
                col_name: str = col["name"]
                col_type: str = col["type"].upper()

                # Fail if column type allows binary image payload
                assert "BLOB" not in col_type, (
                    f"Forbidden BLOB column detected: {table_name}.{col_name} (type: {col_type})"
                )
                assert "BINARY" not in col_type, (
                    f"Forbidden BINARY column detected: {table_name}.{col_name} (type: {col_type})"
                )


def test_wal_mode_enabled(temp_db: str) -> None:
    """Verify that Write-Ahead Logging (WAL) mode is active on file connections."""
    init_db(temp_db)

    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert str(mode).lower() == "wal"


def test_parameterized_audit_log_insert(temp_db: str) -> None:
    """Verify parameterized insertion into the audit_log table."""
    init_db(temp_db)

    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log (
                ts_utc, session_id, event_type, detail_json, prev_hash, entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                "2026-11-17T18:00:00Z",
                "sess_abc123",
                "IMAGE_INGESTED",
                '{"size_bytes": 1024}',
                "GENESIS",
                "hash_entry_1",
            ),
        )

        cursor.execute(
            "SELECT * FROM audit_log WHERE session_id = ?;",
            ("sess_abc123",),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["session_id"] == "sess_abc123"
        assert row["event_type"] == "IMAGE_INGESTED"
        assert row["prev_hash"] == "GENESIS"
        assert row["entry_hash"] == "hash_entry_1"


def test_parameterized_receipts_insert(temp_db: str) -> None:
    """Verify parameterized insertion into the receipts table."""
    init_db(temp_db)

    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO receipts (
                session_id, image_sha256, bytes_wiped, wipe_verified, status, created_utc, signature, receipt_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                "sess_xyz789",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                2048,
                1,
                "WIPED",
                "2026-11-17T18:00:00Z",
                "hmac_signature_sample",
                '{"wiped": true}',
            ),
        )

        cursor.execute(
            "SELECT * FROM receipts WHERE session_id = ?;",
            ("sess_xyz789",),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["session_id"] == "sess_xyz789"
        assert row["bytes_wiped"] == 2048
        assert row["wipe_verified"] == 1
        assert row["status"] == "WIPED"


def test_transaction_rollback_on_error(temp_db: str) -> None:
    """Verify that get_db_connection rolls back transactions when an unhandled exception occurs."""
    init_db(temp_db)

    with pytest.raises(RuntimeError):
        with get_db_connection(temp_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (
                    ts_utc, session_id, event_type, detail_json, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                ("2026-11-17T18:00:00Z", "sess_err", "TEST", "{}", "0", "1"),
            )
            raise RuntimeError("Intentional error to trigger rollback")

    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM audit_log WHERE session_id = ?;", ("sess_err",))
        assert cursor.fetchone()["total"] == 0
