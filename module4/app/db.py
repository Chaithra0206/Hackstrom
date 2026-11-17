"""SQLite database manager and schema initialization for audit logging and receipts.

Privacy and Security Guarantees:
- Raw image bytes are NEVER persisted to SQLite.
- Only hashes, numeric metrics, timestamps, and JSON metadata are stored.
- SQLite WAL (Write-Ahead Logging) mode is enforced.
- All database interactions use strictly parameterized queries.
"""

from contextlib import contextmanager
import sqlite3
from typing import Generator, Optional


class DatabaseManager:
    """Manages SQLite database connections, lifecycle, and schema integrity."""

    def __init__(self, default_db_path: str = "module4.db") -> None:
        """Initialize database manager with default database path.

        Args:
            default_db_path: Default file path for the SQLite database.
        """
        self._default_db_path: str = default_db_path

    @property
    def default_db_path(self) -> str:
        """Return the default database path."""
        return self._default_db_path

    @contextmanager
    def get_connection(
        self, db_path: Optional[str] = None
    ) -> Generator[sqlite3.Connection, None, None]:
        """Context-manager helper yielding an active, WAL-enabled SQLite connection.

        Args:
            db_path: Optional custom path to SQLite database. Uses default_db_path if None.

        Yields:
            sqlite3.Connection: Active database connection with Row factory and WAL enabled.
        """
        target_path = db_path if db_path is not None else self._default_db_path
        conn = sqlite3.connect(target_path)
        conn.row_factory = sqlite3.Row
        # Enforce Write-Ahead Logging for concurrency and crash-resilience
        conn.execute("PRAGMA journal_mode = WAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# Module-level connection manager instance (only allowed global mutable state)
db_manager: DatabaseManager = DatabaseManager()


@contextmanager
def get_db_connection(
    db_path: Optional[str] = None,
) -> Generator[sqlite3.Connection, None, None]:
    """Provide a context-managed SQLite connection using the global manager.

    Args:
        db_path: Optional database path override.

    Yields:
        sqlite3.Connection: Transactional SQLite connection with WAL enabled.
    """
    with db_manager.get_connection(db_path=db_path) as conn:
        yield conn


def init_db(db_path: Optional[str] = None) -> None:
    """Create audit_log and receipts tables with strict privacy-preserving columns.

    Args:
        db_path: Optional target SQLite database file path.
    """
    with get_db_connection(db_path=db_path) as conn:
        cursor = conn.cursor()

        # Table 1: audit_log (tamper-evident hash-chained audit log)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """
        )

        # Table 2: receipts (cryptographic deletion receipts)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                session_id TEXT PRIMARY KEY,
                image_sha256 TEXT NOT NULL,
                bytes_wiped INTEGER NOT NULL,
                wipe_verified INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_utc TEXT NOT NULL,
                signature TEXT NOT NULL,
                receipt_json TEXT NOT NULL
            );
            """
        )
