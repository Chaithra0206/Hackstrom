"""Tamper-evident hash-chained audit logging.

Hash Chain Specification:
- Each entry's entry_hash = sha256(prev_hash + ts_utc + session_id + event_type + detail_json).
- The genesis entry (first entry in database) uses GENESIS_HASH.
- Subsequent entries strictly chain to the preceding row's entry_hash.
- verify_chain() validates the entire cryptographic chain and returns the index
  of the first broken entry, or None if the log is intact.

Security Guarantees:
- Raw image bytes are NEVER recorded in the audit log or database.
- Entries are immutable; any unauthorized alteration in SQLite breaks the chain.
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Union
from app.db import get_db_connection

# Fixed 64-character hex genesis hash for the audit chain
GENESIS_HASH: str = "0" * 64


class AuditLogger:
    """Manages appending and verifying hash-chained audit log records."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize audit logger with target SQLite database.

        Args:
            db_path: Optional SQLite database file path.
        """
        self._db_path: Optional[str] = db_path

    def append_event(
        self,
        session_id: str,
        event_type: str,
        detail: Union[str, Dict[str, Any]],
        image_sha256: Optional[str] = None,
        ts_utc: Optional[str] = None,
    ) -> str:
        """Append an event to the audit log linked via SHA-256 hash chaining.

        Args:
            session_id: Session identifier.
            event_type: Action or lifecycle identifier.
            detail: Metadata string or dictionary (must NEVER contain image bytes).
            image_sha256: Optional SHA-256 digest of the session image.
            ts_utc: Optional ISO timestamp override (defaults to current UTC time).

        Returns:
            str: Computed entry_hash for this audit row.
        """
        timestamp = ts_utc or datetime.now(timezone.utc).isoformat()

        if isinstance(detail, dict):
            detail_dict = dict(detail)
            if image_sha256 and "image_sha256" not in detail_dict:
                detail_dict["image_sha256"] = image_sha256
            detail_json = json.dumps(detail_dict, sort_keys=True, separators=(",", ":"))
        else:
            detail_json = str(detail)

        with get_db_connection(self._db_path) as conn:
            cursor = conn.cursor()
            # Fetch previous entry's hash in the same transaction to guarantee linear chain
            cursor.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1;")
            last_row = cursor.fetchone()
            prev_hash = str(last_row["entry_hash"]) if last_row and last_row["entry_hash"] else GENESIS_HASH

            # entry_hash = sha256(prev_hash + ts_utc + session_id + event_type + detail_json)
            payload = f"{prev_hash}{timestamp}{session_id}{event_type}{detail_json}".encode("utf-8")
            entry_hash = hashlib.sha256(payload).hexdigest()

            cursor.execute(
                """
                INSERT INTO audit_log (
                    ts_utc, session_id, event_type, detail_json, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (timestamp, session_id, event_type, detail_json, prev_hash, entry_hash),
            )

        return entry_hash

    def log_event(
        self,
        event_type: str,
        session_id: str,
        image_sha256: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Compatibility wrapper for appending audit events."""
        detail_data = metadata or {}
        return self.append_event(
            session_id=session_id,
            event_type=event_type,
            detail=detail_data,
            image_sha256=image_sha256,
        )

    def verify_chain(self) -> Optional[int]:
        """Verify the cryptographic integrity of the entire audit chain.

        Returns:
            Optional[int]: 0-based index of the first broken entry, or None if the chain is intact.
        """
        with get_db_connection(self._db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, ts_utc, session_id, event_type, detail_json, prev_hash, entry_hash
                FROM audit_log
                ORDER BY id ASC;
                """
            )
            rows = cursor.fetchall()

        expected_prev_hash = GENESIS_HASH

        for index, row in enumerate(rows):
            actual_prev_hash: str = row["prev_hash"]
            ts_utc: str = row["ts_utc"]
            session_id: str = row["session_id"]
            event_type: str = row["event_type"]
            detail_json: str = row["detail_json"]
            actual_entry_hash: str = row["entry_hash"]

            # 1. Verify link to previous hash
            if actual_prev_hash != expected_prev_hash:
                return index

            # 2. Recompute and verify entry_hash
            payload = f"{actual_prev_hash}{ts_utc}{session_id}{event_type}{detail_json}".encode("utf-8")
            computed_entry_hash = hashlib.sha256(payload).hexdigest()

            if actual_entry_hash != computed_entry_hash:
                return index

            expected_prev_hash = actual_entry_hash

        return None

    def get_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Fetch audit events excluding sensitive payload details.

        Args:
            session_id: Optional session filter.
            limit: Maximum count of rows to return.

        Returns:
            List[Dict[str, Any]]: Audit rows containing structural and verification metadata only.
        """
        with get_db_connection(self._db_path) as conn:
            cursor = conn.cursor()
            if session_id:
                cursor.execute(
                    """
                    SELECT id, ts_utc, session_id, event_type, prev_hash, entry_hash
                    FROM audit_log
                    WHERE session_id = ?
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (session_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, ts_utc, session_id, event_type, prev_hash, entry_hash
                    FROM audit_log
                    ORDER BY id DESC
                    LIMIT ?;
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "ts_utc": row["ts_utc"],
                "session_id": row["session_id"],
                "event_type": row["event_type"],
                "prev_hash": row["prev_hash"],
                "entry_hash": row["entry_hash"],
            }
            for row in rows
        ]


# Module-level audit logger instance
audit_logger: AuditLogger = AuditLogger()


def append_event(
    session_id: str,
    event_type: str,
    detail: Union[str, Dict[str, Any]],
    image_sha256: Optional[str] = None,
    ts_utc: Optional[str] = None,
    db_path: Optional[str] = None,
) -> str:
    """Convenience function to append an event to the audit log."""
    logger = AuditLogger(db_path=db_path) if db_path else audit_logger
    return logger.append_event(
        session_id=session_id,
        event_type=event_type,
        detail=detail,
        image_sha256=image_sha256,
        ts_utc=ts_utc,
    )


def verify_chain(db_path: Optional[str] = None) -> Optional[int]:
    """Convenience function to verify the hash chain integrity."""
    logger = AuditLogger(db_path=db_path) if db_path else audit_logger
    return logger.verify_chain()
