"""In-memory session manager with TTL-based expiration and secure memory zeroing.

Security Guarantees:
- Active sessions hold images solely in SecureImageBuffer (RAM-only).
- No session images are ever written to disk or SQLite.
- Background cleanup task wipes expired buffers and logs 'ttl_expired_wipe' audit events.
"""

import asyncio
import time
from typing import Dict, List, Optional
from app.audit_log import audit_logger
from app.receipts import generate_receipt
from app.secure_buffer import SecureImageBuffer


class SessionEntry:
    """Represents an active in-memory session holding a SecureImageBuffer."""

    def __init__(
        self,
        session_id: str,
        buffer: SecureImageBuffer,
        task: str,
        ttl_seconds: int,
    ) -> None:
        """Initialize session entry.

        Args:
            session_id: Unique token identifier for the session.
            buffer: SecureImageBuffer instance storing raw pixels in RAM.
            task: User-specified prompt/task.
            ttl_seconds: Session lifespan in seconds.
        """
        self.session_id: str = session_id
        self.buffer: SecureImageBuffer = buffer
        self.task: str = task
        self.created_at: float = time.time()
        self.ttl_seconds: int = ttl_seconds
        self.image_sha256: str = buffer.sha256
        self.expires_at: float = self.created_at + ttl_seconds


class SessionManager:
    """Manages active image sessions with TTL tracking and automatic zeroing."""

    def __init__(self) -> None:
        """Initialize empty session registry."""
        self._sessions: Dict[str, SessionEntry] = {}

    def register_session(
        self,
        session_id: str,
        buffer: SecureImageBuffer,
        task: str,
        ttl_seconds: int,
    ) -> SessionEntry:
        """Register a new session in RAM.

        Args:
            session_id: Unique session token.
            buffer: Active SecureImageBuffer.
            task: Task instructions.
            ttl_seconds: Lifespan in seconds.

        Returns:
            SessionEntry: Registered session entry.
        """
        entry = SessionEntry(
            session_id=session_id,
            buffer=buffer,
            task=task,
            ttl_seconds=ttl_seconds,
        )
        self._sessions[session_id] = entry
        return entry

    def get_session(self, session_id: str) -> Optional[SessionEntry]:
        """Retrieve an active session by id, expiring it if TTL has elapsed.

        Args:
            session_id: Unique session identifier.

        Returns:
            Optional[SessionEntry]: The active session, or None if expired/not found.
        """
        entry = self._sessions.get(session_id)
        if entry is None:
            return None
        if time.time() >= entry.expires_at:
            self.expire_session(session_id)
            return None
        return entry

    def remove_session(self, session_id: str) -> Optional[SessionEntry]:
        """Remove a session from memory registry without auto-wiping (caller manages wipe).

        Args:
            session_id: Session identifier to remove.

        Returns:
            Optional[SessionEntry]: Removed session entry, or None.
        """
        return self._sessions.pop(session_id, None)

    def expire_session(self, session_id: str) -> Optional[SessionEntry]:
        """Wipe and remove an expired session from RAM and record audit log.

        Args:
            session_id: Session identifier to expire.

        Returns:
            Optional[SessionEntry]: The wiped session entry, if it existed.
        """
        entry = self._sessions.pop(session_id, None)
        if entry is not None:
            # Overwrite image bytes with 0x00 and verify
            entry.buffer.wipe()
            # Issue deletion receipt for expired session
            generate_receipt(
                session_id=session_id,
                image_sha256=entry.image_sha256,
                bytes_wiped=entry.buffer.bytes_wiped,
                wipe_verified=entry.buffer.wipe_verified,
                status="ttl_expired",
            )
            # Record audit event
            audit_logger.log_event(
                event_type="ttl_expired_wipe",
                session_id=session_id,
                image_sha256=entry.image_sha256,
                metadata={
                    "reason": "TTL expired",
                    "bytes_wiped": entry.buffer.bytes_wiped,
                    "wipe_verified": entry.buffer.wipe_verified,
                },
            )
        return entry

    def sweep_expired(self) -> int:
        """Sweep and wipe all sessions that have exceeded their TTL.

        Returns:
            int: Number of sessions wiped during this sweep.
        """
        now = time.time()
        expired_ids: List[str] = [
            sid for sid, entry in self._sessions.items() if now >= entry.expires_at
        ]
        count = 0
        for sid in expired_ids:
            if self.expire_session(sid) is not None:
                count += 1
        return count

    def wipe_all(self) -> None:
        """Wipe all active sessions immediately (used during application shutdown)."""
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self.expire_session(sid)

    async def run_ttl_cleanup_loop(self, check_interval_seconds: float = 1.0) -> None:
        """Background coroutine running continuously to wipe expired sessions.

        Args:
            check_interval_seconds: Frequency of expiration checks.
        """
        while True:
            try:
                await asyncio.sleep(check_interval_seconds)
                self.sweep_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                pass


# Global session manager instance
session_manager: SessionManager = SessionManager()
