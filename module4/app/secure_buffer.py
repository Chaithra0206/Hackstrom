"""RAM-only mutable secure image buffer with explicit memory zeroing.

Security Constraints & Hard Rules:
- Image bytes are NEVER written to disk, SQLite, logs, temp files, or exceptions.
- Data is held in a mutable bytearray; immutable copies are strictly prohibited
  except inside use_for_model() during final dispatch.
- ctypes.memset is used to securely zero out RAM at the physical address.
- Every code path that touches image data must wipe it in a try/finally block.
"""

import ctypes
import hashlib
from typing import Any, Optional


class SecureImageBuffer:
    """Manages raw image bytes in a mutable bytearray with guaranteed RAM zeroing."""

    def __init__(self, raw_bytes: bytes) -> None:
        """Initialize buffer, compute SHA-256 digest once, and store data in bytearray.

        Args:
            raw_bytes: Raw uploaded image bytes. The local reference is dropped
                immediately after copying into the internal mutable bytearray.
        """
        hasher = hashlib.sha256()
        hasher.update(raw_bytes)
        self._sha256: str = hasher.hexdigest()
        self._length: int = len(raw_bytes)

        # Copy immediately into mutable bytearray
        self._buffer: Optional[bytearray] = bytearray(raw_bytes)
        # Drop local reference to input bytes
        del raw_bytes

        self._bytes_wiped: int = 0
        self._wipe_verified: bool = False
        self._is_wiped: bool = False
        self._active_views: list[memoryview] = []

    @property
    def sha256(self) -> str:
        """Return the hex SHA-256 digest of the image bytes."""
        return self._sha256

    @property
    def length(self) -> int:
        """Return the size of the image buffer in bytes."""
        return self._length

    @property
    def bytes_wiped(self) -> int:
        """Return the count of bytes successfully overwritten with zeroes."""
        return self._bytes_wiped

    @property
    def wipe_verified(self) -> bool:
        """Return True if RAM zeroing was verified before buffer release."""
        return self._wipe_verified

    @property
    def is_wiped(self) -> bool:
        """Return True if the buffer has been wiped."""
        return self._is_wiped

    def get_view(self) -> memoryview:
        """Return a read-only memoryview to inspect image bytes without copying.

        Returns:
            memoryview: Direct zero-copy view over the mutable bytearray.

        Raises:
            ValueError: If the buffer has already been wiped.
        """
        if self._is_wiped or self._buffer is None:
            raise ValueError("SecureImageBuffer has already been wiped from RAM.")
        view = memoryview(self._buffer).toreadonly()
        self._active_views.append(view)
        return view

    def use_for_model(self) -> bytes:
        """Return a short-lived immutable bytes copy strictly for AI model SDK dispatch.

        SECURITY WARNING:
        This immutable bytes copy represents the single unavoidable leak surface
        required by third-party AI SDK interfaces (google-genai and openai), which
        require immutable `bytes` for HTTP multipart/data payloads. In CPython,
        immutable bytes cannot be safely zeroed via ctypes.memset without risking
        memory corruption of shared byte singletons. Callers must drop references
        to the returned bytes object immediately after the SDK call finishes.

        Returns:
            bytes: Temporary immutable copy for SDK call.

        Raises:
            ValueError: If the buffer has already been wiped.
        """
        if self._is_wiped or self._buffer is None:
            raise ValueError("SecureImageBuffer has already been wiped from RAM.")
        return bytes(self._buffer)

    def wipe(self) -> None:
        """Overwrite buffer memory with 0x00 via ctypes.memset, verify, and clear.

        This method is idempotent and safe to call multiple times.
        """
        if self._is_wiped:
            return

        if self._buffer is not None:
            buf_len = len(self._buffer)
            if buf_len > 0:
                char_array_type = ctypes.c_char * buf_len
                c_array = char_array_type.from_buffer(self._buffer)
                ctypes.memset(ctypes.addressof(c_array), 0, buf_len)
                del c_array

                # Verify that every byte was zeroed BEFORE clearing
                self._wipe_verified = not any(self._buffer)
                self._bytes_wiped = buf_len
            else:
                self._wipe_verified = True
                self._bytes_wiped = 0

            # Release tracked internal memoryviews
            for view in self._active_views:
                try:
                    view.release()
                except (ValueError, BufferError):
                    pass
            self._active_views.clear()

            # Attempt buffer clear (suppress BufferError if external caller holds view)
            try:
                self._buffer.clear()
            except BufferError:
                pass
            self._buffer = None

        self._is_wiped = True

    def __enter__(self) -> "SecureImageBuffer":
        """Enter context manager."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        """Exit context manager, guaranteeing wipe() in a finally-equivalent path."""
        self.wipe()

    def __repr__(self) -> str:
        """Return safe string representation containing NO image data."""
        return (
            f"<SecureImageBuffer sha256={self._sha256} "
            f"length={self._length} wiped={self._is_wiped}>"
        )

    def __str__(self) -> str:
        """Return safe user-facing summary containing NO image data."""
        return (
            f"SecureImageBuffer(sha256={self._sha256}, "
            f"length={self._length}, wiped={self._is_wiped})"
        )
