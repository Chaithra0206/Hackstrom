"""Unit tests for SecureImageBuffer: RAM zeroing, exception cleanup, idempotency, and secrecy."""

import ctypes
import pytest
from app.secure_buffer import SecureImageBuffer


def test_wipe_zeroes_buffer_ctypes_view() -> None:
    """Verify that wipe() uses ctypes.memset to zero out RAM and records verification."""
    data = b"CONFIDENTIAL_IMAGE_BYTES_XYZ_987654321"
    buf = SecureImageBuffer(data)

    # Establish an external ctypes view referencing the raw buffer
    assert buf._buffer is not None
    char_array_type = ctypes.c_char * len(data)
    c_view = char_array_type.from_buffer(buf._buffer)

    # Verify content prior to wipe
    assert c_view.raw == data
    assert not buf.is_wiped
    assert not buf.wipe_verified

    # Trigger wipe
    buf.wipe()

    # Verify the underlying memory view is now zeroed
    assert c_view.raw == b"\x00" * len(data)
    assert buf.is_wiped is True
    assert buf.wipe_verified is True
    assert buf.bytes_wiped == len(data)

    # Subsequent access through SecureImageBuffer methods must fail
    with pytest.raises(ValueError, match="already been wiped"):
        buf.use_for_model()

    with pytest.raises(ValueError, match="already been wiped"):
        buf.get_view()


def test_wipe_happens_on_exception_in_with_block() -> None:
    """Verify that context manager __exit__ executes wipe() even if an exception occurs."""
    data = b"SENSITIVE_SESSION_PAYLOAD_TO_BE_WIPED"
    captured_buf: SecureImageBuffer | None = None

    with pytest.raises(RuntimeError, match="Simulated agent processing failure"):
        with SecureImageBuffer(data) as buf:
            captured_buf = buf
            assert not buf.is_wiped
            raise RuntimeError("Simulated agent processing failure")

    assert captured_buf is not None
    assert captured_buf.is_wiped is True
    assert captured_buf.wipe_verified is True
    assert captured_buf.bytes_wiped == len(data)


def test_wipe_is_idempotent() -> None:
    """Verify that calling wipe() multiple times is safe and maintains wiped metrics."""
    data = b"IDEMPOTENT_TEST_PAYLOAD"
    buf = SecureImageBuffer(data)

    buf.wipe()
    assert buf.is_wiped is True
    wiped_bytes = buf.bytes_wiped
    wiped_verified = buf.wipe_verified

    # Second and third calls must succeed with identical state
    buf.wipe()
    assert buf.is_wiped is True
    assert buf.bytes_wiped == wiped_bytes
    assert buf.wipe_verified == wiped_verified

    buf.wipe()
    assert buf.is_wiped is True
    assert buf.bytes_wiped == wiped_bytes
    assert buf.wipe_verified == wiped_verified


def test_repr_and_str_contain_no_image_data() -> None:
    """Verify that __repr__ and __str__ never expose raw image data or payloads."""
    secret_text = "SECRET_TOP_CONFIDENTIAL_PIXELS"
    raw_bytes = secret_text.encode("utf-8")
    buf = SecureImageBuffer(raw_bytes)

    repr_str = repr(buf)
    str_summary = str(buf)

    assert secret_text not in repr_str
    assert secret_text not in str_summary
    assert buf.sha256 in repr_str
    assert str(len(raw_bytes)) in repr_str

    buf.wipe()

    repr_wiped = repr(buf)
    str_wiped = str(buf)

    assert secret_text not in repr_wiped
    assert secret_text not in str_wiped
    assert "wiped=True" in repr_wiped
