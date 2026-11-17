"""Unit and integration tests for POST /v1/sessions upload endpoint."""

import io
import time
from fastapi.testclient import TestClient
import pytest
from app.config import get_settings
from app.db import get_db_connection
from app.main import app
from app.session_manager import session_manager


@pytest.fixture
def client():
    """Fixture providing TestClient with active lifespan context."""
    with TestClient(app) as test_client:
        yield test_client


def make_clean_jpeg() -> bytes:
    """Construct a minimal valid JPEG without EXIF GPS metadata."""
    # SOI (FF D8) + APP0 JFIF (FF E0) + dummy scan payload + EOI (FF D9)
    app0_payload = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    app0_len = (len(app0_payload) + 2).to_bytes(2, "big")
    return b"\xff\xd8\xff\xe0" + app0_len + app0_payload + (b"\x12" * 128) + b"\xff\xd9"


def make_clean_png() -> bytes:
    """Construct minimal valid PNG magic bytes."""
    return b"\x89PNG\r\n\x1a\n" + (b"\x34" * 64)


def make_clean_webp() -> bytes:
    """Construct minimal valid WEBP magic bytes."""
    payload = b"VP8 \x08\x00\x00\x00\x30\x01\x00\x9d\x01\x2a\x08\x00"
    riff_header = b"RIFF" + (len(payload) + 4).to_bytes(4, "little") + b"WEBP"
    return riff_header + payload


def make_jpeg_with_exif_gps() -> bytes:
    """Construct a JPEG image carrying EXIF APP1 with a GPSInfo tag (0x8825)."""
    # TIFF header: Little-endian ('II'), Magic 42, IFD0 offset at 8
    tiff_header = b"II" + (42).to_bytes(2, "little") + (8).to_bytes(4, "little")
    # IFD0 with 1 entry: Tag 0x8825 (GPSInfo), Type 4 (LONG), Count 1, Offset 64
    ifd0_count = (1).to_bytes(2, "little")
    tag_gps = (0x8825).to_bytes(2, "little")
    type_long = (4).to_bytes(2, "little")
    count_1 = (1).to_bytes(4, "little")
    offset_val = (64).to_bytes(4, "little")
    ifd0_entry = tag_gps + type_long + count_1 + offset_val
    next_ifd = (0).to_bytes(4, "little")

    tiff_bytes = tiff_header + ifd0_count + ifd0_entry + next_ifd
    # Pad to offset 64 and add GPS sub-IFD
    tiff_bytes += b"\x00" * max(0, 64 - len(tiff_bytes))
    # GPS IFD: 1 entry
    tiff_bytes += (1).to_bytes(2, "little") + (0x0001).to_bytes(2, "little") + (2).to_bytes(2, "little") + (2).to_bytes(4, "little") + b"N\x00\x00\x00"

    app1_payload = b"Exif\x00\x00" + tiff_bytes
    app1_len = (len(app1_payload) + 2).to_bytes(2, "big")
    return b"\xff\xd8\xff\xe1" + app1_len + app1_payload + b"\xff\xd9"


def test_upload_valid_jpeg(client: TestClient) -> None:
    """Test successful session initialization with valid JPEG."""
    jpeg_bytes = make_clean_jpeg()
    response = client.post(
        "/v1/sessions",
        files={"file": ("test.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")},
        data={"task": "Describe the main object"},
    )

    assert response.status_code == 201
    body = response.json()
    assert "session_id" in body
    assert "image_sha256" in body
    assert body["expires_in"] == get_settings().SESSION_TTL_SECONDS

    # Verify session is retained in memory
    session = session_manager.get_session(body["session_id"])
    assert session is not None
    assert session.image_sha256 == body["image_sha256"]
    assert not session.buffer.is_wiped


def test_upload_valid_png(client: TestClient) -> None:
    """Test successful session initialization with valid PNG."""
    png_bytes = make_clean_png()
    response = client.post(
        "/v1/sessions",
        files={"file": ("photo.png", io.BytesIO(png_bytes), "image/png")},
        data={"task": "Detect objects"},
    )
    assert response.status_code == 201
    body = response.json()
    assert "session_id" in body
    assert "image_sha256" in body


def test_upload_valid_webp(client: TestClient) -> None:
    """Test successful session initialization with valid WEBP."""
    webp_bytes = make_clean_webp()
    response = client.post(
        "/v1/sessions",
        files={"file": ("image.webp", io.BytesIO(webp_bytes), "image/webp")},
        data={"task": "Extract text"},
    )
    assert response.status_code == 201
    body = response.json()
    assert "session_id" in body


def test_reject_invalid_magic_bytes(client: TestClient) -> None:
    """Test rejection when magic bytes do not match JPEG, PNG, or WEBP."""
    fake_content = b"%PDF-1.4 header and some text posing as image"
    response = client.post(
        "/v1/sessions",
        files={"file": ("fake.jpg", io.BytesIO(fake_content), "image/jpeg")},
        data={"task": "Summarize"},
    )
    assert response.status_code == 400
    assert "Invalid image format" in response.json()["detail"]


def test_reject_exif_gps_metadata(client: TestClient) -> None:
    """Test HTTP 422 rejection when image contains EXIF GPS data."""
    gps_jpeg = make_jpeg_with_exif_gps()
    response = client.post(
        "/v1/sessions",
        files={"file": ("unfiltered.jpg", io.BytesIO(gps_jpeg), "image/jpeg")},
        data={"task": "Analyze photo"},
    )
    assert response.status_code == 422
    assert "Image contains EXIF GPS metadata" in response.json()["detail"]
    assert "local privacy filter" in response.json()["detail"]


def test_reject_size_exceeding_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test rejection when image exceeds MAX_IMAGE_MB limit."""
    settings = get_settings()
    # Set MAX_IMAGE_MB to 1 for this test
    monkeypatch.setattr(settings, "MAX_IMAGE_MB", 1)

    # 1.5 MB payload with JPEG header
    oversized_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"X" * (1500 * 1024))
    response = client.post(
        "/v1/sessions",
        files={"file": ("large.jpg", io.BytesIO(oversized_data), "image/jpeg")},
        data={"task": "Analyze large image"},
    )
    assert response.status_code == 413
    assert "exceeds maximum limit" in response.json()["detail"]


def test_ttl_expiration_wiping_and_audit_event(client: TestClient) -> None:
    """Test that expired sessions are wiped from RAM and write a ttl_expired_wipe audit record."""
    jpeg_bytes = make_clean_jpeg()
    response = client.post(
        "/v1/sessions",
        files={"file": ("quick.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")},
        data={"task": "Fast test"},
    )
    assert response.status_code == 201
    sid = response.json()["session_id"]

    # Retrieve session and artificially backdate created_at to trigger expiration
    session = session_manager._sessions.get(sid)
    assert session is not None
    session.expires_at = time.time() - 1.0  # Already expired

    # Run sweep
    wiped_count = session_manager.sweep_expired()
    assert wiped_count >= 1

    # Buffer must be wiped
    assert sid not in session_manager._sessions
    assert session.buffer.is_wiped is True
    assert session.buffer.wipe_verified is True

    # Check audit log in SQLite
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_log WHERE session_id = ? AND event_type = ?;",
            (sid, "ttl_expired_wipe"),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["session_id"] == sid
        assert row["event_type"] == "ttl_expired_wipe"
        assert row["prev_hash"] is not None
        assert row["entry_hash"] is not None
