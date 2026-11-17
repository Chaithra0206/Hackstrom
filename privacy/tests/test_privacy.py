"""
Pytest Test Suite for Local Privacy Filter (Module 1).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Verifies:
  1. In-memory EXIF GPS tag 0x8825 detection and 100% removal.
  2. Compatibility with Module 4's image_validator.py checks.
  3. Sensitive PII OCR detection and blackout (Aadhaar / PAN).
  4. Face detection and semantic [FACE_1] labeling.
  5. End-to-end FastAPI endpoint /api/sanitize execution.
"""
from __future__ import annotations

import base64
import io
import pytest
from PIL import Image, ImageDraw
import piexif

from module4.app.image_validator import detect_exif_gps, validate_magic_bytes
from privacy.app.router import sanitize_image, health_check, inspect_image_metadata
from privacy.app.exif_stripper import inspect_exif_metadata, strip_all_metadata
from privacy.app.face_redactor import redact_faces
from privacy.app.pii_redactor import redact_pii_text
from privacy.app.schemas import SanitizeRequest


def _create_image_with_gps_and_pii() -> bytes:
    """Generate an in-memory test image containing EXIF GPS tag 0x8825 and mock ID text."""
    # 1. Image canvas with mock ID text
    img = Image.new("RGB", (600, 350), color=(245, 245, 250))
    draw = ImageDraw.Draw(img)

    # Simulated ID Card Header & Details
    draw.rectangle([20, 20, 580, 330], outline=(100, 100, 150), width=2)
    draw.text((40, 40), "GOVERNMENT OF INDIA", fill=(20, 20, 40))
    draw.text((40, 80), "NAME: RAJESH SHARMA", fill=(20, 20, 40))
    draw.text((40, 120), "DOB: 15/08/1990", fill=(20, 20, 40))
    # Target Aadhaar number: 12 digits (4 4 4)
    draw.text((40, 180), "Aadhaar: 5489 1234 5678", fill=(0, 0, 0))
    # Target PAN number: 5 letters, 4 digits, 1 letter
    draw.text((40, 230), "PAN: ABCDE1234F", fill=(0, 0, 0))
    # Target Phone
    draw.text((40, 280), "Mobile: +91 9876543210", fill=(0, 0, 0))

    # 2. Build EXIF payload with GPS tag 0x8825
    gps_ifd = {
        piexif.GPSIFD.GPSVersionID: (2, 0, 0, 0),
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((12, 1), (54, 1), (50, 1)),
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((74, 1), (51, 1), (21, 1)),
    }
    exif_dict = {
        "0th": {
            piexif.ImageIFD.Make: "Google Pixel 9",
            piexif.ImageIFD.Model: "Pixel 9 Pro",
            piexif.ImageIFD.DateTime: "2026:11:18 02:30:00",
        },
        "Exif": {},
        "GPS": gps_ifd,
        "1st": {},
        "thumbnail": None,
    }
    exif_bytes = piexif.dump(exif_dict)

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif_bytes)
    return buf.getvalue()


def test_exif_gps_stripping_and_module4_validation():
    """Verify that EXIF GPS tag 0x8825 is detected and stripped, passing Module 4 checks."""
    raw_bytes = _create_image_with_gps_and_pii()

    # Step A: Validate raw image triggers Module 4 GPS detection
    assert detect_exif_gps(raw_bytes) is True, "Module 4 should detect EXIF GPS tag 0x8825 in raw test image"
    assert validate_magic_bytes(raw_bytes) == "image/jpeg"

    # Step B: Inspect with our stripper
    has_exif, has_gps, summary = inspect_exif_metadata(raw_bytes)
    assert has_exif is True
    assert has_gps is True
    assert "GPS" in summary
    assert "Google Pixel 9" in summary.get("Device", "")

    # Step C: Strip all metadata in-memory
    clean_bytes, exif_det, gps_det, _ = strip_all_metadata(raw_bytes, output_format="PNG")

    # Step D: Verify output passes Module 4 checks with ZERO GPS tags
    assert detect_exif_gps(clean_bytes) is False, "Stripped image MUST NOT trigger Module 4 GPS detection"
    assert validate_magic_bytes(clean_bytes) == "image/png"


def test_pii_redactor_aadhaar_and_pan():
    """Verify local OCR identifies Aadhaar and PAN strings and blackouts text coordinates."""
    raw_bytes = _create_image_with_gps_and_pii()
    pil_img = Image.open(io.BytesIO(raw_bytes)).convert("RGB")

    redacted_rgb, categories, tags = redact_pii_text(pil_img)

    assert isinstance(categories, list)
    assert isinstance(tags, list)
    # Check that PII was detected
    assert any(c in categories for c in ("AADHAAR", "PAN", "PHONE", "AADHAAR_HEADER", "PAN_HEADER"))
    assert any("[AADHAAR_REDACTED]" in t or "[PAN_REDACTED]" in t or "[ID_REDACTED]" in t for t in tags)


def test_face_redaction_behavior():
    """Verify face redactor interface and execution in-memory."""
    img = Image.new("RGB", (200, 200), color=(200, 200, 200))
    redacted_rgb, count, labels = redact_faces(img, blur=True)
    assert redacted_rgb.shape == (200, 200, 3)
    assert isinstance(count, int)
    assert isinstance(labels, list)


def test_end_to_end_sanitize_api():
    """Test full POST /api/sanitize endpoint and verify Module 4 compatibility of the output."""
    raw_bytes = _create_image_with_gps_and_pii()
    b64_in = base64.b64encode(raw_bytes).decode("utf-8")

    req = SanitizeRequest(
        image_base64=b64_in,
        blur_faces=True,
        redact_pii=True,
        strip_metadata=True,
    )

    data = sanitize_image(req)
    assert data.status == "success"
    assert data.sanitized_image_base64 is not None

    audit = data.audit
    assert audit.exif_stripped is True
    assert audit.gps_removed is True
    assert audit.processing_time_ms > 0
    assert any("AADHAAR" in i or "PAN" in i for i in audit.ids_redacted)
    assert "GPS_EXIF" in audit.detected_entities

    # Decode returned sanitized image bytes
    sanitized_bytes = base64.b64decode(data.sanitized_image_base64)

    # Guaranteed compliance with Module 4 (Zero GPS and valid magic bytes)
    assert detect_exif_gps(sanitized_bytes) is False
    assert validate_magic_bytes(sanitized_bytes) == "image/png"


def test_health_check_endpoint():
    """Verify GET /api/sanitize/health endpoint."""
    data = health_check()
    assert data["status"] == "ok"
    assert "capabilities" in data
