"""
Sanitization Pipeline Coordinator
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Coordinates the full in-memory sanitization workflow:
  1. Base64 / Byte Ingestion & Magic Byte Verification
  2. In-Memory EXIF & GPS Metadata Purge
  3. CPU Face Detection & Context-Preserving Redaction ([FACE_1], ...)
  4. Local OCR PII Masking ([AADHAAR_REDACTED], [PAN_REDACTED], ...)
  5. Clean Re-Rasterization (PNG/JPEG) with Zero Disk Writes
"""
from __future__ import annotations

import base64
import io
import time
from typing import Tuple, Dict, Any, Optional
import numpy as np
from PIL import Image

from privacy.app.schemas import SanitizeRequest, SanitizeResponse, SanitizeAudit
from privacy.app.exif_stripper import strip_all_metadata
from privacy.app.face_redactor import redact_faces
from privacy.app.pii_redactor import redact_pii_text


def _clean_base64_payload(raw_b64: str) -> bytes:
    """Decode input base64 string, handling data URL prefixes if present."""
    trimmed = raw_b64.strip()
    if "," in trimmed and (trimmed.startswith("data:") or "base64," in trimmed):
        trimmed = trimmed.split(",", 1)[1]
    return base64.b64decode(trimmed)


def execute_sanitization_pipeline(
    request: SanitizeRequest,
) -> SanitizeResponse:
    """
    Execute end-to-end sanitization pipeline strictly in RAM.

    Args:
        request: Validated SanitizeRequest containing base64 image data.

    Returns:
        SanitizeResponse with clean image base64 and structured audit.
    """
    start_time = time.perf_counter()

    # 1. Decode raw bytes in-memory
    raw_bytes = _clean_base64_payload(request.image_base64)
    if len(raw_bytes) < 12:
        raise ValueError("Image payload too small to be a valid image file.")

    # 2. In-memory Metadata Stripping (EXIF, GPS tag 0x8825, XMP, ICC)
    if request.strip_metadata:
        sanitized_bytes, exif_detected, gps_detected, metadata_summary = strip_all_metadata(
            raw_bytes, output_format="PNG"
        )
    else:
        sanitized_bytes = raw_bytes
        exif_detected, gps_detected, metadata_summary = False, False, {}

    # Load clean pixels to RGB numpy array
    pil_img = Image.open(io.BytesIO(sanitized_bytes)).convert("RGB")
    current_rgb = np.array(pil_img)

    # 3. Face Detection & Redaction
    face_count = 0
    face_labels: list[str] = []
    if request.blur_faces:
        current_rgb, face_count, face_labels = redact_faces(
            current_rgb,
            blur=True,
            blur_strength=request.blur_strength,
        )

    # 4. Sensitive PII OCR & Masking (Aadhaar, PAN, Cards, Phone, Email)
    categories_redacted: list[str] = []
    pii_labels: list[str] = []
    if request.redact_pii:
        current_rgb, categories_redacted, pii_labels = redact_pii_text(current_rgb)

    # 5. Final in-memory render to clean PNG bytes
    out_buf = io.BytesIO()
    final_pil = Image.fromarray(current_rgb)
    final_pil.save(out_buf, format="PNG")
    clean_output_bytes = out_buf.getvalue()

    # 6. Build audit report
    elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
    detected_entities = list(face_labels)
    for pii in pii_labels:
        if pii not in detected_entities:
            detected_entities.append(pii)
    if gps_detected and "GPS_EXIF" not in detected_entities:
        detected_entities.append("GPS_EXIF")

    audit = SanitizeAudit(
        exif_stripped=exif_detected,
        gps_removed=gps_detected,
        faces_redacted=face_count,
        ids_redacted=categories_redacted,
        detected_entities=detected_entities,
        stripped_metadata=metadata_summary,
        processing_time_ms=elapsed_ms,
    )

    out_b64 = base64.b64encode(clean_output_bytes).decode("utf-8")

    return SanitizeResponse(
        sanitized_image_base64=out_b64,
        audit=audit,
        status="success",
    )
