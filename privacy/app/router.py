"""FastAPI Router for Local Privacy Filter (Module 1)."""
from __future__ import annotations

import base64
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from typing import Optional

from privacy.app.schemas import SanitizeRequest, SanitizeResponse
from privacy.app.pipeline import execute_sanitization_pipeline
from privacy.app.exif_stripper import inspect_exif_metadata

router = APIRouter(prefix="/api/sanitize", tags=["sanitize"])


@router.get("/health")
def health_check():
    """Service health and readiness check."""
    return {
        "status": "ok",
        "service": "Local Privacy Filter (Module 1)",
        "capabilities": [
            "exif_gps_stripping",
            "face_redaction_blur",
            "pii_ocr_redaction",
        ],
    }


@router.post("", response_model=SanitizeResponse)
def sanitize_image(request: SanitizeRequest):
    """
    Sanitize an uploaded image payload strictly in RAM.

    Purges EXIF/GPS tags (0x8825), blurs human faces with semantic tags ([FACE_1]),
    and blacks out sensitive IDs (Aadhaar, PAN, Cards, Phone, Email) with [ID_REDACTED].
    """
    try:
        return execute_sanitization_pipeline(request)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sanitization pipeline failure: {exc}",
        )


@router.post("/upload", response_model=SanitizeResponse)
async def sanitize_file_upload(
    file: UploadFile = File(...),
    blur_faces: bool = Form(True),
    redact_pii: bool = Form(True),
    strip_metadata: bool = Form(True),
):
    """Multipart file upload endpoint matching standard file form submissions."""
    try:
        raw_bytes = await file.read()
        b64_str = base64.b64encode(raw_bytes).decode("utf-8")
        req = SanitizeRequest(
            image_base64=b64_str,
            blur_faces=blur_faces,
            redact_pii=redact_pii,
            strip_metadata=strip_metadata,
        )
        return execute_sanitization_pipeline(req)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File sanitization failed: {exc}",
        )


@router.post("/inspect")
async def inspect_image_metadata(request: SanitizeRequest):
    """Inspect raw metadata without applying modifications."""
    try:
        raw_b64 = request.image_base64
        if "," in raw_b64:
            raw_b64 = raw_b64.split(",", 1)[1]
        raw_bytes = base64.b64decode(raw_b64)
        has_exif, has_gps, summary = inspect_exif_metadata(raw_bytes)
        return {
            "has_exif": has_exif,
            "has_gps": has_gps,
            "metadata_summary": summary,
            "module4_compatible": not has_gps,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to inspect metadata: {exc}",
        )
