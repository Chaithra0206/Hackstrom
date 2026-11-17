"""Data validation schemas for Local Privacy Filter (Module 1)."""
from __future__ import annotations

from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class SanitizeRequest(BaseModel):
    """Payload for local sanitization."""
    image_base64: str = Field(..., description="Base64-encoded raw image bytes (JPEG, PNG, or WEBP)")
    blur_faces: bool = Field(default=True, description="Whether to redact detected faces")
    blur_strength: int = Field(default=51, description="Gaussian blur kernel size (odd integer >= 3)")
    redact_pii: bool = Field(default=True, description="Whether to run local OCR and mask sensitive PII")
    strip_metadata: bool = Field(default=True, description="Whether to strip EXIF, GPS, XMP, and ICC metadata")


class SanitizeAudit(BaseModel):
    """Audit report generated during in-memory sanitization."""
    exif_stripped: bool = Field(..., description="True if EXIF metadata was detected and stripped")
    gps_removed: bool = Field(..., description="True if GPS metadata (tag 0x8825) was detected and removed")
    faces_redacted: int = Field(..., description="Number of human faces detected and redacted")
    ids_redacted: List[str] = Field(default_factory=list, description="Categories of PII redacted (Aadhaar, PAN, Card, etc.)")
    detected_entities: List[str] = Field(default_factory=list, description="Labels of all redacted entities (e.g. FACE_1, AADHAAR)")
    stripped_metadata: Dict[str, str] = Field(default_factory=dict, description="Summary of stripped metadata tags and values")
    processing_time_ms: float = Field(..., description="Total pipeline execution latency in milliseconds")


class SanitizeResponse(BaseModel):
    """Sanitized image payload and audit report."""
    sanitized_image_base64: str = Field(..., description="Base64-encoded sanitized image bytes (clean PNG/JPEG)")
    audit: SanitizeAudit = Field(..., description="Structured sanitization audit report")
    status: str = Field(default="success", description="Execution status")
