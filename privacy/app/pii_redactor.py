"""
In-Memory Local OCR & Sensitive PII Redactor Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Uses RapidOCR (ONNX Runtime on CPU) initialized once at startup to detect text lines.
Applies regex pattern matching for Indian Aadhaar, PAN, Payment Cards, Phone, and Email.
Draws solid blackout redaction boxes with semantic label badges ([AADHAAR_REDACTED], etc.).
Operates strictly in memory with zero disk writes.
"""
from __future__ import annotations

import io
import re
from typing import Tuple, List, Dict, Optional, Union
import cv2
import numpy as np
from PIL import Image

# ── Regular Expression Matchers for Sensitive PII ──────────────────────────────
PII_PATTERNS = [
    # Aadhaar Number (12 digits, often grouped in 4-4-4)
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "AADHAAR", "[AADHAAR_REDACTED]"),
    # PAN Number (5 letters, 4 digits, 1 letter)
    (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE), "PAN", "[PAN_REDACTED]"),
    # Payment / Credit Card Numbers (13-16 digits)
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|(?:\d[ -]*?){13,16})\b"), "CARD", "[CARD_REDACTED]"),
    # Phone Numbers (Indian 10-digit mobile, optional +91)
    (re.compile(r"(?:\+91[\-\s]?)?[6-9]\d{9}\b"), "PHONE", "[PHONE_REDACTED]"),
    # Email Addresses
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "EMAIL", "[EMAIL_REDACTED]"),
]

_ocr_engine = None


def _get_ocr_engine():
    """Lazily load RapidOCR engine once on CPU."""
    global _ocr_engine
    if _ocr_engine is not None:
        return _ocr_engine

    try:
        from rapidocr_onnxruntime import RapidOCR
        _ocr_engine = RapidOCR()
        return _ocr_engine
    except Exception as e:
        print(f"[PII Redactor] Failed to initialize RapidOCR: {e}")
        return None


def redact_pii_text(
    image_input: Union[bytes, np.ndarray, Image.Image],
) -> Tuple[np.ndarray, List[str], List[str]]:
    """
    Scan image in memory for sensitive PII using local OCR and apply black redaction boxes.

    Args:
        image_input: Raw image bytes, RGB numpy array, or PIL Image.

    Returns:
        (redacted_rgb_numpy_array, ids_redacted_categories, detected_entity_tags)
    """
    # 1. Standardize to RGB numpy array
    if isinstance(image_input, bytes):
        pil_img = Image.open(io.BytesIO(image_input)).convert("RGB")
        img_rgb = np.array(pil_img)
    elif isinstance(image_input, Image.Image):
        img_rgb = np.array(image_input.convert("RGB"))
    else:
        img_rgb = image_input.copy()

    h, w = img_rgb.shape[:2]
    engine = _get_ocr_engine()
    if engine is None:
        return img_rgb, [], []

    # 2. Run OCR in-memory
    try:
        ocr_results, _ = engine(img_rgb)
    except Exception as e:
        print(f"[PII Redactor] OCR error during execution: {e}")
        return img_rgb, [], []

    if not ocr_results:
        return img_rgb, [], []

    categories_redacted: List[str] = []
    entity_tags: List[str] = []

    # 3. Match detected text blocks against PII patterns
    for item in ocr_results:
        # RapidOCR format: [box_points, text, confidence]
        box_points = item[0]
        text = str(item[1]).strip()
        confidence = float(item[2])

        if confidence < 0.3 or not text:
            continue

        matched_category: Optional[str] = None
        redaction_tag: Optional[str] = None

        for pattern, cat, tag in PII_PATTERNS:
            if pattern.search(text):
                matched_category = cat
                redaction_tag = tag
                break

        # Also check contextual triggers (e.g. text containing "Aadhaar", "Income Tax Dept", etc.)
        if not matched_category:
            lower = text.lower()
            if "aadhaar" in lower or "uidai" in lower:
                matched_category = "AADHAAR_HEADER"
                redaction_tag = "[ID_REDACTED]"
            elif "income tax" in lower or "permanent account" in lower:
                matched_category = "PAN_HEADER"
                redaction_tag = "[ID_REDACTED]"

        if matched_category and redaction_tag:
            if matched_category not in categories_redacted:
                categories_redacted.append(matched_category)
            if redaction_tag not in entity_tags:
                entity_tags.append(redaction_tag)

            # 4. Draw Blackout Redaction Box
            pts = np.array(box_points, dtype=np.int32)
            bx, by, bw, bh = cv2.boundingRect(pts)

            # Pad bounding box to ensure total coverage of text glyphs
            pad_x = 4
            pad_y = 4
            x1 = max(0, bx - pad_x)
            y1 = max(0, by - pad_y)
            x2 = min(w, bx + bw + pad_x)
            y2 = min(h, by + bh + pad_y)

            # Solid blackout fill
            cv2.rectangle(img_rgb, (x1, y1), (x2, y2), (0, 0, 0), -1)
            # High-visibility red/coral stroke
            cv2.rectangle(img_rgb, (x1, y1), (x2, y2), (239, 68, 68), 1)

            # Draw semantic redaction text inside the blackout box
            font = cv2.FONT_HERSHEY_SIMPLEX
            font_scale = max(0.3, min(0.55, bh / 32.0))
            thickness = 1
            (tw, th), _ = cv2.getTextSize(redaction_tag, font, font_scale, thickness)

            # Center text inside redaction bar
            tx = x1 + max(2, (x2 - x1 - tw) // 2)
            ty = y1 + (y2 - y1 + th) // 2

            cv2.putText(
                img_rgb,
                redaction_tag,
                (tx, ty),
                font,
                font_scale,
                (248, 113, 113),
                thickness,
                cv2.LINE_AA,
            )

    return img_rgb, categories_redacted, entity_tags
