"""
In-Memory Face Detection and Redaction Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects human faces on CPU and applies configurable heavy Gaussian blur or blackout.
Overlays semantic badges ([FACE_1], [FACE_2], ...) to preserve scene context
for downstream multimodal AI models while removing biometric facial identity.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Tuple, List, Union, Optional
import cv2
import numpy as np
from PIL import Image

# Path to bundled local Haar Cascade asset
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
CASCADE_PATH = ASSETS_DIR / "haarcascade_frontalface_default.xml"

_face_cascade: Optional[cv2.CascadeClassifier] = None


def _get_cascade() -> Optional[cv2.CascadeClassifier]:
    """Initialize face cascade once at startup."""
    global _face_cascade
    if _face_cascade is not None:
        return _face_cascade

    if CASCADE_PATH.is_file():
        cascade = cv2.CascadeClassifier(str(CASCADE_PATH))
        if not cascade.empty():
            _face_cascade = cascade
            return _face_cascade

    # Fallback to cv2 data directory if available
    cv2_data_dir = getattr(cv2, "data", None)
    if cv2_data_dir and hasattr(cv2_data_dir, "haarcascades"):
        alt_path = Path(cv2.data.haarcascades) / "haarcascade_frontalface_default.xml"
        if alt_path.is_file():
            cascade = cv2.CascadeClassifier(str(alt_path))
            if not cascade.empty():
                _face_cascade = cascade
                return _face_cascade

    return None


def redact_faces(
    image_input: Union[bytes, np.ndarray, Image.Image],
    blur: bool = True,
    blur_strength: int = 51,
) -> Tuple[np.ndarray, int, List[str]]:
    """
    Detect faces in-memory and apply redaction with semantic tags.

    Args:
        image_input: Raw image bytes, RGB numpy array, or PIL Image.
        blur: If True, applies heavy Gaussian blur; if False, applies solid blackout.
        blur_strength: Blur kernel size (odd integer >= 25).

    Returns:
        (redacted_rgb_numpy_array, face_count, list_of_face_labels)
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
    cascade = _get_cascade()
    if cascade is None:
        return img_rgb, 0, []

    gray = cv2.cvtColor(img_rgb, cv2.COLOR_RGB2GRAY)
    # Detect faces
    faces = cascade.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=4,
        minSize=(28, 28),
    )

    face_count = len(faces)
    face_labels: List[str] = []

    # Sort faces left-to-right for deterministic labeling
    sorted_faces = sorted(faces, key=lambda f: f[0])

    for i, (fx, fy, fw, fh) in enumerate(sorted_faces):
        label = f"[FACE_{i + 1}]"
        face_labels.append(label)

        # Expand bounding box by 12% to cover entire face oval, hairline & chin
        pad_x = int(fw * 0.12)
        pad_y = int(fh * 0.15)
        x1 = max(0, fx - pad_x)
        y1 = max(0, fy - pad_y)
        x2 = min(w, fx + fw + pad_x)
        y2 = min(h, fy + fh + pad_y)

        roi = img_rgb[y1:y2, x1:x2]
        if roi.size == 0:
            continue

        if blur:
            # Heavy Gaussian blur with large kernel
            k = max(25, blur_strength if blur_strength % 2 == 1 else blur_strength + 1)
            # Clip k to roi dimensions
            max_k = min(roi.shape[0], roi.shape[1])
            if max_k % 2 == 0:
                max_k -= 1
            k = min(k, max(3, max_k))
            blurred_roi = cv2.GaussianBlur(roi, (k, k), 30)
            img_rgb[y1:y2, x1:x2] = blurred_roi
        else:
            # Solid blackout
            img_rgb[y1:y2, x1:x2] = (15, 23, 42)

        # Draw subtle border around redacted face
        cv2.rectangle(img_rgb, (x1, y1), (x2, y2), (56, 189, 248), 2)

        # Draw semantic label pill
        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = max(0.4, min(0.7, fw / 200.0))
        thickness = 1 if font_scale < 0.6 else 2
        (text_w, text_h), baseline = cv2.getTextSize(label, font, font_scale, thickness)

        badge_x1 = x1 + (x2 - x1 - text_w) // 2
        badge_y1 = y1 + (y2 - y1 - text_h) // 2 - 4
        badge_x2 = badge_x1 + text_w + 12
        badge_y2 = badge_y1 + text_h + 10

        # Clamp badge within image
        badge_x1 = max(0, min(w - text_w - 14, badge_x1))
        badge_x2 = min(w, badge_x1 + text_w + 12)
        badge_y1 = max(0, min(h - text_h - 12, badge_y1))
        badge_y2 = min(h, badge_y1 + text_h + 10)

        # Draw dark badge background with light border
        cv2.rectangle(img_rgb, (badge_x1, badge_y1), (badge_x2, badge_y2), (15, 23, 42), -1)
        cv2.rectangle(img_rgb, (badge_x1, badge_y1), (badge_x2, badge_y2), (239, 68, 68), 1)
        cv2.putText(
            img_rgb,
            label,
            (badge_x1 + 6, badge_y2 - 5),
            font,
            font_scale,
            (248, 250, 252),
            thickness,
            cv2.LINE_AA,
        )

    return img_rgb, face_count, face_labels
