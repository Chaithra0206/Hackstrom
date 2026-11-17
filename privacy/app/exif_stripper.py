"""
In-Memory EXIF & GPS Metadata Stripper
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Inspects incoming image bytes for sensitive metadata (specifically GPS tag 0x8825,
camera serials, and timestamps), then completely purges all metadata tags in-memory.
Ensures the output passes Module 4's image_validator.py without triggering HTTP 422.
"""
from __future__ import annotations

import io
from typing import Tuple, Dict, Any, Optional
from PIL import Image


# Well-known EXIF Tag IDs
TAG_MAKE = 0x010F
TAG_MODEL = 0x0110
TAG_SOFTWARE = 0x0131
TAG_DATETIME = 0x0132
TAG_ARTIST = 0x013B
TAG_COPYRIGHT = 0x8298
TAG_EXIF_IFD = 0x8769
TAG_GPS_IFD = 0x8825
TAG_DATETIME_ORIGINAL = 0x9003


def inspect_exif_metadata(image_bytes: bytes) -> Tuple[bool, bool, Dict[str, str]]:
    """
    Inspect raw image bytes for EXIF and GPS tags.

    Returns:
        (has_exif, has_gps, metadata_summary_dict)
    """
    has_exif = False
    has_gps = False
    summary: Dict[str, str] = {}

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            exif = img.getexif()
            if exif and len(exif) > 0:
                has_exif = True

                # Check GPS tag 0x8825
                if TAG_GPS_IFD in exif:
                    has_gps = True
                    gps_ifd = exif.get_ifd(TAG_GPS_IFD)
                    summary["GPS"] = f"Detected ({len(gps_ifd)} GPS tags present)"
                
                # Check Device tags
                make = exif.get(TAG_MAKE)
                model = exif.get(TAG_MODEL)
                if make or model:
                    device_str = " ".join(filter(None, [str(make).strip() if make else "", str(model).strip() if model else ""]))
                    summary["Device"] = device_str
                
                # Check Timestamp tags
                dt = exif.get(TAG_DATETIME) or exif.get(TAG_DATETIME_ORIGINAL)
                if dt:
                    summary["Timestamp"] = str(dt)

                # Check Software
                sw = exif.get(TAG_SOFTWARE)
                if sw:
                    summary["Software"] = str(sw)

            # Check XMP / ICC
            if img.info.get("xmp") or img.info.get("XML:com.adobe.xmp"):
                summary["XMP"] = "Adobe XMP metadata present"
                has_exif = True

            if img.info.get("icc_profile"):
                summary["ICC"] = "Color profile present"

            # Check PNG text comments
            if img.format == "PNG" and getattr(img, "text", None):
                summary["PNG_Text"] = f"{len(img.text)} text comment chunks"
                has_exif = True
    except Exception:
        pass

    # Secondary raw-byte inspection for GPS tag 0x8825 to ensure parity with module4
    if not has_gps:
        has_gps = _scan_raw_bytes_for_gps(image_bytes)
        if has_gps:
            summary["GPS"] = "Detected (Raw APP1/eXIf GPS Tag 0x8825)"
            has_exif = True

    return has_exif, has_gps, summary


def _scan_raw_bytes_for_gps(data: bytes) -> bool:
    """Scan raw TIFF segments in JPEG/PNG/WEBP bytes for tag 0x8825 (matching module4 image_validator)."""
    buf_len = len(data)
    if buf_len < 12:
        return False

    def check_tiff(tiff_data: bytes) -> bool:
        if len(tiff_data) < 8:
            return False
        endian = tiff_data[:2]
        if endian == b"II":
            byte_order = "little"
        elif endian == b"MM":
            byte_order = "big"
        else:
            return False
        if int.from_bytes(tiff_data[2:4], byte_order) != 42:
            return False
        ifd0_offset = int.from_bytes(tiff_data[4:8], byte_order)
        if ifd0_offset + 2 > len(tiff_data):
            return False
        num_entries = int.from_bytes(tiff_data[ifd0_offset : ifd0_offset + 2], byte_order)
        entry_offset = ifd0_offset + 2
        for i in range(num_entries):
            cur = entry_offset + (i * 12)
            if cur + 12 > len(tiff_data):
                break
            tag = int.from_bytes(tiff_data[cur : cur + 2], byte_order)
            if tag == TAG_GPS_IFD:
                return True
        return False

    # 1. JPEG APP1
    if data.startswith(b"\xff\xd8"):
        idx = 2
        while idx < buf_len - 4:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marker = data[idx + 1]
            if marker in (0xD9, 0xDA):
                break
            length = int.from_bytes(data[idx + 2 : idx + 4], "big")
            if marker == 0xE1:
                app1 = data[idx + 4 : idx + 2 + length]
                if app1.startswith(b"Exif\x00\x00") and check_tiff(app1[6:]):
                    return True
            idx += 2 + length

    # 2. PNG eXIf
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        idx = 8
        while idx + 8 <= buf_len:
            length = int.from_bytes(data[idx : idx + 4], "big")
            chunk_type = data[idx + 4 : idx + 8]
            start = idx + 8
            end = start + length
            if chunk_type == b"eXIf" and check_tiff(data[start:end]):
                return True
            idx = end + 4

    return False


def strip_all_metadata(
    image_bytes: bytes,
    output_format: str = "PNG",
) -> Tuple[bytes, bool, bool, Dict[str, str]]:
    """
    100% in-memory purge of all metadata (EXIF, GPS, XMP, ICC, text chunks).

    Re-rasterizes pure pixels into a brand-new image container.

    Args:
        image_bytes: Incoming image bytes.
        output_format: Output format ('PNG' or 'JPEG'). Default is 'PNG' for lossless clarity.

    Returns:
        (sanitized_bytes, exif_detected, gps_detected, metadata_summary)
    """
    has_exif, has_gps, summary = inspect_exif_metadata(image_bytes)

    with Image.open(io.BytesIO(image_bytes)) as img:
        target_mode = "RGB" if output_format.upper() in ("JPEG", "JPG") else img.mode
        if target_mode not in ("RGB", "RGBA"):
            target_mode = "RGB"

        converted = img.convert(target_mode)
        clean_img = Image.new(target_mode, converted.size)
        clean_img.paste(converted)

        out_buf = io.BytesIO()
        if output_format.upper() in ("JPEG", "JPG"):
            clean_img.save(out_buf, format="JPEG", quality=95)
        else:
            clean_img.save(out_buf, format="PNG")

        sanitized_bytes = out_buf.getvalue()

    return sanitized_bytes, has_exif, has_gps, summary
