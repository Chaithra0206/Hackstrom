"""In-memory image format and EXIF GPS metadata validator.

Security Guarantees:
- Validation is performed entirely in memory on raw byte sequences.
- No files are written to disk.
- EXIF tags are scanned directly without executing untrusted external binary parsers.
"""

from typing import Union
from fastapi import HTTPException, status

BufferType = Union[bytes, bytearray, memoryview]


def validate_magic_bytes(data: BufferType) -> str:
    """Validate magic bytes for JPEG, PNG, and WEBP formats.

    Args:
        data: In-memory image buffer.

    Returns:
        str: Detected MIME type.

    Raises:
        HTTPException: 400 Bad Request if the format is unsupported or invalid.
    """
    if len(data) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File too small to be a valid image.",
        )

    # JPEG: starts with FF D8 FF
    if data[0:3] == b"\xff\xd8\xff":
        return "image/jpeg"

    # PNG: starts with 89 50 4E 47 0D 0A 1A 0A
    if data[0:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"

    # WEBP: starts with 'RIFF' .... 'WEBP'
    if data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid image format. Only JPEG, PNG, and WEBP are supported.",
    )


def _check_tiff_for_gps(tiff_data: BufferType) -> bool:
    """Parse a raw TIFF byte segment to detect the presence of the GPSInfo tag (0x8825).

    Args:
        tiff_data: TIFF structure bytes.

    Returns:
        bool: True if GPS metadata (tag 0x8825) is detected, False otherwise.
    """
    if len(tiff_data) < 8:
        return False

    endian_marker = bytes(tiff_data[:2])
    if endian_marker == b"II":
        byte_order = "little"
    elif endian_marker == b"MM":
        byte_order = "big"
    else:
        return False

    # Verify TIFF magic 42
    magic_42 = int.from_bytes(tiff_data[2:4], byte_order)
    if magic_42 != 42:
        return False

    ifd0_offset = int.from_bytes(tiff_data[4:8], byte_order)
    if ifd0_offset + 2 > len(tiff_data):
        return False

    num_entries = int.from_bytes(tiff_data[ifd0_offset : ifd0_offset + 2], byte_order)
    entry_offset = ifd0_offset + 2

    # Each IFD entry is 12 bytes
    for i in range(num_entries):
        current = entry_offset + (i * 12)
        if current + 12 > len(tiff_data):
            break
        tag = int.from_bytes(tiff_data[current : current + 2], byte_order)
        # Tag 0x8825 is GPSInfo
        if tag == 0x8825:
            return True

    return False


def detect_exif_gps(data: BufferType) -> bool:
    """Scan in-memory image bytes for EXIF GPS metadata without disk writes.

    Args:
        data: In-memory image buffer.

    Returns:
        bool: True if GPS metadata was detected, False otherwise.
    """
    buf_len = len(data)

    # 1. Check JPEG APP1 Marker (FF E1)
    if buf_len >= 4 and data[0:2] == b"\xff\xd8":
        idx = 2
        while idx < buf_len - 4:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marker = data[idx + 1]
            if marker in (0xD9, 0xDA):  # EOI (End of Image) or SOS (Start of Scan)
                break
            if idx + 4 > buf_len:
                break
            length = int.from_bytes(data[idx + 2 : idx + 4], "big")
            if marker == 0xE1:  # APP1
                app1_content = data[idx + 4 : idx + 2 + length]
                if app1_content.startswith(b"Exif\x00\x00"):
                    tiff_payload = app1_content[6:]
                    if _check_tiff_for_gps(tiff_payload):
                        return True
            idx += 2 + length

    # 2. Check PNG eXIf chunk
    if buf_len >= 8 and data[0:8] == b"\x89PNG\r\n\x1a\n":
        idx = 8
        while idx + 8 <= buf_len:
            chunk_len = int.from_bytes(data[idx : idx + 4], "big")
            chunk_type = bytes(data[idx + 4 : idx + 8])
            chunk_data_start = idx + 8
            chunk_data_end = chunk_data_start + chunk_len
            if chunk_data_end > buf_len:
                break
            if chunk_type == b"eXIf":
                if _check_tiff_for_gps(data[chunk_data_start:chunk_data_end]):
                    return True
            # Advance past length, type, data, and 4-byte CRC
            idx = chunk_data_end + 4

    # 3. Check WEBP EXIF chunk
    if buf_len >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        idx = 12
        while idx + 8 <= buf_len:
            fourcc = bytes(data[idx : idx + 4])
            chunk_size = int.from_bytes(data[idx + 4 : idx + 8], "little")
            chunk_data_start = idx + 8
            chunk_data_end = chunk_data_start + chunk_size
            if chunk_data_end > buf_len:
                break
            if fourcc == b"EXIF":
                raw_exif = data[chunk_data_start:chunk_data_end]
                # Some WEBP EXIF chunks start with 'Exif\x00\x00'
                if raw_exif.startswith(b"Exif\x00\x00"):
                    raw_exif = raw_exif[6:]
                if _check_tiff_for_gps(raw_exif):
                    return True
            # Chunks in RIFF are padded to even sizes
            idx = chunk_data_end + (chunk_size % 2)

    return False
