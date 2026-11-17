"""Upload and session initialization routes for Module 4.

Hard Privacy Rules:
- NEVER write image bytes to disk, logs, SQLite, temp files, or exception messages.
- Read uploaded file in chunks and abort immediately if exceeding MAX_IMAGE_MB.
- Validate magic bytes and reject unapproved formats.
- Scan and reject any image carrying EXIF GPS metadata with HTTP 422.
- In-memory data must be wiped inside try/finally blocks.
"""

import secrets
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from app.audit_log import audit_logger
from app.config import get_settings
from app.image_validator import detect_exif_gps, validate_magic_bytes
from app.schemas import SessionCreateResponse
from app.secure_buffer import SecureImageBuffer
from app.session_manager import session_manager

router = APIRouter(prefix="/v1", tags=["Sessions"])


@router.post(
    "/sessions",
    response_model=SessionCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create In-Memory Privacy Session",
    description=(
        "Upload a sanitized image and user task. Image is validated in memory, "
        "retained strictly in RAM inside a SecureImageBuffer, and assigned an expiration TTL."
    ),
)
async def create_session(
    file: UploadFile = File(..., description="Sanitized image file (JPEG, PNG, or WEBP)."),
    task: str = Form(..., description="Prompt or task instructions for downstream AI agent."),
) -> SessionCreateResponse:
    """Validate image payload entirely in RAM and initialize a secure session.

    Args:
        file: Uploaded image file stream.
        task: Processing instructions for the AI model.

    Returns:
        SessionCreateResponse: Session identifier, SHA-256 digest, and expiration TTL.

    Raises:
        HTTPException:
            - 400: If image is empty or magic bytes are invalid.
            - 413: If image size exceeds MAX_IMAGE_MB.
            - 422: If EXIF GPS metadata is detected.
    """
    settings = get_settings()
    chunk_size: int = 64 * 1024  # 64 KB streaming chunk
    max_bytes: int = settings.MAX_IMAGE_MB * 1024 * 1024

    raw_buf = bytearray()
    success = False

    try:
        total_read = 0
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Image size exceeds maximum limit of {settings.MAX_IMAGE_MB}MB.",
                )
            raw_buf.extend(chunk)

        if len(raw_buf) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded image is empty.",
            )

        # 1. Validate format using magic bytes
        validate_magic_bytes(raw_buf)

        # 2. Reject if EXIF GPS data is present
        if detect_exif_gps(raw_buf):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Image contains EXIF GPS metadata. Please run the local privacy filter first.",
            )

        # 3. Create cryptographically secure session ID
        session_id = secrets.token_urlsafe(16)

        # 4. Initialize SecureImageBuffer and wipe raw_buf immediately
        secure_buf = SecureImageBuffer(bytes(raw_buf))
        # Zero out the staging raw_buf now that SecureImageBuffer owns the mutable data
        for i in range(len(raw_buf)):
            raw_buf[i] = 0
        raw_buf.clear()

        # 5. Register in session manager
        session_manager.register_session(
            session_id=session_id,
            buffer=secure_buf,
            task=task,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )

        # 6. Audit logging (metadata only - NEVER image bytes)
        audit_logger.log_event(
            event_type="session_created",
            session_id=session_id,
            image_sha256=secure_buf.sha256,
            metadata={
                "task_length": len(task),
                "size_bytes": secure_buf.length,
                "ttl_seconds": settings.SESSION_TTL_SECONDS,
            },
        )

        success = True
        return SessionCreateResponse(
            session_id=session_id,
            image_sha256=secure_buf.sha256,
            expires_in=settings.SESSION_TTL_SECONDS,
        )

    finally:
        # Guarantee memory zeroing of staging buffer on any exception path
        if not success and len(raw_buf) > 0:
            for i in range(len(raw_buf)):
                raw_buf[i] = 0
            raw_buf.clear()
        await file.close()
