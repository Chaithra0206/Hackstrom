"""API routes for receipt retrieval, receipt verification, and audit chain verification."""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Body, HTTPException, Query, status
from app.audit_log import audit_logger
from app.db import get_db_connection
from app.receipts import verify_receipt
from app.schemas import AuditEventItem, AuditVerifyResponse, ReceiptVerifyResponse

router = APIRouter(prefix="/v1", tags=["Receipts & Audit"])


@router.get(
    "/receipts/{session_id}",
    response_model=Dict[str, Any],
    summary="Get Deletion Receipt",
    description="Retrieve the cryptographically signed deletion receipt for a terminated session.",
)
async def get_receipt(session_id: str) -> Dict[str, Any]:
    """Retrieve deletion receipt by session ID.

    Args:
        session_id: Target session identifier.

    Returns:
        Dict[str, Any]: Signed deletion receipt.

    Raises:
        HTTPException: 404 if receipt does not exist.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT receipt_json FROM receipts WHERE session_id = ?;",
            (session_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Receipt not found for session '{session_id}'.",
            )
        return json.loads(row["receipt_json"])


@router.post(
    "/receipts/verify",
    response_model=ReceiptVerifyResponse,
    summary="Verify Deletion Receipt",
    description="Verify the HMAC-SHA256 signature and field integrity of a deletion receipt.",
)
async def verify_receipt_endpoint(
    receipt: Dict[str, Any] = Body(..., description="Full deletion receipt JSON object."),
) -> ReceiptVerifyResponse:
    """Validate receipt signature against canonical JSON reconstruction.

    Args:
        receipt: Signed receipt dictionary.

    Returns:
        ReceiptVerifyResponse: valid=True if signature matches; valid=False if forged/tampered.
    """
    is_valid = verify_receipt(receipt)
    return ReceiptVerifyResponse(valid=is_valid)


@router.get(
    "/audit",
    response_model=List[AuditEventItem],
    summary="Query Audit Events",
    description="Query hash-chained audit log events excluding sensitive image data and raw payloads.",
)
async def get_audit_log(
    session_id: Optional[str] = Query(None, description="Optional session ID filter."),
    limit: int = Query(50, ge=1, le=500, description="Max audit entries to retrieve."),
) -> List[AuditEventItem]:
    """Return redacted audit log records for verification.

    Args:
        session_id: Optional session filter.
        limit: Maximum number of events to return.

    Returns:
        List[AuditEventItem]: Audit entries containing chain hashes and structural metadata.
    """
    events = audit_logger.get_events(session_id=session_id, limit=limit)
    return [AuditEventItem(**e) for e in events]


@router.get(
    "/audit/verify",
    response_model=AuditVerifyResponse,
    summary="Verify Audit Hash Chain",
    description="Perform cryptographic verification across the entire audit log chain.",
)
async def verify_audit_chain() -> AuditVerifyResponse:
    """Verify hash chain integrity across all historical audit entries.

    Returns:
        AuditVerifyResponse: chain_intact=True if valid; first_broken_index if tampered.
    """
    broken_index = audit_logger.verify_chain()
    return AuditVerifyResponse(
        chain_intact=broken_index is None,
        first_broken_index=broken_index,
    )
