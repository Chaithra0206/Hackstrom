"""Cryptographic deletion receipts, HMAC-SHA256 signing, and tamper-evident verification.

Security Guarantees:
- Receipt contains cryptographic hashes, wipe metrics, and metadata only. NEVER raw image bytes.
- Canonical JSON serialization (sorted keys, no whitespace separators) guarantees deterministic signing.
- Signature computed via HMAC-SHA256 and verified with constant-time hmac.compare_digest.
- The secret signing key is never exposed in receipts, database rows, or audit logs.

ASYMMETRIC VERIFICATION UPGRADE NOTE (Ed25519):
To allow external third parties to independently verify receipts without possessing the secret key:
1. Replace symmetric HMAC with Ed25519 asymmetric signatures (e.g. via standard cryptography.hazmat.primitives.asymmetric.ed25519).
2. Store the Ed25519 private key securely in a KMS/HSM and publish the public key at a well-known endpoint (e.g. GET /.well-known/jwks.json).
3. Sign canonical_json using private_key.sign(canonical_json.encode('utf-8')).
4. Third parties can verify the signature using only the public key: public_key.verify(signature_bytes, canonical_json.encode('utf-8')).
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Optional, Union
from app.audit_log import AuditLogger, audit_logger
from app.config import get_settings
from app.db import get_db_connection

LIMITATIONS_STATEMENT: str = (
    "Attests only that this gateway's in-memory copy was zero-filled. "
    "It cannot attest to retention by the third-party AI provider."
)


def canonicalise_json(data: Dict[str, Any]) -> str:
    """Format dictionary into canonical JSON string with sorted keys and no whitespace.

    Args:
        data: Key-value data to format.

    Returns:
        str: Deterministic canonical JSON string.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def generate_receipt(
    session_id: str,
    image_sha256: str,
    bytes_wiped: int,
    wipe_verified: bool,
    status: str,
    db_path: Optional[str] = None,
    signing_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Build, sign, store, and audit a cryptographic deletion receipt.

    Args:
        session_id: Unique session identifier.
        image_sha256: SHA-256 digest of the wiped image (hash only).
        bytes_wiped: Exact count of bytes zeroed via ctypes.memset.
        wipe_verified: Confirmation that every byte in RAM was verified to be 0x00.
        status: Operation status ("completed" | "blocked" | "error" | "ttl_expired").
        db_path: Optional target SQLite database override.
        signing_key: Optional custom signing key override.

    Returns:
        Dict[str, Any]: Signed deletion receipt payload.
    """
    valid_statuses = {"completed", "blocked", "error", "ttl_expired"}
    if status not in valid_statuses:
        status = "completed"

    key = signing_key or get_settings().RECEIPT_SIGNING_KEY
    receipt_id = f"rcpt_{secrets.token_urlsafe(16)}"
    issued_utc = datetime.now(timezone.utc).isoformat()

    # 1. Construct unsigned receipt payload
    unsigned_payload: Dict[str, Any] = {
        "bytes_wiped": bytes_wiped,
        "image_sha256": image_sha256,
        "issued_utc": issued_utc,
        "limitations": LIMITATIONS_STATEMENT,
        "receipt_id": receipt_id,
        "scope": "in_memory_gateway_destruction",
        "session_id": session_id,
        "status": status,
        "wipe_method": "bytearray ctypes.memset zero-fill",
        "wipe_verified": wipe_verified,
    }

    # 2. Canonicalise JSON and compute HMAC-SHA256 signature
    canonical_repr = canonicalise_json(unsigned_payload)
    signature = hmac.new(
        key.encode("utf-8"),
        canonical_repr.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # 3. Assemble complete signed receipt
    signed_receipt: Dict[str, Any] = dict(unsigned_payload)
    signed_receipt["signature"] = signature
    signed_receipt_json = canonicalise_json(signed_receipt)

    # 4. Store receipt in SQLite receipts table
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO receipts (
                session_id, image_sha256, bytes_wiped, wipe_verified, status, created_utc, signature, receipt_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                session_id,
                image_sha256,
                bytes_wiped,
                1 if wipe_verified else 0,
                status,
                issued_utc,
                signature,
                signed_receipt_json,
            ),
        )

    # 5. Write 'receipt_issued' audit event (NEVER include signing key or image bytes)
    logger = AuditLogger(db_path=db_path) if db_path else audit_logger
    logger.log_event(
        event_type="receipt_issued",
        session_id=session_id,
        image_sha256=image_sha256,
        metadata={
            "receipt_id": receipt_id,
            "signature": signature,
            "bytes_wiped": bytes_wiped,
            "wipe_verified": wipe_verified,
            "status": status,
        },
    )

    return signed_receipt


def verify_receipt(
    receipt_data: Union[str, Dict[str, Any]],
    signing_key: Optional[str] = None,
) -> bool:
    """Verify the authenticity and integrity of a signed deletion receipt.

    Args:
        receipt_data: JSON string or dictionary representation of the receipt.
        signing_key: Optional signing key override.

    Returns:
        bool: True if signature is valid and no fields were altered; False otherwise.
    """
    key = signing_key or get_settings().RECEIPT_SIGNING_KEY

    try:
        if isinstance(receipt_data, str):
            parsed: Dict[str, Any] = json.loads(receipt_data)
        elif isinstance(receipt_data, dict):
            parsed = dict(receipt_data)
        else:
            return False
    except Exception:
        return False

    if "signature" not in parsed:
        return False

    given_signature = parsed["signature"]
    if not isinstance(given_signature, str):
        return False

    # Extract all fields except 'signature' to reconstruct canonical payload
    unsigned_fields = {k: v for k, v in parsed.items() if k != "signature"}
    canonical_repr = canonicalise_json(unsigned_fields)

    expected_signature = hmac.new(
        key.encode("utf-8"),
        canonical_repr.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison preventing timing attacks
    return hmac.compare_digest(given_signature, expected_signature)


class ReceiptIssuer:
    """Helper class managing receipt issuance and verification."""

    def __init__(self, signing_key: Optional[str] = None) -> None:
        """Initialize ReceiptIssuer."""
        self._signing_key: Optional[str] = signing_key

    def issue_receipt(
        self,
        session_id: str,
        image_sha256: str,
        bytes_wiped: int,
        wipe_verified: bool,
        status: str = "completed",
    ) -> Dict[str, Any]:
        """Issue, sign, and store deletion receipt."""
        return generate_receipt(
            session_id=session_id,
            image_sha256=image_sha256,
            bytes_wiped=bytes_wiped,
            wipe_verified=wipe_verified,
            status=status,
            signing_key=self._signing_key,
        )

    def verify(self, receipt_data: Union[str, Dict[str, Any]]) -> bool:
        """Verify receipt authenticity."""
        return verify_receipt(receipt_data, signing_key=self._signing_key)


receipt_issuer: ReceiptIssuer = ReceiptIssuer()
