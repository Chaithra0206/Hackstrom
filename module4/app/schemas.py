"""Pydantic schemas and data transfer models for Module 4.

Includes comprehensive OpenAPI schema examples and documentation for inter-module integration.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: str = Field(default="ok", description="Operational status of the service.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"status": "ok"}]
        }
    }


class SessionCreateResponse(BaseModel):
    """Response returned upon successful image session creation."""

    session_id: str = Field(
        description="Cryptographically random session token (URL-safe, 16 bytes).",
        examples=["w9Z7B8qR3vT1mK4L7nQ2zA"],
    )
    image_sha256: str = Field(
        description="SHA-256 hex digest of the validated in-memory image.",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    expires_in: int = Field(
        description="Remaining session lifespan in seconds before forced memory wipe.",
        examples=[120],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
                    "image_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "expires_in": 120,
                }
            ]
        }
    }


class SessionRunRequest(BaseModel):
    """Request payload for executing an AI task on a session image."""

    provider: str = Field(
        default="gemini",
        pattern="^(gemini|openai)$",
        description="Target AI provider ('gemini' or 'openai').",
        examples=["gemini"],
    )
    task_override: Optional[str] = Field(
        default=None,
        description="Optional override task prompt. If omitted, the session's initial task is used.",
        examples=["Identify key architectural features in this sanitized photo."],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "provider": "gemini",
                    "task_override": "Identify key architectural features in this sanitized photo.",
                }
            ]
        }
    }


class SessionRunResponse(BaseModel):
    """Response payload returned upon completing an AI session task."""

    session_id: str = Field(
        description="Session identifier.",
        examples=["w9Z7B8qR3vT1mK4L7nQ2zA"],
    )
    receipt_id: str = Field(
        description="Identifier for the signed deletion receipt stored in the database.",
        examples=["rcpt_V8xK9mP2L5nQ4tW7rY1zA_"],
    )
    answer: str = Field(
        description="Firewalled textual answer from the AI model.",
        examples=["The image depicts a stone archway with classical columns."],
    )
    tool_calls: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Executed allowlisted tool calls and results.",
        examples=[[{"name": "describe_image", "args": {"focus": "columns"}, "result": {"status": "ok"}}]],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
                    "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
                    "answer": "The image depicts a stone archway with classical columns.",
                    "tool_calls": [],
                }
            ]
        }
    }


class DeletionReceipt(BaseModel):
    """Cryptographically signed deletion receipt schema."""

    receipt_id: str = Field(description="Unique receipt identifier.", examples=["rcpt_V8xK9mP2L5nQ4tW7rY1zA_"])
    session_id: str = Field(description="Associated session ID.", examples=["w9Z7B8qR3vT1mK4L7nQ2zA"])
    image_sha256: str = Field(
        description="SHA-256 digest of wiped image data.",
        examples=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )
    bytes_wiped: int = Field(description="Total bytes zero-filled via ctypes.memset.", examples=[2048])
    wipe_method: str = Field(
        default="bytearray ctypes.memset zero-fill",
        description="Memory eradication technique.",
    )
    wipe_verified: bool = Field(description="Confirmation of 0x00 memory verification.", examples=[True])
    status: str = Field(
        description="Execution status ('completed' | 'blocked' | 'error' | 'ttl_expired').",
        examples=["completed"],
    )
    issued_utc: str = Field(description="ISO 8601 UTC timestamp of deletion.", examples=["2026-11-18T00:00:00.000000+00:00"])
    scope: str = Field(default="in_memory_gateway_destruction", description="Scope of receipt.")
    limitations: str = Field(
        default="Attests only that this gateway's in-memory copy was zero-filled. It cannot attest to retention by the third-party AI provider.",
        description="Explicit limitation disclaimer.",
    )
    signature: str = Field(
        description="HMAC-SHA256 signature over canonicalized receipt JSON.",
        examples=["8f56a312bc815b39e2467d363b925bdfa91b2df9cc01a3cfb578c736e4f323a1"],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "receipt_id": "rcpt_V8xK9mP2L5nQ4tW7rY1zA_",
                    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
                    "image_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "bytes_wiped": 2048,
                    "wipe_method": "bytearray ctypes.memset zero-fill",
                    "wipe_verified": True,
                    "status": "completed",
                    "issued_utc": "2026-11-18T00:00:00.000000+00:00",
                    "scope": "in_memory_gateway_destruction",
                    "limitations": "Attests only that this gateway's in-memory copy was zero-filled. It cannot attest to retention by the third-party AI provider.",
                    "signature": "8f56a312bc815b39e2467d363b925bdfa91b2df9cc01a3cfb578c736e4f323a1",
                }
            ]
        }
    }


class ReceiptVerifyResponse(BaseModel):
    """Verification response for a deletion receipt."""

    valid: bool = Field(description="True if HMAC-SHA256 signature is authentic and unaltered.", examples=[True])

    model_config = {
        "json_schema_extra": {
            "examples": [{"valid": True}]
        }
    }


class AuditEventItem(BaseModel):
    """Redacted audit log event item excluding sensitive image payload details."""

    id: int = Field(description="Auto-incremented primary key.", examples=[42])
    ts_utc: str = Field(description="UTC timestamp of the logged event.", examples=["2026-11-18T00:00:00.000000+00:00"])
    session_id: str = Field(description="Session identifier.", examples=["w9Z7B8qR3vT1mK4L7nQ2zA"])
    event_type: str = Field(description="Audit lifecycle event type.", examples=["image_wiped"])
    prev_hash: str = Field(description="SHA-256 digest of preceding audit row.", examples=["9ff2fdaec5850ca0a7f4a3744f624959bb63a89472498df773e6f5df3200b8e2"])
    entry_hash: str = Field(description="SHA-256 digest of this chained audit entry.", examples=["d0db22ba2c41ab731158b7eda05d76a7586dd83d4aec22bd864d966a1a36cd80"])

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": 42,
                    "ts_utc": "2026-11-18T00:00:00.000000+00:00",
                    "session_id": "w9Z7B8qR3vT1mK4L7nQ2zA",
                    "event_type": "image_wiped",
                    "prev_hash": "9ff2fdaec5850ca0a7f4a3744f624959bb63a89472498df773e6f5df3200b8e2",
                    "entry_hash": "d0db22ba2c41ab731158b7eda05d76a7586dd83d4aec22bd864d966a1a36cd80",
                }
            ]
        }
    }


class AuditVerifyResponse(BaseModel):
    """Integrity verification response for the audit hash chain."""

    chain_intact: bool = Field(description="True if the entire hash chain is intact and untampered.", examples=[True])
    first_broken_index: Optional[int] = Field(
        default=None,
        description="0-based index of the first broken entry in the chain, or null if intact.",
        examples=[None],
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "chain_intact": True,
                    "first_broken_index": None,
                }
            ]
        }
    }


class ErrorResponse(BaseModel):
    """Standardized API error response schema."""

    detail: str = Field(description="Detailed error explanation.", examples=["Image contains EXIF GPS metadata. Please run the local privacy filter first."])

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"detail": "Image contains EXIF GPS metadata. Please run the local privacy filter first."},
                {"detail": "Firewall blocked task: PROMPT_INJECTION_PHRASE - Prompt injection phrase detected."},
                {"detail": "Session not found or expired."},
            ]
        }
    }
