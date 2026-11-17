"""Unit and integration tests for hash-chained audit logging, tamper detection, and audit endpoints."""

from pathlib import Path
from fastapi.testclient import TestClient
import pytest
from app.audit_log import AuditLogger, GENESIS_HASH
from app.db import get_db_connection, init_db
from app.main import app
from app.receipts import generate_receipt


@pytest.fixture
def temp_logger(tmp_path: Path) -> tuple[AuditLogger, str]:
    """Fixture providing an isolated AuditLogger backed by a fresh SQLite database."""
    db_file = str(tmp_path / "audit_chain_test.db")
    init_db(db_file)
    logger = AuditLogger(db_path=db_file)
    return logger, db_file


@pytest.fixture
def client():
    """Fixture providing TestClient with active lifespan context."""
    with TestClient(app) as test_client:
        yield test_client


def test_audit_hash_chain_append_and_verify(temp_logger: tuple[AuditLogger, str]) -> None:
    """Verify that multiple entries link linearly starting from GENESIS_HASH and verify_chain returns None."""
    logger, db_path = temp_logger

    # Append 5 events
    h1 = logger.append_event("sess_1", "SESSION_CREATED", {"info": "step 1"})
    h2 = logger.append_event("sess_1", "IMAGE_INGESTED", {"bytes": 1024})
    h3 = logger.append_event("sess_2", "SESSION_CREATED", {"info": "step 2"})
    h4 = logger.append_event("sess_1", "IMAGE_WIPED", {"bytes_wiped": 1024})
    h5 = logger.append_event("sess_2", "IMAGE_WIPED", {"bytes_wiped": 2048})

    # Verify rows in SQLite
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, prev_hash, entry_hash FROM audit_log ORDER BY id ASC;")
        rows = cursor.fetchall()
        assert len(rows) == 5

        # First entry must point to GENESIS_HASH
        assert rows[0]["prev_hash"] == GENESIS_HASH
        assert rows[0]["entry_hash"] == h1

        # Subsequent entries link to predecessor entry_hash
        assert rows[1]["prev_hash"] == h1
        assert rows[1]["entry_hash"] == h2

        assert rows[2]["prev_hash"] == h2
        assert rows[2]["entry_hash"] == h3

        assert rows[3]["prev_hash"] == h3
        assert rows[3]["entry_hash"] == h4

        assert rows[4]["prev_hash"] == h4
        assert rows[4]["entry_hash"] == h5

    # Verification must report chain intact
    assert logger.verify_chain() is None


def test_tamper_detection_edits_one_row_in_sqlite(temp_logger: tuple[AuditLogger, str]) -> None:
    """Requirement: Edit one row directly in SQLite and confirm verify_chain detects the tampering."""
    logger, db_path = temp_logger

    # Append 4 sequential audit records
    logger.append_event("sess_A", "EVENT_0", {"step": 0})
    logger.append_event("sess_A", "EVENT_1", {"step": 1})
    logger.append_event("sess_A", "EVENT_2", {"step": 2})
    logger.append_event("sess_A", "EVENT_3", {"step": 3})

    # Chain initially intact
    assert logger.verify_chain() is None

    # Directly tamper with row at index 2 (id=3) in SQLite (e.g. modify detail_json)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_log SET detail_json = ? WHERE id = 3;",
            ('{"step": "MALICIOUS_FORGERY"}',),
        )

    # verify_chain MUST detect tampering and identify index 2 as the first broken entry
    broken_idx = logger.verify_chain()
    assert broken_idx == 2

    # Now tamper with event_type at index 1 (id=2)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_log SET event_type = ? WHERE id = 2;",
            ("ALTERED_TYPE",),
        )

    # verify_chain MUST now identify index 1 as the earliest broken entry
    broken_idx_earlier = logger.verify_chain()
    assert broken_idx_earlier == 1


def test_tamper_detection_edits_entry_hash_in_sqlite(temp_logger: tuple[AuditLogger, str]) -> None:
    """Verify that directly modifying an entry_hash is flagged at that row's index."""
    logger, db_path = temp_logger

    logger.append_event("sess_B", "EVENT_0", {"data": "ok"})
    logger.append_event("sess_B", "EVENT_1", {"data": "ok"})

    assert logger.verify_chain() is None

    # Forcibly alter entry_hash at id=1 (index 0)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE audit_log SET entry_hash = ? WHERE id = 1;",
            ("0000000000000000000000000000000000000000000000000000000000000000",),
        )

    assert logger.verify_chain() == 0


def test_get_receipt_endpoint(client: TestClient) -> None:
    """Test GET /v1/receipts/{session_id} returns signed receipt or 404."""
    # 404 for non-existent session
    res_missing = client.get("/v1/receipts/non_existent_session_123")
    assert res_missing.status_code == 404

    # Issue receipt
    sid = "sess_receipt_endpoint_test"
    rcpt = generate_receipt(
        session_id=sid,
        image_sha256="dummy_sha256_hash",
        bytes_wiped=2048,
        wipe_verified=True,
        status="completed",
    )

    # 200 for existing session receipt
    res_found = client.get(f"/v1/receipts/{sid}")
    assert res_found.status_code == 200
    data = res_found.json()
    assert data["session_id"] == sid
    assert data["receipt_id"] == rcpt["receipt_id"]
    assert data["signature"] == rcpt["signature"]
    assert data["bytes_wiped"] == 2048


def test_post_receipt_verify_endpoint(client: TestClient) -> None:
    """Test POST /v1/receipts/verify evaluates genuine and tampered receipt bodies."""
    receipt = generate_receipt(
        session_id="sess_verify_api_test",
        image_sha256="abc123sha256",
        bytes_wiped=1024,
        wipe_verified=True,
        status="completed",
    )

    # Verify genuine receipt
    res_valid = client.post("/v1/receipts/verify", json=receipt)
    assert res_valid.status_code == 200
    assert res_valid.json() == {"valid": True}

    # Verify tampered receipt
    tampered = dict(receipt)
    tampered["bytes_wiped"] = 999999
    res_invalid = client.post("/v1/receipts/verify", json=tampered)
    assert res_invalid.status_code == 200
    assert res_invalid.json() == {"valid": False}


def test_get_audit_events_endpoint(client: TestClient) -> None:
    """Test GET /v1/audit?session_id=&limit= returns redacted event logs."""
    sid = "sess_audit_query_test"
    generate_receipt(
        session_id=sid,
        image_sha256="sha256_audit_test",
        bytes_wiped=512,
        wipe_verified=True,
        status="completed",
    )

    response = client.get(f"/v1/audit?session_id={sid}&limit=10")
    assert response.status_code == 200
    events = response.json()
    assert len(events) >= 1

    first_event = events[0]
    assert first_event["session_id"] == sid
    assert "event_type" in first_event
    assert "prev_hash" in first_event
    assert "entry_hash" in first_event
    # Verify no raw payload detail is exposed in the response
    assert "detail_json" not in first_event


def test_get_audit_verify_endpoint(client: TestClient) -> None:
    """Test GET /v1/audit/verify returns chain_intact=True on intact database."""
    response = client.get("/v1/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["chain_intact"] is True
    assert data["first_broken_index"] is None
