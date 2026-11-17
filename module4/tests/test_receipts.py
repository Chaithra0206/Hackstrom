"""Unit tests for cryptographic deletion receipts, HMAC verification, and tamper detection."""

import copy
from pathlib import Path
import pytest
from app.db import get_db_connection, init_db
from app.receipts import generate_receipt, verify_receipt


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Fixture providing temporary SQLite database path."""
    db_file = str(tmp_path / "receipts_test.db")
    init_db(db_file)
    return db_file


def test_valid_receipt_verifies(temp_db: str) -> None:
    """Verify that a newly generated receipt passes cryptographic verification."""
    receipt = generate_receipt(
        session_id="sess_valid_1",
        image_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        bytes_wiped=4096,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )

    assert receipt["status"] == "completed"
    assert receipt["bytes_wiped"] == 4096
    assert receipt["wipe_verified"] is True
    assert "signature" in receipt

    # Verify dictionary
    assert verify_receipt(receipt) is True


def test_tampered_bytes_wiped_fails_verification(temp_db: str) -> None:
    """Verify that altering bytes_wiped causes HMAC signature check to fail."""
    receipt = generate_receipt(
        session_id="sess_tamper_bytes",
        image_sha256="abc123hash",
        bytes_wiped=1024,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )

    tampered = copy.deepcopy(receipt)
    tampered["bytes_wiped"] = 2048  # Tamper with wiped byte count
    assert verify_receipt(tampered) is False


def test_tampered_status_fails_verification(temp_db: str) -> None:
    """Verify that altering status causes HMAC signature check to fail."""
    receipt = generate_receipt(
        session_id="sess_tamper_status",
        image_sha256="abc123hash",
        bytes_wiped=1024,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )

    tampered = copy.deepcopy(receipt)
    tampered["status"] = "error"  # Tamper with status
    assert verify_receipt(tampered) is False


def test_tampered_image_sha256_fails_verification(temp_db: str) -> None:
    """Verify that altering image_sha256 causes HMAC signature check to fail."""
    receipt = generate_receipt(
        session_id="sess_tamper_hash",
        image_sha256="original_image_hash_12345",
        bytes_wiped=1024,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )

    tampered = copy.deepcopy(receipt)
    tampered["image_sha256"] = "forged_image_hash_67890"  # Tamper with image hash
    assert verify_receipt(tampered) is False


def test_tampered_signature_fails_verification(temp_db: str) -> None:
    """Verify that forging or mutating signature characters causes verification to fail."""
    receipt = generate_receipt(
        session_id="sess_tamper_sig",
        image_sha256="abc123hash",
        bytes_wiped=1024,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )

    tampered = copy.deepcopy(receipt)
    # Flip the last character of the hex signature
    sig = tampered["signature"]
    tampered["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert verify_receipt(tampered) is False


def test_signing_key_never_leaked_in_receipt_or_logs(temp_db: str) -> None:
    """Verify that the secret signing key is NEVER present in receipt JSON or database rows."""
    test_secret_key = "super_secret_signing_key_32chars_length!"
    receipt = generate_receipt(
        session_id="sess_secret_leak_check",
        image_sha256="sha256_dummy_hash",
        bytes_wiped=512,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
        signing_key=test_secret_key,
    )

    # 1. Assert secret key is NOT in receipt dictionary values
    for val in receipt.values():
        assert test_secret_key not in str(val)

    # 2. Assert secret key is NOT in SQLite receipts table
    with get_db_connection(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM receipts WHERE session_id = ?;", ("sess_secret_leak_check",))
        row = cursor.fetchone()
        assert row is not None
        for col_name in row.keys():
            assert test_secret_key not in str(row[col_name])

        # 3. Assert secret key is NOT in SQLite audit_log table
        cursor.execute("SELECT * FROM audit_log WHERE session_id = ?;", ("sess_secret_leak_check",))
        audit_rows = cursor.fetchall()
        assert len(audit_rows) > 0
        for a_row in audit_rows:
            assert test_secret_key not in a_row["detail_json"]


def test_receipt_limitations_exact_wording(temp_db: str) -> None:
    """Verify that the limitations statement matches the exact legal privacy disclaimer."""
    receipt = generate_receipt(
        session_id="sess_limitations",
        image_sha256="sha256_hash",
        bytes_wiped=100,
        wipe_verified=True,
        status="completed",
        db_path=temp_db,
    )
    expected_statement = (
        "Attests only that this gateway's in-memory copy was zero-filled. "
        "It cannot attest to retention by the third-party AI provider."
    )
    assert receipt["limitations"] == expected_statement
