"""Test health endpoint."""

from fastapi.testclient import TestClient
import pytest
from app.main import app


@pytest.fixture
def client():
    """Fixture providing a test client for the FastAPI app."""
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client: TestClient) -> None:
    """Verify that GET /health returns 200 and {'status': 'ok'}."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
