"""Tests for Hider secret management service."""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Set test environment variables BEFORE any Hider imports
os.environ["ENCRYPTION_KEY"] = "test-encryption-key-32-bytes!!"
os.environ["API_KEY"] = "test-key"

# Use temporary database for tests
db_fd, db_path = tempfile.mkstemp(suffix=".db")
os.close(db_fd)
os.environ["DB_PATH"] = db_path


@pytest.fixture(autouse=True)
def cleanup_db():
    """Clean up test database before and after each test."""
    # Remove old database and re-initialize tables before each test
    for suffix in ("", "-wal", "-shm"):
        path = db_path + suffix
        if os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass
    api_storage._init_db()
    yield
    # Close any open connections before deleting
    if os.path.exists(db_path):
        try:
            os.unlink(db_path)
        except OSError:
            pass
    # Also clean up WAL and SHM files
    for suffix in ("-wal", "-shm"):
        wal_path = db_path + suffix
        if os.path.exists(wal_path):
            try:
                os.unlink(wal_path)
            except OSError:
                pass


# Now import after env vars are set
from hider.api import app  # noqa: E402
from hider.api import storage as api_storage  # noqa: E402

# Reconfigure storage to use the temp database
api_storage.db_path = db_path
api_storage._init_db()


client = TestClient(app)

HEADERS = {"Authorization": "Bearer test-key"}


class TestHealth:
    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "Hider"


class TestSecrets:
    def test_create_secret(self):
        response = client.post(
            "/api/secrets",
            json={"key": "db_password", "value": "secret123", "service": "Greenie"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "db_password"

    def test_get_secret(self):
        client.post(
            "/api/secrets",
            json={"key": "api_key", "value": "mykey", "service": "Trapper"},
            headers=HEADERS,
        )
        response = client.get("/api/secrets/api_key", headers=HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["value"] == "mykey"

    def test_list_secrets(self):
        response = client.get("/api/secrets", headers=HEADERS)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_delete_secret(self):
        client.post(
            "/api/secrets",
            json={"key": "temp", "value": "val"},
            headers=HEADERS,
        )
        response = client.delete("/api/secrets/temp", headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["deleted"] is True

    def test_secret_encrypted_at_rest(self):
        """Verify secrets are encrypted in the database."""
        client.post(
            "/api/secrets",
            json={"key": "encrypted_test", "value": "sensitive_data"},
            headers=HEADERS,
        )
        # Read raw database to verify encryption
        import sqlite3
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT value FROM secrets WHERE key = ?", ("encrypted_test",)).fetchone()
        conn.close()
        assert row is not None
        # The stored value should NOT be the plaintext
        assert row[0] != "sensitive_data"
        # But GET should return decrypted value
        response = client.get("/api/secrets/encrypted_test", headers=HEADERS)
        assert response.json()["value"] == "sensitive_data"

    def test_list_secrets_no_value(self):
        """Verify list endpoint does not expose secret values."""
        client.post(
            "/api/secrets",
            json={"key": "no_leak", "value": "hidden"},
            headers=HEADERS,
        )
        response = client.get("/api/secrets", headers=HEADERS)
        secrets = response.json()
        found = [s for s in secrets if s["key"] == "no_leak"]
        assert len(found) == 1
        assert "value" not in found[0]


class TestConfigs:
    def test_create_config(self):
        response = client.post(
            "/api/configs",
            json={"key": "max_retries", "value": 3, "service": "Slinker"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "max_retries"
        assert data["value"] == 3

    def test_get_config(self):
        client.post(
            "/api/configs",
            json={"key": "timeout", "value": 30},
            headers=HEADERS,
        )
        response = client.get("/api/configs/timeout", headers=HEADERS)
        assert response.status_code == 200
        # Config values are stored as strings in SQLite
        assert response.json()["value"] in (30, "30")


class TestAuth:
    def test_missing_auth(self):
        response = client.get("/api/secrets")
        assert response.status_code == 401

    def test_invalid_key(self):
        response = client.get("/api/secrets", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_query_param_rejected(self):
        """Query parameter auth should be rejected."""
        response = client.get("/api/secrets", params={"x_key": "test-key"})
        assert response.status_code == 401
