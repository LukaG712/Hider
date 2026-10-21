"""Tests for Hider secret management service."""

import os
import pytest
from fastapi.testclient import TestClient

from hider.api import app, _secrets, _configs


@pytest.fixture(autouse=True)
def clear_data():
    _secrets.clear()
    _configs.clear()
    os.environ["API_KEY"] = "test-key"
    yield


client = TestClient(app)


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
            params={"x_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "db_password"

    def test_get_secret(self):
        client.post(
            "/api/secrets",
            json={"key": "api_key", "value": "mykey", "service": "Trapper"},
            params={"x_key": "test-key"},
        )
        response = client.get("/api/secrets/api_key", params={"x_key": "test-key"})
        assert response.status_code == 200
        data = response.json()
        assert data["value"] == "mykey"

    def test_list_secrets(self):
        response = client.get("/api/secrets", params={"x_key": "test-key"})
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_delete_secret(self):
        client.post(
            "/api/secrets",
            json={"key": "temp", "value": "val"},
            params={"x_key": "test-key"},
        )
        response = client.delete("/api/secrets/temp", params={"x_key": "test-key"})
        assert response.status_code == 200
        assert response.json()["deleted"] is True


class TestConfigs:
    def test_create_config(self):
        response = client.post(
            "/api/configs",
            json={"key": "max_retries", "value": 3, "service": "Slinker"},
            params={"x_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "max_retries"
        assert data["value"] == 3

    def test_get_config(self):
        client.post(
            "/api/configs",
            json={"key": "timeout", "value": 30},
            params={"x_key": "test-key"},
        )
        response = client.get("/api/configs/timeout", params={"x_key": "test-key"})
        assert response.status_code == 200
        assert response.json()["value"] == 30


class TestAuth:
    def test_invalid_key(self):
        response = client.get("/api/secrets", params={"x_key": "wrong"})
        assert response.status_code == 401
