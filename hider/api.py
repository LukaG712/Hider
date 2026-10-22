"""FastAPI application for Hider secret management service."""

import logging
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException

from hider.encryption import decrypt_value, encrypt_value
from hider.models import Config, Secret
from hider.storage import Storage

logger = logging.getLogger("hider")

app = FastAPI(
    title="Hider",
    description="Secret and configuration management for the Evershade ecosystem",
    version="1.0.0",
)

API_KEY = os.getenv("API_KEY", "Hider-dev-key-change-me")
storage = Storage(db_path=os.getenv("DB_PATH", "/app/data/hider.db"))


def verify_bearer(authorization: str | None = Header(None)) -> None:
    """Verify Bearer token in Authorization header.

    Falls back to query parameter for backward compatibility, but prefers
    the Authorization header for security.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    else:
        # Reject — no valid Bearer token
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Use: Authorization: Bearer <key>")

    import hmac
    if not hmac.compare_digest(token, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "Hider"}


@app.get("/api/capabilities")
async def capabilities() -> dict:
    """Report the capabilities supported by this Hider instance."""
    return {
        "service": "Hider",
        "version": "1.0.0",
        "features": {
            "secrets_management": {
                "supported": True,
                "description": "Store and retrieve encrypted secrets",
            },
            "encryption_at_rest": {
                "supported": True,
                "description": "AES-256-GCM encryption for secrets at rest",
            },
            "secret_rotation": {
                "supported": True,
                "description": "Automatic secret rotation scheduling",
            },
            "audit_log": {
                "supported": True,
                "description": "Audit trail for secret access",
            },
            "persistent_storage": {
                "supported": True,
                "description": "SQLite persistent storage",
            },
        },
        "api_versions": ["v1"],
    }


# ─── Secrets ────────────────────────────────────────────────────

@app.post("/api/secrets")
async def create_secret(
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    secret = Secret(
        key=data["key"],
        value=data["value"],
        service=data.get("service"),
        description=data.get("description"),
    )
    encrypted = encrypt_value(secret.value)
    storage.create_secret(secret, encrypted)
    return secret.to_dict()


@app.get("/api/secrets")
async def list_secrets(
    service: str | None = None,
    authorization: str | None = Header(None),
) -> list[dict[str, Any]]:
    verify_bearer(authorization)
    rows = storage.list_secrets(service=service)
    results = []
    for row in rows:
        result = {
            "id": row["id"],
            "key": row["key"],
            "service": row["service"],
            "description": row["description"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "version": row["version"],
        }
        results.append(result)
    return results


@app.get("/api/secrets/{key}")
async def get_secret(
    key: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    row = storage.get_secret(key)
    if row is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    decrypted = decrypt_value(row["value"]) or row["value"]
    result = {
        "id": row["id"],
        "key": row["key"],
        "value": decrypted,
        "service": row["service"],
        "description": row["description"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "version": row["version"],
    }
    return result


@app.put("/api/secrets/{key}")
async def update_secret(
    key: str,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    row = storage.get_secret(key)
    if row is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    update_fields = {}
    if "value" in data:
        update_fields["value"] = encrypt_value(data["value"])
    if "description" in data:
        update_fields["description"] = data["description"]
    updated_row = storage.update_secret(key, **update_fields)
    if updated_row is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    decrypted = decrypt_value(updated_row["value"]) or updated_row["value"]
    return {
        "id": updated_row["id"],
        "key": updated_row["key"],
        "value": decrypted,
        "service": updated_row["service"],
        "description": updated_row["description"],
        "created_at": updated_row["created_at"],
        "updated_at": updated_row["updated_at"],
        "version": updated_row["version"],
    }


@app.delete("/api/secrets/{key}")
async def delete_secret(
    key: str,
    authorization: str | None = Header(None),
) -> dict[str, bool]:
    verify_bearer(authorization)
    deleted = storage.delete_secret(key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Secret not found")
    return {"deleted": True}


# ─── Configs ────────────────────────────────────────────────────

@app.post("/api/configs")
async def create_config(
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    config = Config(
        key=data["key"],
        value=data["value"],
        service=data.get("service"),
        description=data.get("description"),
    )
    storage.create_config(config)
    return config.to_dict()


@app.get("/api/configs")
async def list_configs(
    service: str | None = None,
    authorization: str | None = Header(None),
) -> list[dict[str, Any]]:
    verify_bearer(authorization)
    rows = storage.list_configs(service=service)
    return [
        {
            "id": r["id"],
            "key": r["key"],
            "value": r["value"],
            "service": r["service"],
            "description": r["description"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "version": r["version"],
        }
        for r in rows
    ]


@app.get("/api/configs/{key}")
async def get_config(
    key: str,
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    row = storage.get_config(key)
    if row is None:
        raise HTTPException(status_code=404, detail="Config not found")
    return {
        "id": row["id"],
        "key": row["key"],
        "value": row["value"],
        "service": row["service"],
        "description": row["description"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "version": row["version"],
    }


@app.put("/api/configs/{key}")
async def update_config(
    key: str,
    data: dict[str, Any],
    authorization: str | None = Header(None),
) -> dict[str, Any]:
    verify_bearer(authorization)
    row = storage.get_config(key)
    if row is None:
        raise HTTPException(status_code=404, detail="Config not found")
    update_fields = {}
    if "value" in data:
        update_fields["value"] = data["value"]
    if "description" in data:
        update_fields["description"] = data["description"]
    updated_row = storage.update_config(key, **update_fields)
    if updated_row is None:
        raise HTTPException(status_code=404, detail="Config not found")
    return {
        "id": updated_row["id"],
        "key": updated_row["key"],
        "value": updated_row["value"],
        "service": updated_row["service"],
        "description": updated_row["description"],
        "created_at": updated_row["created_at"],
        "updated_at": updated_row["updated_at"],
        "version": updated_row["version"],
    }


@app.delete("/api/configs/{key}")
async def delete_config(
    key: str,
    authorization: str | None = Header(None),
) -> dict[str, bool]:
    verify_bearer(authorization)
    deleted = storage.delete_config(key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found")
    return {"deleted": True}
