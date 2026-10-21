"""FastAPI application for Hider secret management service."""

import os
from datetime import datetime
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query

from hider.models import Secret, Config


app = FastAPI(
    title="Hider",
    description="Secret and configuration management for the Evershade ecosystem",
    version="1.0.0",
)

API_KEY = os.getenv("API_KEY", "Hider-dev-key-change-me")

# In-memory storage
_secrets: dict[str, Secret] = {}
_configs: dict[str, Config] = {}


def verify_key(x_key: Optional[str] = Query(None)) -> None:
    if x_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "Hider"}


# ─── Secrets ────────────────────────────────────────────────────

@app.post("/api/secrets")
async def create_secret(data: dict[str, Any], x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
    secret = Secret(
        key=data["key"],
        value=data["value"],
        service=data.get("service"),
        description=data.get("description"),
    )
    _secrets[secret.key] = secret
    return secret.to_dict()


@app.get("/api/secrets")
async def list_secrets(
    service: Optional[str] = None,
    x_key: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    verify_key(x_key)
    results = _secrets.values()
    if service:
        results = [s for s in results if s.service == service]
    return [s.to_dict() for s in results]


@app.get("/api/secrets/{key}")
async def get_secret(key: str, x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
    secret = _secrets.get(key)
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    return secret.to_dict(include_value=True)


@app.put("/api/secrets/{key}")
async def update_secret(
    key: str,
    data: dict[str, Any],
    x_key: Optional[str] = Query(None),
) -> dict[str, Any]:
    verify_key(x_key)
    secret = _secrets.get(key)
    if secret is None:
        raise HTTPException(status_code=404, detail="Secret not found")
    if "value" in data:
        secret.value = data["value"]
    if "description" in data:
        secret.description = data["description"]
    secret.updated_at = datetime.utcnow()
    secret.version += 1
    return secret.to_dict()


@app.delete("/api/secrets/{key}")
async def delete_secret(key: str, x_key: Optional[str] = Query(None)) -> dict[str, bool]:
    verify_key(x_key)
    if key not in _secrets:
        raise HTTPException(status_code=404, detail="Secret not found")
    del _secrets[key]
    return {"deleted": True}


# ─── Configs ────────────────────────────────────────────────────

@app.post("/api/configs")
async def create_config(data: dict[str, Any], x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
    config = Config(
        key=data["key"],
        value=data["value"],
        service=data.get("service"),
        description=data.get("description"),
    )
    _configs[config.key] = config
    return config.to_dict()


@app.get("/api/configs")
async def list_configs(
    service: Optional[str] = None,
    x_key: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    verify_key(x_key)
    results = _configs.values()
    if service:
        results = [c for c in results if c.service == service]
    return [c.to_dict() for c in results]


@app.get("/api/configs/{key}")
async def get_config(key: str, x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
    config = _configs.get(key)
    if config is None:
        raise HTTPException(status_code=404, detail="Config not found")
    return config.to_dict()


@app.put("/api/configs/{key}")
async def update_config(
    key: str,
    data: dict[str, Any],
    x_key: Optional[str] = Query(None),
) -> dict[str, Any]:
    verify_key(x_key)
    config = _configs.get(key)
    if config is None:
        raise HTTPException(status_code=404, detail="Config not found")
    if "value" in data:
        config.value = data["value"]
    if "description" in data:
        config.description = data["description"]
    config.updated_at = datetime.utcnow()
    config.version += 1
    return config.to_dict()


@app.delete("/api/configs/{key}")
async def delete_config(key: str, x_key: Optional[str] = Query(None)) -> dict[str, bool]:
    verify_key(x_key)
    if key not in _configs:
        raise HTTPException(status_code=404, detail="Config not found")
    del _configs[key]
    return {"deleted": True}
