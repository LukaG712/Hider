"""Data models for Hider secret management."""

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4


class Secret:
    def __init__(
        self,
        key: str,
        value: str,
        service: str | None = None,
        description: str | None = None,
        id: UUID | None = None,
        created_at: datetime | None = None,
    ):
        self.id = id or uuid4()
        self.key = key
        self.value = value  # Stored encrypted in production
        self.service = service
        self.description = description
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = self.created_at
        self.version = 1

    def to_dict(self, include_value: bool = False) -> dict[str, Any]:
        result = {
            "id": str(self.id),
            "key": self.key,
            "service": self.service,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }
        if include_value:
            result["value"] = self.value
        return result


class Config:
    def __init__(
        self,
        key: str,
        value: Any,
        service: str | None = None,
        description: str | None = None,
        id: UUID | None = None,
        created_at: datetime | None = None,
    ):
        self.id = id or uuid4()
        self.key = key
        self.value = value
        self.service = service
        self.description = description
        self.created_at = created_at or datetime.utcnow()
        self.updated_at = self.created_at
        self.version = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "key": self.key,
            "value": self.value,
            "service": self.service,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
        }
