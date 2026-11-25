"""
DRAIN-X IoT Edge Node / Device Registry API.

Milestone: P0.6 Supabase Cloud Integration.

Endpoints for managing physical and simulated edge controllers (ESP32 DevKit V1),
tracking hardware validation stages, firmware revisions, and connection timestamps.
"""

from typing import Any, Dict, FrozenSet, List, Optional, Set
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.security import require_roles
from app.services.persistence_repository import persistence_repo

router = APIRouter(prefix="/devices", tags=["Device Registry"])

_PROTECTED_DEVICE_METADATA_KEYS: FrozenSet[str] = frozenset({
    "assigned_worker_id",
    "assigned_worker",
    "worker_id",
    "assigned_team_id",
    "assigned_team",
    "team_id",
    "team",
    "assigned_devices",
    "allowed_devices",
    "assigned_device",
    "assigned_sections",
    "allowed_sections",
    "assigned_section",
    "section_id",
    "owner_id",
    "role",
    "permissions",
    "authorized_workers",
    "authorized_teams",
})


def _find_protected_metadata_keys(obj: Any) -> Set[str]:
    """Recursively detects authorization-sensitive metadata keys in nested payloads."""
    found: Set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_norm = str(k).strip().lower()
            if key_norm in _PROTECTED_DEVICE_METADATA_KEYS:
                found.add(key_norm)
            found.update(_find_protected_metadata_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            found.update(_find_protected_metadata_keys(item))
    return found


class DeviceRegistrationRequest(BaseModel):
    device_id: str = Field(..., min_length=3, max_length=64, description="Unique hardware node identifier")
    name: str = Field(..., max_length=128, description="Human-readable node label")
    hardware_model: str = Field(default="ESP32 DevKit V1", description="Microcontroller board model")
    firmware_version: str = Field(default="0.3.7-p0.3g", description="Firmware build version")
    is_active: bool = Field(default=True, description="Whether node is authorized and enabled")
    validation_stage: str = Field(default="SOFTWARE_ONLY", description="Current hardware readiness stage")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom peripheral configuration")


@router.get("", summary="List all registered edge devices")
async def list_devices() -> Dict[str, Any]:
    """
    Returns the list of all registered physical and simulated edge nodes.
    """
    devices = await persistence_repo.list_devices()
    return {
        "status": "success",
        "count": len(devices),
        "devices": devices,
    }


@router.get("/{device_id}", summary="Get device by identifier")
async def get_device(device_id: str) -> Dict[str, Any]:
    """
    Retrieve metadata and validation stage for a specific edge device.
    """
    device = await persistence_repo.get_device(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found in registry.",
        )
    return {
        "status": "success",
        "device": device,
    }


@router.post(
    "",
    summary="Register or update an IoT edge device",
)
async def register_device(
    payload: DeviceRegistrationRequest,
    claims: Dict[str, Any] = Depends(require_roles(["admin", "municipality", "worker", "service_role"])),
) -> Dict[str, Any]:
    """
    Registers a new edge hardware node or updates firmware and validation stage.
    Protected by role-based access control when Supabase Auth is enabled.
    Workers are strictly prohibited from setting or overwriting authorization-sensitive metadata.
    """
    if claims.get("extracted_role") == "worker":
        if _find_protected_metadata_keys(payload.metadata):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Field workers are not authorized to set or modify authorization-sensitive device metadata.",
            )
        try:
            existing = await persistence_repo.get_device(payload.device_id, strict=True)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Device registry persistence store is unavailable.",
            ) from exc

        if existing is not None:
            if _find_protected_metadata_keys(existing.get("metadata") or {}):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Field workers are not authorized to overwrite a device containing managed authorization metadata.",
                )
            if bool(payload.is_active) != bool(existing.get("is_active", True)):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Field workers are not authorized to change device activation status.",
                )

    registered = await persistence_repo.register_device(payload.model_dump())
    return {
        "status": "success",
        "message": f"Device '{payload.device_id}' registered successfully.",
        "device": registered,
    }
