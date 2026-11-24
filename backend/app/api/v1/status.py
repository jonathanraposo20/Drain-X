from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Body, Depends
from app.core.security import require_roles
from app.models.contracts import (
    SystemStatusContract,
    SystemOperationalState,
    ModeTransitionRequest,
    DirectiveIssuerType,
    DirectiveAuditOutboxFullError,
)
from app.services.state_store import state_store
from app.services.persistence_repository import persistence_repo

router = APIRouter(prefix="/status", tags=["Status"])


@router.get("", response_model=SystemStatusContract, summary="Get full system status")
async def get_system_status():
    """
    Returns the authoritative system state, operational mode, uptime,
    active alerts count, and latest sensor values.
    """
    return state_store.get_system_status()


@router.get("/mode", summary="Get current operational mode and details")
async def get_current_mode():
    """
    Returns current operational mode (SIMULATION, PHYSICAL, SAFE_HOLD, or HARDWARE)
    and helper boolean flags.
    """
    return {
        "status": "success",
        "mode": state_store.mode,
        "is_simulation": state_store.is_simulation(),
        "is_physical": state_store.is_physical(),
        "is_safe_hold": state_store.is_safe_hold(),
    }


@router.get("/mode/history", summary="Get auditable mode transition history")
async def get_mode_history():
    """
    Returns the complete auditable log of operational mode transitions,
    including timestamps, source modes, target modes, and transition reasons.
    """
    return {
        "status": "success",
        "current_mode": state_store.mode,
        "history": state_store.get_mode_history(),
    }


@router.post("/mode", summary="Set system operational mode")
async def set_system_mode(
    payload: ModeTransitionRequest,
    claims: Dict[str, Any] = Depends(require_roles(["admin", "municipality", "worker", "service_role"])),
):
    """
    Explicitly transition between SIMULATION, PHYSICAL, SAFE_HOLD, and HARDWARE modes.
    Mode transitions are validated, secured by RBAC, and logged into an auditable ledger.
    """
    try:
        old_mode = state_store.mode
        user_role = claims.get("extracted_role")
        raw_subject = claims.get("sub") or claims.get("email")
        verified_subject = (
            raw_subject.strip()
            if isinstance(raw_subject, str) and raw_subject.strip()
            else None
        )
        if user_role in ("admin", "municipality", "worker") and verified_subject:
            mode_issuer_type = DirectiveIssuerType.OPERATOR
            mode_issuer_id = verified_subject
        else:
            mode_issuer_type = (
                DirectiveIssuerType.SAFETY_INTERLOCK
                if payload.mode == "SAFE_HOLD"
                else DirectiveIssuerType.AUTOMATED_ENGINE
            )
            mode_issuer_id = verified_subject or (
                "safety_interlock"
                if payload.mode == "SAFE_HOLD"
                else "system_mode_controller"
            )

        success, message = state_store.set_mode(
            payload.mode,
            payload.reason or "",
            issuer_type=mode_issuer_type,
            issuer_id=mode_issuer_id,
        )
        if success and old_mode != state_store.mode:
            operator_id = verified_subject or "API_OPERATOR"
            await persistence_repo.persist_mode_transition(
                from_mode=old_mode,
                to_mode=state_store.mode,
                reason=payload.reason or f"Mode transition to {state_store.mode}",
                operator_id=operator_id,
            )
    except DirectiveAuditOutboxFullError as e:
        raise HTTPException(
            status_code=503,
            detail="Actuator directive audit outbox capacity exceeded; persistence backpressure applied.",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "status": "success",
        "mode": state_store.mode,
        "message": message,
    }


@router.post("/state", summary="Set operational state")
async def set_operational_state(operational_state: SystemOperationalState = Body(..., embed=True)):
    """
    Set operational state (e.g. STANDBY, MONITORING, INTERVENING, FAULT, EMERGENCY_STOP).
    """
    state_store.operational_state = operational_state
    return {
        "status": "success",
        "operational_state": state_store.operational_state
    }
