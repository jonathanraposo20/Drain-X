from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from pydantic import BaseModel

from app.core.security import require_roles
from app.models.contracts import ScenarioType
from app.services.scenario_benchmark import scenario_runner
from app.services.state_store import state_store

router = APIRouter(
    prefix="/simulation",
    tags=["Simulation & Digital Twin"],
    dependencies=[Depends(require_roles(["municipality", "admin", "service_role"]))],
)


class StartScenarioPayload(BaseModel):
    scenario: ScenarioType
    seed: Optional[int] = 42


class InjectFaultPayload(BaseModel):
    fault_type: Literal["SENSOR_DISCONNECT", "SENSOR_FREEZE", "SENSOR_SPIKE", "WINCH_JAM"]
    sensor_id: Optional[str] = "US_UPSTREAM_01"


@router.get("/state", summary="Get comprehensive live simulation and digital twin state")
async def get_simulation_state():
    """
    Returns the real-time simulation snapshot:
    - Active scenario name and elapsed simulation time
    - Mechanism kinematics (tray height, backup net angle, cycle count)
    - Hydraulic levels (h1, h2, Qin, Qout)
    - Blockage diagnosis & TTC prediction
    - Benchmark performance comparison metrics
    """
    system_status = state_store.get_system_status()
    benchmark = state_store.get_benchmark_results()
    active_faults = state_store.get_active_faults()

    return {
        "status": "success",
        "is_running": scenario_runner.is_running,
        "active_scenario": scenario_runner.current_scenario.value if scenario_runner.current_scenario else None,
        "simulation_time_s": round(scenario_runner.simulation_time_s, 1),
        "system": system_status,
        "mechanism": system_status.mechanism,
        "blockage": system_status.active_blockage,
        "prediction": system_status.active_prediction,
        "benchmark": benchmark,
        "active_faults": active_faults,
    }


@router.post("/start", summary="Start a simulation scenario")
async def start_scenario(payload: StartScenarioPayload):
    """
    Launches a reproducible scenario (e.g. GRADUAL_DEBRIS, SUDDEN_BLOCKAGE, SUCCESSFUL_INTERVENTION).
    Guarded: rejected with 409 Conflict if not in SIMULATION mode.
    """
    if not state_store.is_simulation():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Simulation cannot be started while in {state_store.mode} mode. Transition mode to SIMULATION first.",
        )
    scenario_runner.start_scenario(scenario=payload.scenario, seed=payload.seed)
    return {
        "status": "success",
        "message": f"Scenario {payload.scenario.value} started with seed {payload.seed}",
        "scenario": payload.scenario.value
    }


@router.post("/stop", summary="Stop current simulation")
async def stop_scenario():
    """Halts the active simulation scenario."""
    scenario_runner.stop_scenario()
    return {"status": "success", "message": "Simulation halted"}


@router.post("/step", summary="Advance simulation by dt seconds")
async def step_simulation(dt: float = Query(default=0.5, ge=0.05, le=5.0)):
    """Advances the simulation by dt seconds. Ideal for stepped experimentation."""
    if not state_store.is_simulation():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Simulation cannot be stepped while in {state_store.mode} mode. Transition mode to SIMULATION first.",
        )
    step_result = scenario_runner.step(dt=dt)
    return {
        "status": "success",
        "step_result": step_result
    }


@router.post("/inject_fault", summary="Inject a fault into the running simulation")
async def inject_fault(payload: InjectFaultPayload):
    """Injects an intentional sensor or mechanism failure into the simulation."""
    if payload.fault_type == "SENSOR_DISCONNECT":
        scenario_runner.channel.fault_disconnected_sensor = payload.sensor_id
    elif payload.fault_type == "SENSOR_FREEZE":
        scenario_runner.channel.fault_frozen_sensor = payload.sensor_id
        scenario_runner.channel.fault_frozen_value = scenario_runner.channel.h1
    elif payload.fault_type == "SENSOR_SPIKE":
        scenario_runner.channel.fault_spike_sensor = payload.sensor_id
    elif payload.fault_type == "WINCH_JAM":
        scenario_runner.mechanism.inject_jam_on_hoist = True

    return {
        "status": "success",
        "message": f"Fault {payload.fault_type} injected into {payload.sensor_id or 'WINCH'}"
    }


@router.post("/mechanism/trigger", summary="Manually trigger the waste-removal cycle")
async def trigger_mechanism():
    """Manually commands the screening mechanism to execute a collection and dump cycle."""
    success = scenario_runner.mechanism.trigger_cycle()
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot trigger cycle: mechanism is not IDLE or is in a FAULT/JAM state."
        )
    return {"status": "success", "message": "Waste-removal cycle initiated"}


@router.post("/mechanism/reset", summary="Reset mechanism from jammed/failed state")
async def reset_mechanism():
    """Resets the screening mechanism back to drain bed (IDLE)."""
    scenario_runner.mechanism.manual_reset()
    state_store.clear_faults()
    return {"status": "success", "message": "Mechanism reset to IDLE"}
