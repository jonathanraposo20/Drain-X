# DRAIN-X
### Observe to Resolve — Predictive Urban Drainage Intelligence System

[![CI - Full System Suite](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Supabase](https://img.shields.io/badge/Supabase-Cloud%20PostgreSQL-3ECF8E.svg?logo=supabase&logoColor=white)](https://supabase.com)
[![PlatformIO ESP32](https://img.shields.io/badge/PlatformIO-ESP32%20C%2B%2B-E95420.svg?logo=platformio&logoColor=white)](https://platformio.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

DRAIN-X is an enterprise-grade, end-to-end **predictive urban drainage intelligence and active flood mitigation platform**. It unifies physical IoT edge sensing, high-throughput sensory telemetry processing, real-time hydraulic state modeling, automated fail-safe diversion actuation, an authoritative sheet-metal Digital Twin (Top, Isometric, and Side views), and multi-stakeholder civic incident workflows.

Developed by **Team NIRAKSHAN** as an IoT and municipal intelligence prototype for the *IDEAS 5.0 — Idea to Impact* innovation initiative.

---

## Table of Contents
1. [Overview](#-overview)
2. [Current Development Status](#-current-development-status)
3. [System Architecture](#-system-architecture)
4. [Feature Inventory](#-feature-inventory)
5. [Digital Twin Specification (P1.0.5 Fidelity)](#-digital-twin-specification-p105-fidelity)
6. [Telemetry & Operational Modes (P1.1 Integration)](#-telemetry--operational-modes-p11-integration)
7. [Security Architecture & Governance](#-security-architecture--governance)
8. [API Reference](#-api-reference)
9. [Database & Persistence](#-database--persistence)
10. [Installation & Local Setup](#-installation--local-setup)
11. [Automated Testing & Quality Verification](#-automated-testing--quality-verification)
12. [Deployment Architecture](#-deployment-architecture)
13. [Hardware Status & Prototype Boundary](#-hardware-status--prototype-boundary)
14. [Development Roadmap](#-development-roadmap)
15. [Project Limitations](#-project-limitations)
16. [Team & License](#-team--license)

---

## 📌 Overview

During intense precipitation, stormwater drainage networks in modern cities frequently choke due to accumulated debris, plastics, construction silt, and illegal dumping. Conventional stormwater management is almost entirely **reactive**: municipal authorities dispatch maintenance personnel only after surface roads are inundated, traffic grids stall, or citizen grievances flood emergency lines.

DRAIN-X transforms urban drainage into a proactive, intelligent, closed-loop cyber-physical system:
- **Continuous Sub-surface Sensing:** Measures hydraulic head, volumetric discharge, and velocity differentials across interconnected drainage sections.
- **Physics-Informed Anomaly Detection:** Detects sub-surface hydraulic choke points and localizes developing obstructions before water overflows street-level grates.
- **Dynamic Time-to-Critical (TTC) Prediction:** Forecasts flood risk levels and water-level rise rates to give emergency teams actionable advance warning.
- **Autonomous & Fail-Safe Interventions:** Activates physical diversion gates to relieve hydrostatic head while maintaining strict fail-safe baseline postures.
- **Multi-Stakeholder Collaboration:** Coordinates municipal administrators, field maintenance crews, and citizens through synchronized dashboards and incident workflows.
- **Authoritative Digital Twin:** Projects orthogonal plan, side elevation, and 3D axonometric views reflecting exact prototype geometry and telemetry in real time.

---

## 📍 Current Development Status

The codebase is currently at **Milestone P1.2 (Backend & Telemetry Architecture Audit Baseline)**, building directly upon **P1.0.5 (Digital Twin Presentation Cleanup)** and **P1.1 (Digital Twin Integration & Reliability)**.

| Component / Layer | Status | Implementation Details |
| :--- | :--- | :--- |
| **Physical Sheet-Metal Digital Twin** | **Implemented** | $140 \times 80 \times 50\text{ cm}$ canonical model with Top, Isometric, and Side views; hinged door rotation; debris screening grid; radar beam standby states. |
| **Telemetry Ingestion & State Store** | **Implemented** | Partitioned in-memory store (`SIMULATED`, `PHYSICAL`, `SAFE_HOLD`); zero-flow vs fault discrimination; circular rolling buffers (maxlen=300). |
| **Telemetry Abstraction & Reliability** | **Implemented** | Strict source classification (`SIMULATED`, `LIVE`, `OFFLINE`, `STALE`, `FAULT`); no substitution of 0 for missing values; `(CMD)` vs `ACTUAL` actuator separation. |
| **Backend API Core & Probes** | **Implemented** | FastAPI modular monolith; zero circular dependencies; `/health`, `/health/liveness`, `/health/ready` probes. |
| **Security & JWT Verification** | **Implemented** | Modern asymmetric ES256 via trusted JWKS; legacy HS256 secret fallback; anti-privilege escalation; `X-Device-Key` edge authentication. |
| **Cloud Persistence (Supabase)** | **Implemented** | PostgREST asynchronous adapter with graceful local in-memory fallback; RLS policies; time-series indexes. |
| **SCADA Web Dashboard** | **Implemented** | React 18 + Vite + TypeScript; Leaflet GIS mapping; historical telemetry scrubber; incident management modals. |
| **Mobile Application (Flutter)** | **Planned / In Progress** | Application contracts and initial views defined in `mobile/`; full mobile deployment under development. |
| **Physical ESP32 Hardware** | **Prototype In Assembly** | Physical sheet-metal flume is being assembled; ESP32 is **not** connected; firmware runs unit tests only; no live water testing performed. |

---

## 🏗 System Architecture

DRAIN-X is engineered as a modular monolith optimized for high reliability, clear role boundaries, and graceful degradation:

```mermaid
flowchart TD
    subgraph EdgeHardware["IoT Edge Tier (Physical Flume - In Assembly)"]
        ESP32["ESP32 DevKit V1 (FreeRTOS Firmware)"]
        Radar_Sensor["Radar Level Sensor (US_UPSTREAM_01)"]
        Flow_Sensor["Flow Sensor (PUMP_INFLOW_01)"]
        Servo_Gate["Hinged Diversion Gate Actuator (DischargeKeeper)"]
        Radar_Sensor -.->|Simulated / Future ADC| ESP32
        Flow_Sensor -.->|Simulated / Future ISR| ESP32
        ESP32 -.->|PWM Command (Open-Loop)| Servo_Gate
    end

    subgraph BackendCore["FastAPI Backend Core (Python 3.12)"]
        Ingest["Telemetry Ingest Endpoint (/api/v1/telemetry/ingest)"]
        Security["JWT & Device Key Cryptographic Validator"]
        StateStore["Authoritative State Store (Partitioned Isolation)"]
        FaultEngine["Fault Detector (Plausibility, Stale, Step-Change)"]
        HydraulicEngine["Blockage Detector (Excess Head Loss Delta_h)"]
        PredictionEngine["Prediction Engine (Linear Regression dh/dt & TTC)"]
        InterventionEngine["Intervention Engine (Actuator Directives)"]
        StreamHub["Live WebSocket Broadcast Hub (/stream)"]

        Ingest --> Security
        Security --> StateStore
        StateStore --> FaultEngine
        StateStore --> HydraulicEngine
        StateStore --> PredictionEngine
        StateStore --> InterventionEngine
        StateStore --> StreamHub
    end

    subgraph CloudPersistence["Cloud Persistence & Security (Supabase Cloud)"]
        PostgREST["PostgREST REST API v1"]
        PgTables[("PostgreSQL 15 Tables: sensor_readings, alerts, incidents, devices")]
        RLS["Row Level Security Policies (citizen, municipality, worker, service_role)"]
        AuthService["GoTrue Auth Service (ES256 JWKS)"]

        PostgREST --> PgTables
        PgTables --- RLS
    end

    subgraph PresentationTier["Presentation & Mobile Ecosystem"]
        ReactDashboard["React 18 + Vite Municipal Dashboard (GIS + 3D SCADA Twin)"]
        DigitalTwinComponent["LongitudinalSideDrainTwin (Top, Isometric, Side Views)"]
        FlutterApp["Unified Flutter Mobile App (In Development)"]

        ReactDashboard --> DigitalTwinComponent
    end

    ESP32 -.->|HTTPS POST + X-Device-Key| Ingest
    BackendCore -->|Service Role PostgREST / Async Buffer| PostgREST
    Security -->|Fetch Trusted JWKS / Key Verification| AuthService
    StreamHub -->|WebSocket (WSS Broadcast)| ReactDashboard
    BackendCore -->|REST API v1| ReactDashboard
    BackendCore -->|REST API v1| FlutterApp
```

---

## ⚡ Feature Inventory

### 1. Real-Time SCADA Digital Twin
- **Authoritative Physical Twin:** SVG projection engine supporting Orthogonal Plan (Top View), Side Elevation Cutaway, and 3D Axonometric Isometric views.
- **Kinematic Diversion Door:** 38 cm door leaf rotating strictly around fixed vertical hinge pin at $(X=40\text{ cm}, Z=70\text{ cm})$ through $0^\circ \to 90^\circ$.
- **Debris Dispersion Simulation:** Particle physics model tracking debris deflection into the secondary diversion channel during high-head events.
- **Radar Sensor Assembly:** Conical measurement beam hitting water surface with animated pulse echo in active states, switching to dashed standby guide lines when offline.

### 2. Predictive Hydraulics & Risk Estimation
- **Differential Head Analysis:** Computes excess head loss ($\Delta h_{excess} = h_{upstream} - (P_{weir} + h_{weir}) - \Delta h_{baseline}(Q_{in})$) across the primary screening net.
- **Blockage Severity Index ($\beta$):** Estimates obstruction fraction ($0.0 \to 1.0$) with localization confidence scores.
- **Time-to-Critical (TTC):** Robust moving-window linear regression ($dh/dt$) forecasting lead time until conduit brim overflow.
- **Automated Actuator Directives:** Real-time computation of diversion angles based on water depth, TTC, blockage severity, and sensor health.

### 3. Operational Mode State Machine
- **Strict Boundary Enforcement:** Operates in `SIMULATION`, `PHYSICAL`, or `SAFE_HOLD` modes.
- **Contamination Prevention:** Rejects physical telemetry in `SIMULATION` mode and rejects simulated telemetry in `PHYSICAL` and `SAFE_HOLD` modes (HTTP 409 Conflict).
- **Safe Hold Lock:** In `SAFE_HOLD` mode, automated dynamic actuation is locked to calibrated fail-safe angle ($0.0^\circ$, nominal drainage).
- **Auditable Ledger:** Every transition records timestamp, source mode, target mode, operator ID, and transition rationale.

### 4. Telemetry Streaming & Historical Scrubbing
- **High-Concurrency Broadcast:** WebSocket endpoint (`/api/v1/telemetry/stream`) broadcasting state updates with bounded per-client queues.
- **Client Topic Filtering:** Selective subscription by data source (`PHYSICAL` vs `SIMULATED`) or specific `sensor_id`.
- **Historical Telemetry Scrubber:** Municipal operators can load historical event windows from Supabase Cloud and replay past storms at $1\times$, $2\times$, or $5\times$ speeds.

### 5. Municipal Incident Management & GIS Mapping
- **Interactive Leaflet GIS Map:** Real-time visualization of drainage conduits, sensor markers, flood risk heatmaps, and citizen incident markers.
- **Civic Incident Lifecycle:** Citizen reporting workflow with photo uploads and municipal dispatch tracking (`REPORTED` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `DISPATCHED` $\rightarrow$ `IN_PROGRESS` $\rightarrow$ `RESOLVED`).

---

## 📐 Digital Twin Specification (P1.0.5 Fidelity)

The Digital Twin strictly reflects the physical sheet-metal drainage model dimensions from engineering drawings:

```
TOP VIEW (PLAN) LAYOUT — 140 cm x 80 cm
===================================================================================
0 cm (Left / Outlet)               70 cm (Hinge Pin)           140 cm (Right / 'IN')
+------------------------------------+--------------------------------------------+ 0 cm (Front Wall)
|                                    |                                            |
|       SECONDARY DIVERSION CHANNEL  |          SIDE DITCH DRAIN                  |
|       (Width = 40 cm)              |          (Width = 40 cm)                   |
|                                    |                                            |
|  [ 40 cm x 50 cm Debris Grate ]    |          [ Stationary Pin (40, 70) ]       |
+====================================*============================================+ 40 cm (Dividing Wall)
|                                    \                                            |
|                                     \  Hinged Diversion Door (Length = 38 cm)   |
|       PRIMARY DRAINAGE CHANNEL       \                                          |
|       (Width = 40 cm)                 \ (Rotates 0° flush to 90° diversion)     |
|                                                                                 |
|                                        [ Overhead Radar Sensor Z=95, Y=62 ]     |
|                                        [ Inflow Flume Region labeled 'IN' ]     |
+---------------------------------------------------------------------------------+ 80 cm (Rear Wall)
|<------------- 40 cm ------------->|<----- 30 cm ----->|<----- 30 cm ----->|< 40 cm >|
|<--------------------------------- 140 cm Overall Length ------------------------>|
```

### Authoritative Dimensions:
- **Overall Dimensions:** Length = $140\text{ cm}$, Width = $80\text{ cm}$, Wall Height = $50\text{ cm}$.
- **Longitudinal Sections:** Left Section = $40\text{ cm}$ ($Z=0 \to 40$), Middle Section = $60\text{ cm}$ ($Z=40 \to 100$), Right Section = $40\text{ cm}$ ($Z=100 \to 140$, labeled `IN`).
- **Internal Sub-Partition:** Located at $Z=70\text{ cm}$, subdividing the $60\text{ cm}$ middle section into two equal $30\text{ cm}$ sections.
- **Transverse Dividing Wall:** Located at $X=40\text{ cm}$, dividing the conduit into equal $40\text{ cm}$ Primary Channel and $40\text{ cm}$ Side Ditch sections.
- **Hinged Diversion Door:**
  - Stationary hinge pin pivot at $(X=40\text{ cm}, Z=70\text{ cm})$.
  - Door leaf length = $38\text{ cm}$, thickness = $1.6\text{ cm}$, vertical height = $36\text{ cm}$.
  - Kinematics: Strictly rotates from $0^\circ$ (flush along longitudinal divider) to $90^\circ$ (deflecting inflow into secondary diversion channel).
- **Sensor Coordinates:**
  - Overhead Radar: $X=60\text{ cm}, Y=62\text{ cm}, Z=95\text{ cm}$ (inlet flume region).
  - DischargeKeeper Actuator: Mounted on crossbeam at $X=40\text{ cm}, Y=60\text{ cm}, Z=70\text{ cm}$.
  - Debris Grate: $40\text{ cm} \times 50\text{ cm}$ horizontal grid in side ditch ($X=2 \to 38, Z=15 \to 65$).

---

## 📡 Telemetry & Operational Modes (P1.1 Integration)

DRAIN-X establishes an unambiguous telemetry source and connection status abstraction:

### Telemetry Sources:
- `SIMULATED`: Generated by mathematical hydraulic simulation or demonstration controls. Explicitly tagged on the UI with cyan badges and canvas watermark banners.
- `LIVE`: Telemetry received from edge hardware (`source: "PHYSICAL"` or `"LIVE"`). Must include valid timestamps.
- `OFFLINE`: Active hardware mode with no connected microcontroller or expired telemetry packets.

### Connection State Transitions:
- **Freshness Window ($\le 15\text{ s}$):** Active hardware reporting within 15 seconds displays `LIVE (ESP32)`.
- **Stale Threshold ($15\text{ s} < \Delta t \le 30\text{ s}$):** Latency exceeding 15 seconds triggers amber status `STALE (>15s)`.
- **Offline Threshold ($> 30\text{ s}$):** Hardware inactive for $>30$ seconds switches to red status `HARDWARE OFFLINE` with top-canvas offline notification banner. Disconnected hardware **never** retains a misleading `LIVE` badge.
- **Fault State:** Sensor returning hardware errors triggers `HARDWARE FAULT`.

### Missing-Value & Actuator Invariants:
1. **No-Zero Fallback Rule:** Disconnected or faulted sensors display as `UNAVAILABLE` rather than substituting `0.0 cm` or `0.0 L/min`.
2. **Commanded vs. Actual State:**
   - Actuator commands are explicitly tagged as `(CMD)` (e.g. `45.0° (CMD)`).
   - If no physical position sensor is installed, actual position displays:
     ```
     ACTUAL: NOT MEASURED (NO SENSOR)
     ```
   - No physical closed-loop feedback is ever fabricated.
3. **Demonstration Mode:** Controlled interactive simulation toggle in camera toolbar (`[HW TRACKING]` $\leftrightarrow$ `[DEMO: ACTIVE]`) with high-visibility canvas watermark.

---

## 🔒 Security Architecture & Governance

- **Edge Device Authentication:** Telemetry ingestion requires `X-Device-Key` header authentication, strictly enforced (fail-closed) in production environments.
- **Cryptographic JWT Verification:**
  - Modern Supabase Auth asymmetric tokens verified using ECDSA P-256 (`ES256`) against public JWKS fetched exclusively from `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`.
  - Symmetric HMAC-SHA256 (`HS256`) verification with minimum secret length enforcement ($\ge 16$ characters).
  - Strict algorithm allowlist: only `ES256` and `HS256` permitted; tokens using `none`, `RS256`, or `RS512` are rejected immediately with 401.
- **Anti-Privilege Escalation:** Trusted roles (`admin`, `municipality`, `worker`, `service_role`) are extracted strictly from `app_metadata.role` or PostgreSQL role. User-controlled `user_metadata` is explicitly rejected for authorization decisions.
- **WebSocket Safety Invariant:** Telemetry WebSockets are strictly read-only monitoring channels; any actuation commands attempted over WebSocket frames are rejected with security warning logs and error responses.
- **CORS & Origin Isolation:** Dynamic origin validation prevents unauthorized cross-origin requests.

---

## 📖 API Reference

All backend API endpoints are versioned under prefix `/api/v1`:

### 1. Telemetry Domain
- `POST /api/v1/telemetry/ingest` (or `POST /api/v1/telemetry`): Ingest single or batched sensor readings. Evaluates fault detection, blockage localization, prediction, and actuator directives.
- `GET /api/v1/telemetry/latest`: Retrieve latest readings across all sensors in active partition.
- `GET /api/v1/telemetry/history/{sensor_id}`: Rolling circular buffer history (up to 500 records).
- `GET /api/v1/telemetry/persistence/historical`: Query persistent Supabase telemetry with `sensor_id`, `source`, `start_time`, `end_time`, and pagination parameters.
- `GET /api/v1/telemetry/analytics/rollup`: 1-minute or 5-minute statistical time-bucket rollups.
- `GET /api/v1/telemetry/stream` (WebSocket): High-throughput live telemetry broadcast hub.

### 2. Status & Operational Mode Domain
- `GET /api/v1/status`: Comprehensive system state, active alerts count, and operational state.
- `GET /api/v1/status/mode`: Current operational mode (`SIMULATION`, `PHYSICAL`, `SAFE_HOLD`).
- `GET /api/v1/status/mode/history`: Auditable ledger of all operational mode transitions.
- `POST /api/v1/status/mode`: Transition operational mode (protected by RBAC).
- `POST /api/v1/status/state`: Set operational state (`STANDBY`, `MONITORING`, `FAULT`, etc.).

### 3. Simulation & Digital Twin Domain
- `GET /api/v1/simulation/state`: Live simulation snapshot, mechanism kinematics, and benchmark metrics.
- `POST /api/v1/simulation/start`: Start deterministic scenario (`GRADUAL_DEBRIS`, `SUDDEN_BLOCKAGE`, etc.).
- `POST /api/v1/simulation/stop`: Stop current scenario.
- `POST /api/v1/simulation/step`: Step simulation by $\Delta t$ seconds.
- `POST /api/v1/simulation/inject_fault`: Inject synthetic sensor or winch jam faults.
- `POST /api/v1/simulation/mechanism/trigger`: Manually trigger debris collection cycle.
- `POST /api/v1/simulation/mechanism/reset`: Reset mechanism to idle bed position.

### 4. Alerts & Incidents Domain
- `GET /api/v1/alerts`: List active or all alerts.
- `POST /api/v1/alerts`: Create system alert.
- `POST /api/v1/alerts/{alert_id}/resolve`: Mark alert as resolved.
- `GET /api/v1/incidents`: List civic drainage incidents with status/severity/category filters.
- `POST /api/v1/incidents`: Submit citizen or worker drainage incident.
- `GET /api/v1/incidents/{incident_id}`: Retrieve incident details.
- `PATCH /api/v1/incidents/{incident_id}`: Update incident status or municipal dispatch notes.

### 5. Edge Device Registry Domain
- `GET /api/v1/devices`: List all registered edge microcontroller nodes.
- `GET /api/v1/devices/{device_id}`: Retrieve device firmware and validation stage.
- `POST /api/v1/devices`: Register or update IoT edge node (protected by RBAC).

### 6. Health & Orchestrator Probes
- `GET /api/v1/health`: Overall service health check, uptime, and system mode.
- `GET /api/v1/health/liveness`: Lightweight process liveness probe for Docker / Kubernetes / Render.
- `GET /api/v1/health/ready`: Deep dependency readiness probe verifying live Supabase PostgREST connectivity.

---

## 🗄 Database & Persistence

DRAIN-X uses Supabase PostgreSQL 15 with declarative SQL migrations:

### Migration Inventory:
1. `database/migrations/001_initial_schema.sql`: Core schema for `drainage_sections`, `sensor_metadata`, `sensor_readings`, `sensor_readings_rollup`, `alerts`, `blockage_events`, and `predictions`.
2. `database/migrations/002_devices_and_mode_history.sql`: Edge `devices` registry, foreign key linkage to `sensor_readings`, operational mode history audit table, and time-series composite indexes.
3. `database/migrations/003_supabase_rls_and_security.sql`: Row Level Security policies across all 10 tables, least-privilege role boundaries, and composite lookup indexes.

### Key Database Indexes:
- `idx_sensor_readings_sensor_ts`: `(sensor_id, timestamp DESC)`
- `idx_sensor_readings_source_ts`: `(source, timestamp DESC)`
- `idx_sensor_readings_composite_lookup`: `(sensor_id, source, timestamp DESC)`
- `idx_sensor_readings_device_ts`: `(device_id, timestamp DESC)`
- `idx_mode_history_timestamp`: `(timestamp DESC)`

---

## 🚀 Installation & Local Setup

### Prerequisites:
- Python 3.12+
- Node.js 20+ and npm 10+
- Git

### 1. Backend Setup
```bash
cd backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # On Linux/macOS: source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend development server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API documentation: `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open `http://localhost:5173` to access the municipal digital twin dashboard.

### Environment Configuration:
Copy template configuration: `cp backend/.env.example backend/.env`.
```ini
ENVIRONMENT=development
DEBUG=true
SYSTEM_MODE=SIMULATION
DEVICE_INGEST_API_KEY=local_development_device_key
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
SUPABASE_JWT_SECRET=your-hs256-secret-min-16-chars
```

---

## 🧪 Automated Testing & Quality Verification

DRAIN-X enforces strict quality gates through comprehensive automated test suites across all layers. All testing is conducted software-only without hardware dependencies.

### Verified Test Summary (P1.2 Baseline):
- **Backend Test Suite (Pytest):** **161 passed** in 3.2s
  - `test_api.py`: 5 passed
  - `test_authenticated_rls.py`: 6 passed
  - `test_contracts.py`: 7 passed
  - `test_esp32_integration.py`: 7 passed
  - `test_hardware_telemetry_pipeline.py`: 8 passed
  - `test_hydraulic_and_prediction.py`: 5 passed
  - `test_incidents_api.py`: 12 passed
  - `test_jwt_verification.py`: 12 passed
  - `test_operational_modes.py`: 16 passed
  - `test_persistence_repository.py`: 5 passed
  - `test_scenario_benchmark.py`: 5 passed
  - `test_screening_mechanism.py`: 3 passed
  - `test_simulation_api.py`: 5 passed
  - `test_sit_comprehensive.py`: 26 passed
  - `test_supabase_cloud_integration.py`: 19 passed
  - `test_telemetry_stream.py`: 13 passed
  - `test_time_series_analytics.py`: 7 passed
- **Frontend Test Suite (Vitest):** **77 passed across 10 test suites** in 11.9s
  - `src/tests/contracts.test.ts`: 5 passed
  - `src/tests/playbackEngine.test.ts`: 4 passed
  - `src/tests/client.test.ts`: 9 passed
  - `src/tests/streamClient.test.ts`: 10 passed
  - `src/tests/diversionGateTwin.test.tsx`: 7 passed
  - `src/tests/streamIntegration.test.tsx`: 3 passed
  - `src/tests/gisDashboard.test.tsx`: 8 passed
  - `src/tests/citizenAndMunicipal.test.tsx`: 8 passed
  - `src/tests/historicalPlayback.test.tsx`: 4 passed
  - `src/tests/longitudinalSideDrainTwin.test.tsx`: 19 passed (including 10 P1.1 regression scenarios)
- **Frontend Production Build:** Successful compilation with TypeScript check; 1653 modules transformed into 530 kB JS bundle (144 kB gzip).
- **Total System Test Count:** **238 automated tests passed**.

---

## ☁️ Deployment Architecture

DRAIN-X is configured for staging hosting across independent cloud tiers:

```
[ ESP32 Microcontroller ] ---> [ Render Web Service ] ---> [ Supabase Cloud ]
 (HTTPS + X-Device-Key)          (FastAPI ASGI Docker)       (PostgreSQL 15 + RLS)
                                          ^
                                          | (WSS / REST)
                               [ Vercel Edge Hosting ]
                                (React + Vite SPA)
```

### Hosting Environments:
- **Backend ASGI:** Deployed on Render (`https://drainx-backend.onrender.com`). Packaged via `backend/Dockerfile` with non-root security user and dynamic `$PORT` binding.
- **Frontend SPA:** Deployed on Vercel (`https://drain-x.vercel.app`). Configured via `frontend/vercel.json` with SPA route rewrites and security headers.
- **Database & Auth:** Supabase Cloud PostgreSQL with connection pooling and automated RLS enforcement.

> [!NOTE]
> The public URLs above represent the previously staged application baseline. The latest local P1.0.5, P1.1, and P1.2 enhancements are currently held as a local release candidate pending operator synchronization.

---

## 🛠 Hardware Status & Prototype Boundary

The physical counterpart of DRAIN-X is an indoor sheet-metal flume modeling an urban drainage channel with a longitudinal side-drain diversion.

### Current Physical Boundary:
- **Assembly State:** Physical sheet-metal flume is currently being fabricated and assembled.
- **Microcontroller Connection:** The ESP32 is **not** connected to the running backend.
- **Sensors:** Ultrasonic sensors and Hall-effect flow meters are **not** calibrated on live water channels.
- **Actuators:** Servomotor gates are **not** executing physical movement under live load.
- **Testing Standard:** All tests and demonstration workflows run purely in software using synthetic physics, mathematical hydraulic models, and software mocks.
- **Competition Demonstration:** Hackathon demonstrations operate in software **Demonstration Mode** without requiring live water circulation.

---

## 🗺 Development Roadmap

```text
[ COMPLETED ] ================================> P1.0.5, P1.1, P1.2 (Twin Fidelity, Reliability, Backend Audit)
[ NEXT PHASE ] ===============================> P1.3 (Mock Edge Adapter & Standby Actuator Directives)
[ PLANNED ] ==================================> P1.4 to P1.5 (Flutter Mobile Suite, Physical Bench Wiring)
[ FUTURE / EXPLORATORY ] =====================> Post-P2.0 (Computer Vision Silt Classification, Edge SLM)
```

### Next Phases:
1. **P1.3 — Edge Adapter & Mock Ingestion Test Harness:** Standalone Python client simulating ESP32 telemetry with realistic sensor noise and polling actuator directives.
2. **P1.4 — Unified Flutter Mobile Application:** Completing mobile interfaces for citizen geotagged reporting and municipal worker remediation updates.
3. **P1.5 — Physical ESP32 Hardware Integration:** Wiring bench sensors, flashing verified PlatformIO firmware, and conducting end-to-end hardware ingestion.
4. **P2.0 — Edge Vision & AI:** Computer vision debris volume estimation and on-device Small Language Models (SLMs) for municipal field queries.

---

## ⚠️ Project Limitations

1. **No Field Validation:** DRAIN-X is a laboratory prototype and digital twin simulation platform; it has not been deployed or certified in live municipal storm sewers.
2. **Uncalibrated Sensor Metrics:** Physical sensor readings in bench testing do not represent calibrated open-channel flow coefficients.
3. **Open-Loop Actuator Command:** Without a dedicated rotary encoder or potentiometer on the diversion door, servo PWM commands represent commanded intent, not measured mechanical position.
4. **Hydraulic Simplifications:** The mathematical hydraulic model assumes 1D steady/gradually varied open-channel flow and does not compute full 3D hydrodynamic turbulence.

---

## 👥 Team & License

**Developed by Team NIRAKSHAN:**
- **Initiative:** IDEAS 5.0 — Idea to Impact
- **Lead Developer & System Architect:** Jonathan Raposo
- **Repository:** [https://github.com/jonathanraposo20/Drain-X](https://github.com/jonathanraposo20/Drain-X)
- **License:** Distributed under the [MIT License](LICENSE).
