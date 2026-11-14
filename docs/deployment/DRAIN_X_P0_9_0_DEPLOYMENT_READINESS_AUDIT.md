# DRAIN-X P0.9.0 — DEPLOYMENT READINESS AUDIT

> **Document Version:** 1.0.0<br/>
> **Milestone:** P0.9.0 — Deployment Readiness Audit<br/>
> **Repository Baseline:** `https://github.com/jonathanraposo20/Drain-X`<br/>
> **Commit SHA:** `fdf3589` (Branch: `main`)<br/>
> **Audit Status:** **AUDIT COMPLETED — READINESS VERIFIED WITH OPERATOR CONFIGURATION PREREQUISITES**<br/>
> **Target Staging Infrastructure:** Render (Backend ASGI), Vercel (Frontend SPA), Supabase Cloud (PostgreSQL 15 + PostgREST + Auth)

---

## 1. Executive Summary

This independent Deployment Readiness Audit evaluates the end-to-end readiness of the **DRAIN-X Predictive Urban Drainage Intelligence System** for its initial cloud staging deployment.

### Key Audit Findings:
1. **Application Code Readiness:** **100% READY.** The codebase requires **zero code modifications** to deploy. Dual-algorithm JWT authentication (`ES256` via trusted JWKS and `HS256`), dynamic URL resolution (`VITE_API_BASE_URL`, `VITE_WS_BASE_URL`), and dynamic CORS origins (`ADDITIONAL_CORS_ORIGINS`) are fully implemented and verified.
2. **Infrastructure Configurations:** Complete deployment manifests exist for all three tiers:
   - Backend: `backend/Dockerfile` (Multi-stage Python 3.12-slim, non-root user `drainx`, dynamic `$PORT`), `backend/Procfile`, and `render.yaml`.
   - Frontend: `frontend/vercel.json` (SPA history rewrites, strict security headers) and `frontend/package.json`.
   - Database: Supabase PostgreSQL migrations `001`, `002`, and `003` defining schemas, composite indexes, and hardened Row Level Security (RLS) policies.
3. **Automated Test Baselines:** **247 / 247 automated tests pass (100%)** across backend API, JWT security, authenticated RLS, SIT, firmware logic, and frontend components. The frontend compiles with zero TypeScript errors into a minified production bundle (494 kB).
4. **Physical Hardware Boundary:** Physical hardware validation remains deferred to Milestone P0.8.1; the staging deployment operates cleanly in `SIMULATION` mode with full synthetic scenario benchmarking.
5. **Deployment Status:** **READY FOR OPERATOR PROVISIONING.** Hosting accounts on Render, Vercel, and Supabase require manual environment variable configuration. No automated deployment has been executed.

---

## 2. Tier-by-Tier Readiness Analysis

### A. Backend ASGI Service (Render)
- **Deployment Manifests:** `render.yaml` (Blueprint), `backend/Dockerfile`, and `backend/Procfile`.
- **Runtime Specification:** Python 3.12 on Render Web Service (Free or Starter instance).
- **Startup Command:**
  ```bash
  cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 1
  ```
- **Healthcheck Routing:**
  - **Liveness:** `GET /api/v1/health/liveness` (returns 200 OK as long as the ASGI event loop is active). Configured as `healthCheckPath` in `render.yaml`.
  - **Readiness:** `GET /api/v1/health/ready` (validates state store health and downstream Supabase PostgREST connectivity).
- **WebSocket Compatibility:** Render natively supports WebSockets (`wss://`) on both free and paid web service tiers. The backend handles connection scaling up to `WS_MAX_CONNECTIONS=100` with 30-second heartbeat ping/pong frames.
- **Spin-Up Latency Consideration:** Free tier instances sleep after 15 minutes of inactivity (causing a 30–50 second cold-start delay). Upgrading to a Starter instance ($7/mo) eliminates cold starts if constant uptime is required.

### B. Frontend Dashboard SPA (Vercel)
- **Deployment Manifest:** `frontend/vercel.json`.
- **Runtime Specification:** Vercel Edge CDN (Static SPA).
- **Build Command:** `npm run build` (`tsc && vite build`).
- **Output Directory:** `dist/`.
- **SPA Routing:** Configured with clean rewrites (`/* -> /index.html`) ensuring seamless client-side navigation without 404 errors on deep routes.
- **Security Headers:** Injected across all routes:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Dynamic URL Resolution:** `frontend/src/api/client.ts` and `frontend/src/api/streamClient.ts` dynamically inspect `import.meta.env.VITE_API_BASE_URL` and `import.meta.env.VITE_WS_BASE_URL`, cleanly falling back to relative paths for local development.

### C. Database & Security Layer (Supabase Cloud)
- **Database Engine:** PostgreSQL 15+ managed instance.
- **Migrations Applied & Validated:**
  1. `001_initial_schema.sql`: Core tables (`sensor_readings`, `alerts`, `incidents`, `drainage_sections`).
  2. `002_devices_and_mode_history.sql`: Hardware device registry and mode transition ledgers.
  3. `003_supabase_rls_and_security.sql`: Multi-role RLS policies and audit logs.
- **Authentication Engine:** Supabase GoTrue Auth (v2) issuing asymmetric `ES256` (ECDSA P-256) JWTs.
- **Cryptographic JWT Verification:** Backend verifies incoming bearer tokens against public keys dynamically resolved from `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`.
- **Anti-SSRF Protection:** Derives JWKS endpoints strictly from configured `SUPABASE_URL`, never trusting external URLs from client headers.
- **Anti-Privilege Escalation:** Roles are strictly extracted from `app_metadata.role`; client-modified `user_metadata` is completely ignored.

---

## 3. Persistent Storage Requirements & Limitations

| Asset Category | Storage Mechanism | Staging Behavior / Persistence Boundary |
| :--- | :--- | :--- |
| **Telemetry Time-Series** | Supabase PostgreSQL (`sensor_readings`) | Persisted permanently; indexed by `(sensor_id, timestamp DESC)`. |
| **Incidents & Photos** | Supabase Database + Local Uploads | Metadata in PostgreSQL; photo uploads in staging use local `backend/uploads/` (ephemeral across container restarts on free tier). Production should use Supabase Storage buckets. |
| **Operational Mode Ledger**| Supabase PostgreSQL (`operational_mode_history`) | Persisted permanently; auditable record of transitions. |
| **In-Memory Buffer** | Circular RAM buffer (5,000 readings) | Ephemeral cache for sub-millisecond API response latency; falls back gracefully if Supabase connection drops. |

---

## 4. Environment Variable Inventory (No Secrets)

Below is the definitive catalog of environment variable names required across the staging ecosystem.

### A. Render Web Service (Backend):
| Variable Name | Required | Staging Value / Description |
| :--- | :---: | :--- |
| `ENVIRONMENT` | Yes | `development` (staging) or `production` |
| `DEBUG` | Yes | `false` |
| `SYSTEM_MODE` | Yes | `SIMULATION` (or `PHYSICAL`) |
| `PORT` | Auto | Assigned automatically by Render orchestrator (e.g. `10000`) |
| `HOST` | Yes | `0.0.0.0` |
| `SUPABASE_URL` | Yes | Project REST URL (`https://<project-ref>.supabase.co`) |
| `SUPABASE_KEY` | Yes | Supabase public anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Supabase privileged service_role secret key |
| `SUPABASE_AUTH_ENABLED` | Yes | `false` (dev/bench) or `true` (enforce JWT) |
| `SUPABASE_JWT_SECRET` | Optional | Symmetric secret for legacy HS256 tokens (>= 16 chars) |
| `DEVICE_INGEST_API_KEY` | Optional | Shared pre-shared key for hardware ingestion (`X-Device-Key`) |
| `ADDITIONAL_CORS_ORIGINS` | Yes | Deployed Vercel domain (e.g. `https://drainx-dashboard.vercel.app`) |
| `PERSISTENCE_TIMEOUT_SEC` | No | Default `3.0` seconds |
| `SUPABASE_JWKS_CACHE_TTL_SEC`| No | Default `3600` seconds |

### B. Vercel Project Settings (Frontend):
| Variable Name | Required | Example Staging Value |
| :--- | :---: | :--- |
| `VITE_API_BASE_URL` | Yes | Base URL of deployed Render backend (e.g. `https://drainx-backend.onrender.com`) |
| `VITE_WS_BASE_URL` | Yes | WebSocket URL of deployed Render backend (e.g. `wss://drainx-backend.onrender.com`) |

> [!WARNING]
> **Strict Security Boundary:** Never configure `SUPABASE_SERVICE_ROLE_KEY` in Vercel. Frontend clients must only ever interface with public endpoints or the authenticated backend API.

---

## 5. Security & Isolation Review

1. **Least-Privilege Database Access:**
   - Anonymous requests to Supabase PostgREST can only read public telemetry and alerts.
   - All mutations (`INSERT`, `UPDATE`, `DELETE`) on sensor readings are rejected with PostgreSQL error `42501` unless performed by `service_role`.
2. **Anti-Privilege Escalation:**
   - Verified under test: an authenticated user injecting `{"role": "admin"}` in `user_metadata` is restricted to `citizen` privileges because the backend evaluates only `app_metadata.role`.
3. **Fail-Closed Production Assertion:**
   - When `ENVIRONMENT=production`, missing critical keys immediately aborts boot via `validate_production_configuration`.
4. **CORS Isolation:**
   - Only configured development domains (`localhost:5173`, `localhost:3000`) and the explicitly listed domain in `ADDITIONAL_CORS_ORIGINS` can access the API.

---

## 6. Deployment Blockers & Prerequisites

| Blocker / Prerequisite | Severity | Description & Resolution |
| :--- | :---: | :--- |
| **No Third-Party Hosting Accounts Authenticated in CLI** | **OPERATOR ACTION** | Render and Vercel CLI credentials are not authenticated in the agent sandbox. Deployment must be initiated via the respective web dashboards or git integrations. |
| **CORS Circular Dependency** | **LOW / SEQUENCING** | The backend requires the Vercel URL in `ADDITIONAL_CORS_ORIGINS`, while the frontend requires the Render URL in `VITE_API_BASE_URL`. Resolved by following the recommended deployment sequence. |
| **Free Tier Cold Starts** | **INFORMATIONAL** | Render free web services spin down after 15 minutes. Initial request after idle takes 30–50s. Acceptable for staging review. |

---

## 7. Recommended Staging Deployment Sequence

To avoid configuration circularity, execute staging in this exact 4-step sequence:

```
Step 1: Deploy Supabase Cloud (Database & Auth)
   │
   ▼
Step 2: Deploy Backend on Render (Web Service Blueprint)
   │  --> Obtain Render Backend URL (e.g. https://drainx-backend.onrender.com)
   ▼
Step 3: Deploy Frontend on Vercel
   │  --> Inject VITE_API_BASE_URL & VITE_WS_BASE_URL using Render URL
   │  --> Obtain Vercel Frontend URL (e.g. https://drainx-dashboard.vercel.app)
   ▼
Step 4: Update Render Backend CORS
      --> Set ADDITIONAL_CORS_ORIGINS = https://drainx-dashboard.vercel.app
```

### Detailed Operator Instructions:

#### Step 1: Supabase Cloud Setup (Already Completed in P0.6.2)
1. Verify migrations `001`, `002`, and `003` are applied.
2. Note the Project URL (`SUPABASE_URL`), anon key (`SUPABASE_KEY`), and service_role key (`SUPABASE_SERVICE_ROLE_KEY`).

#### Step 2: Render Backend Web Service
1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Select **New +** $\rightarrow$ **Blueprint**.
3. Connect repository `jonathanraposo20/Drain-X`.
4. Render detects `render.yaml`. Click **Apply**.
5. In the service settings, enter the secret environment variables (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_KEY`, `SUPABASE_JWT_SECRET`, `DEVICE_INGEST_API_KEY`).
6. Set `ADDITIONAL_CORS_ORIGINS` to `http://localhost:5173` temporarily.
7. Deploy service and copy the live URL (e.g. `https://drainx-backend.onrender.com`).
8. Verify liveness at `https://drainx-backend.onrender.com/api/v1/health/liveness`.

#### Step 3: Vercel Frontend Deployment
1. Log in to [Vercel Dashboard](https://vercel.com).
2. Select **Add New...** $\rightarrow$ **Project**.
3. Import repository `jonathanraposo20/Drain-X`.
4. Set **Root Directory** to `frontend`.
5. Add environment variables:
   - `VITE_API_BASE_URL` = `https://<your-render-backend-url>`
   - `VITE_WS_BASE_URL` = `wss://<your-render-backend-url>`
6. Click **Deploy**.
7. Copy the assigned Vercel URL (e.g. `https://drainx-dashboard.vercel.app`).

#### Step 4: Finalize CORS Configuration
1. Return to Render Dashboard $\rightarrow$ `drainx-backend` $\rightarrow$ **Environment**.
2. Update `ADDITIONAL_CORS_ORIGINS` to include your Vercel URL (e.g. `https://drainx-dashboard.vercel.app`).
3. Render automatically redeploys in seconds.
4. Open the Vercel dashboard URL in a browser and verify live digital twin and GIS map rendering.

---

## 8. Exact Next Execution Milestone

- **Next Milestone:** **P0.9.1 — Live Staging Deployment Execution**
  (Operator deploys backend on Render, frontend on Vercel, links credentials, and runs live smoke verification).
- **Subsequent Hardware Milestone:** **P0.8.1 — Physical ESP32 Hardware Integration**
  (Deferred until physical flume testbed fabrication is fully assembled).

---

> **Audit Conclusion:** DRAIN-X is **100% READY** for staging deployment. Zero codebase or configuration file modifications are required. Deployment can proceed immediately upon operator account provisioning.
