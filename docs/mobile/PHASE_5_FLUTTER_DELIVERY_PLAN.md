# DRAIN-X Phase 5 — Flutter Mobile Delivery Plan

**Status:** ACTIVE  
**Authorized:** 2026-11-26  
**Scope:** Flutter citizen, municipality, and field-worker application workflows against the existing FastAPI/Supabase backend.

## Starting point

The repository already contains a Flutter application under mobile/ with:
- Role-specific welcome and login screens for citizen, municipality, and worker.
- Role-guarded routes and separate citizen, municipal, and worker dashboards.
- Incident reporting, incident detail, municipal triage, and worker task UI.
- A shared API client, incident model, location/media helpers, theme, and unit tests.
- Supabase password-grant login in AuthService.

This is an existing implementation to audit and complete, not a greenfield app. Preserve working screens and behavior; avoid wholesale rewrites.

## Phase 4 disposition

Phase 4 is administratively closed with accepted deferrals. The following remain unverified and must not be represented as passed: production Auth login/refresh, full live JWT/RBAC matrix, complete incident lifecycle, private evidence upload/download and isolation, duplicate confirmation, SAFE_HOLD, live rate limiting, and production CORS. Revisit before field rollout or claiming complete production security acceptance.

## Delivery principles

1. FastAPI remains the authorization and business-logic boundary. The mobile app must never contain Supabase service-role credentials or call privileged database RPCs directly.
2. Read roles only from trusted Supabase app_metadata.role. Unknown/missing roles fail closed to citizen-level access.
3. Demo sessions remain clearly separate from production-authenticated sessions and must never attach fake bearer tokens.
4. Implement refresh-token renewal and secure session persistence before calling the Auth lifecycle complete. Handle refresh rotation, expiry, invalid refresh tokens, logout, and concurrent 401s.
5. Preserve API contracts and status semantics. A 403 must not log the user out; a 401 invalidates or refreshes the session safely.
6. Treat location and photo permissions as optional; provide graceful denial, validation, upload progress, and retry states.
7. No production data mutation or role changes for test convenience. Use mocks/local fixtures for development; live checks require dedicated test accounts and explicit coordination.
8. Keep dependency versions pinned in pubspec.lock and avoid paid services or infrastructure changes without approval.

## Work sequence

### P5.0 — Baseline and contract audit
- Run Flutter analyze and the complete mobile test suite.
- Inventory every screen, API method, endpoint, request/response model, and role requirement.
- Compare mobile API paths and payloads against the deployed FastAPI OpenAPI contract.
- Identify hard-coded demo/fallback data and ensure it cannot be mistaken for production data.
- Establish a clean baseline report before feature changes.

### P5.1 — Authentication foundation
- Implement Supabase refresh-token exchange and refresh rotation.
- Add secure token/session persistence using platform secure storage.
- Restore valid sessions on app launch; route by verified role.
- Serialize refresh attempts to avoid refresh-token reuse races.
- Test login, refresh, expired/invalid refresh token, logout, 401, 403, role parsing, and user_metadata privilege-escalation rejection with mocks.

### P5.2 — Citizen workflow
- Complete incident creation with location, category, severity, description, and optional photo.
- Show submission progress, validation, retry, and server-generated incident reference.
- List and inspect the citizen's own reports according to backend privacy rules.
- Verify refresh/pagination and empty/error/offline states.

### P5.3 — Municipality workflow
- Complete queue filters, incident detail, verification, assignment/reassignment, rejection, status transitions, and audit history.
- Use canonical team IDs and backend-returned assignment state; do not infer successful assignment from UI state.
- Display permission, conflict, and validation errors clearly.

### P5.4 — Worker workflow
- Restrict task views and actions to backend-authorized assignments.
- Support task acknowledgement/progress and resolution evidence only where the backend contract permits.
- Never trust a client-supplied team name as authorization.

### P5.5 — Reliability, accessibility, and release
- Add offline/poor-network behavior, bounded retries, loading/error/empty states, and safe request cancellation.
- Verify Android permissions, app lifecycle, responsive layouts, accessibility labels, and localization readiness.
- Run analyze, unit/widget tests, Android debug/release builds, and an end-to-end test matrix against a non-production or dedicated test environment.
- Produce a release checklist and record remaining live-production verification risks.

## Immediate next task

P5.0 baseline: inspect the existing mobile tests and API client against backend OpenAPI, run Flutter analyze/tests, then publish a gap list. Do not begin a broad UI redesign until the contract and baseline are known.
