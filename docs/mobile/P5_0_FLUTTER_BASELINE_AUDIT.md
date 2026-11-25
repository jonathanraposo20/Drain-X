# DRAIN-X — P5.0 Flutter Baseline & API Contract Audit

**Date:** 2026-11-26  
**Repository:** `jonathanraposo20/Drain-X` (`main`)  
**Disposition:** Static source audit completed; runtime baseline pending local Flutter SDK execution.

## 1. Existing implementation inventory

The mobile app is an existing multi-screen Flutter application, not a blank starter:

- App shell and role-guarded navigation for citizen, municipality, and field worker.
- Demo and Supabase password login flows.
- Citizen dashboard, report form, report detail, GPS acquisition, and camera/gallery photo selection.
- Municipal dashboard, incident detail, field-team selection, verify/assign/reassign/unassign/reject actions, and audit history.
- Worker dashboard and incident/task detail flow.
- Shared incident model, API client, validators, theme, empty states, and badges.
- Eight test files: auth service, citizen reporting workflow, incident model, municipal dashboard, municipal triage assignment, route guards, session reliability, and app widget smoke test.

Dependencies currently include `geolocator`, `http`, `http_parser`, `image_picker`, and `intl`. The inspected pubspec does not include a secure-storage package.

## 2. Confirmed gaps and risks

### P0 — Must address before production mobile authentication / evidence upload

1. **No refresh-token exchange.** `AuthService.loginWithCredentials` stores access and refresh tokens in an in-memory `UserSession`, but the inspected AuthService contains no refresh-token grant implementation. `ApiClient` currently clears the session on token expiry or HTTP 401 rather than attempting a refresh.
2. **No secure session persistence or app-start restoration.** Session state is held in the AuthService singleton's memory. No secure storage dependency or restore-on-launch path was found in the inspected mobile project.
3. **Photo upload omits required cloud idempotency header.** The backend upload route requires a valid `Idempotency-Key` header in cloud mode. The mobile multipart upload code inspected sends Authorization but does not add that header. This will fail closed in production cloud mode until fixed.
4. **Citizen “MINE” filter relies on reporter name.** The citizen dashboard filters its local incident list by matching `reporterName`. The backend intentionally redacts `reporter_name` for citizen responses. The current client-side matching therefore cannot reliably identify the signed-in citizen's own reports. A backend-owned identity filter/endpoint or explicit safe ownership field is needed; do not weaken reporter privacy.
5. **Worker task filtering is client-side and uses display-name assignment.** The worker dashboard fetches the general incident list and filters `assignedTo == widget.assignedTeam`. Backend authorization for worker writes checks verified JWT subject/team claims, but the UI's local display-name filter is not an authorization boundary and can be out of sync with canonical `assigned_team_id` / `assigned_worker_id`. The worker view should use a server-authorized assigned-task endpoint or server-side filter tied to trusted claims.

### P1 — Configuration, roles, and workflow completeness

6. **Runtime API/Auth configuration is not wired in the inspected config.** `ApiConfig.baseUrl` defaults to Android emulator localhost, while `supabaseUrl` and `supabaseAnonKey` are nullable and initially unset. A deliberate environment configuration path is required for local, staging, and production builds. Only the Supabase anon/publishable key may be shipped in the client; never a service-role key.
7. **Admin role is collapsed into the municipality enum in the mobile model.** `UserRole.fromString('admin')` maps to `UserRole.municipality`. This may be acceptable for shared dashboard access, but it loses the distinction and must not imply admin-only capabilities.
8. **Worker team context has a hard-coded fallback label.** The app route supplies a sample Team Alpha label when the session has no assigned team. This is demo-friendly but must not be used to decide real task visibility or permissions.
9. **Photo upload flow needs contract verification beyond the header.** Confirm backend response semantics, supported file count/size, MIME validation, and incident-scoped photo retrieval route. The legacy filename-only photo route is not the canonical route for current content-addressed evidence.

## 3. API contract comparison

The inspected client methods have corresponding backend routes for:

- `GET/POST /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `PATCH /api/v1/incidents/{incident_id}`
- `GET /api/v1/incidents/municipal/kpis`
- `GET /api/v1/incidents/municipal/queue`
- `GET /api/v1/incidents/field-teams`
- `POST /{incident_id}/verify`, `/assign`, `/reassign`, `/unassign`, `/reject`
- `GET /{incident_id}/audit`
- `POST /{incident_id}/photos`

The backend additionally exposes duplicate scan/list/confirm/dismiss flows and incident-scoped photo retrieval. These were not present in the inspected ApiConfig client method inventory and should be considered optional follow-on mobile capabilities unless the existing screens already implement them through another path.

Important backend behavior confirmed in source:

- General incident list/detail endpoints apply role-aware response redaction.
- Municipal queue and KPI endpoints require municipality/admin/service_role.
- Verify/assignment/reassignment/unassignment/rejection/audit endpoints require municipality/admin/service_role.
- Worker mutation authorization checks trusted JWT subject and team claims server-side.
- Cloud photo upload requires `Idempotency-Key`; do not disable this backend requirement to accommodate the client.

## 4. Existing test coverage (source inventory only)

The test suite contains focused tests for:

- Demo sessions, role parsing from `app_metadata.role`, and rejection of editable `user_metadata.role` for privilege assignment.
- Session expiry preflight, 401 invalidation, 403 session preservation, and no bearer token in demo mode.
- Citizen form validation, location success/denial/timeout, report submission, and photo selection/upload paths.
- Municipal dashboard rendering and triage API request/response contracts.
- Incident JSON parsing and lifecycle transition helpers.
- Route guards and navigation.

These tests are mock-driven. They do not establish live Supabase authentication, refresh rotation, secure-storage behavior, cloud Storage authorization, or production role behavior.

## 5. Runtime test status and limitation

**Flutter analyze and `flutter test` were not executed in this audit.** The repository connector can inspect source files but does not provide a local Flutter SDK/runtime. No green runtime result is claimed.

Run from the repository's `mobile` directory on the development machine:

```powershell
flutter --version
flutter pub get
flutter analyze
flutter test --reporter expanded
```

Capture the exact Flutter/Dart versions and full command summaries. Do not update dependencies or regenerate `pubspec.lock` until the baseline has been recorded.

## 6. Recommended execution order

1. Establish the local runtime baseline (`flutter analyze`, full `flutter test`) and fix baseline failures without broad refactors.
2. Resolve the P0 contract/security gaps: refresh-token lifecycle, secure session persistence, upload idempotency key, citizen own-report retrieval, and server-authorized worker task listing.
3. Add mock tests for each correction, including refresh-token rotation and concurrent 401 behavior.
4. Add build-time environment configuration and verify local/staging/production URL selection.
5. Continue the role-specific workflows and release verification.

## 7. Guardrails

- FastAPI remains the authorization/business-logic boundary; never place Supabase service-role credentials in Flutter.
- Trust roles and worker team affiliation only from verified `app_metadata` claims.
- Do not use display names, client filters, or demo fallback values as authorization.
- Preserve 403 as permission denial without logging out; refresh/retry a 401 only when a valid refresh token exists, otherwise clear the session.
- Use mocks or dedicated non-production accounts for tests. Do not mutate production users, roles, or incident data to make the app pass tests.
- Phase 4's accepted live verification deferrals remain unverified and must be revisited before field rollout.
