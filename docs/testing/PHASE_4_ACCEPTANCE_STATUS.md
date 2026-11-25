# DRAIN-X — Phase 4 Production Acceptance Status

**Last updated:** 2026-11-26  
**Overall classification:** CLOSED WITH ACCEPTED DEFERRALS — residual production verification risks remain documented.

This closure records stakeholder acceptance of the remaining live checks as deferred so Phase 5 mobile development can proceed. It does **not** represent those deferred checks as passed or fully validated.

## Verified evidence

| Area | Evidence | Status |
|---|---|---|
| Incident assignment normalization | PR #9 merged; backend CI 680 passed, 9 skipped, 2 warnings | PASS |
| Production incident update | PATCH /api/v1/incidents/PG-R2-F885435C → HTTP 200 | PASS |
| Persisted assignment state | Supabase readback: VERIFIED, assignment_type=TEAM, assigned_team_id=TEAM-DELTA | PASS |
| Original failing incident | PG-R1-F885435C remains REPORTED, assignment NONE; preserved | PASS |
| GIS basemap | OSM Standard default; user confirmed watermark removed | PASS |
| Citizen report modal | PR #10 merged and production deployment READY; user visually confirmed layout | PASS |
| Dashboard KPI cleanup | PR #11 merged and production deployment READY; production bundle no longer contains KPI strip/component; user confirmed UI | PASS |
| Anonymous protected-route denial | Production GET mode history and POST operational-state mutation both returned HTTP 401 | PASS |
| Automated backend authorization tests | Existing tests cover citizen, municipality, worker, admin and anonymous paths | PASS — automated only |

## Previously verified technical baseline

- Disposable PostgreSQL 17 validation applied migrations 001–008; migration 008 reapplication/idempotency passed.
- Disposable database backend suite: 673 passed.
- Backup/restore validation completed with object and representative row parity.
- GitHub Actions backend CI for PR #9: 680 passed, 9 skipped, 2 warnings.
- Frontend: 94 Vitest tests previously verified.
- Production Render health/readiness and public status endpoints previously returned HTTP 200.
- Production Supabase health advisor had no findings at the time of audit.
- Storage bucket incident-evidence is private; live upload/download workflow was not verified.

These are separate runs/configurations and must not be added into one test count.

## Accepted deferrals — not passed

The stakeholder accepted deferring the following live production checks so mobile development can proceed:

1. Supabase Auth login and refresh lifecycle; the inspected Flutter AuthService currently lacks refresh-token renewal.
2. Full live JWT/RBAC matrix for citizen, municipality, admin and worker. Production inventory previously showed one citizen, two municipality, one worker and no admin account.
3. Full incident write lifecycle across create, verify, assign, worker update, resolve/reject and audit trail.
4. Private Storage evidence upload, authorized download and cross-incident access denial.
5. Duplicate incident scan and confirmation workflow.
6. SAFE_HOLD transition and safety behavior.
7. Live rate-limit burst behavior (429).
8. Production CORS allowed-origin and unapproved-origin verification.

The successful municipal PATCH covers one update path only. Anonymous 401 tests do not prove authenticated role behavior. Automated RBAC tests do not replace live JWT checks.

## Security and operational notes

- Production incident transaction RPC execution is restricted to backend service_role; browser clients should use the FastAPI boundary.
- Production Supabase migration history does not mirror the repository's original numbered migration sequence. Do not infer that every repository migration was applied from history records.
- Leaked-password protection remains disabled because it is a Pro-only feature and no paid upgrade was authorized.
- Nine internal tables were previously observed with RLS enabled and no direct policies; anon/authenticated effective privileges were audited as absent. Do not change these permissions without separate review.
- Vercel had 16 identified unused environment-variable entries requiring manual review/removal. Privileged backend credentials belong only on Render.
- No paid infrastructure changes are part of this acceptance.

## Phase 4 disposition

**Phase 4 is administratively closed with accepted deferrals, not an unconditional technical PASS.** The deferred checks remain open risks and should be revisited before any production/field rollout or claims of complete security acceptance.

Phase 5 Flutter development is authorized to proceed. Mobile implementation must preserve the existing backend authorization boundary, use trusted app_metadata.role claims, and avoid treating demo sessions as production authentication.
