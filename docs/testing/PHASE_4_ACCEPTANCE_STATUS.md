# DRAIN-X — Phase 4 Production Acceptance Status

**Last updated:** 2026-11-26  
**Overall classification:** Conditional pass — Phase 4 is not formally closed.

This report records the verified deployment and acceptance evidence available at the time of update. A successful build or local test is not treated as proof of a live production workflow.

## Recent fixes verified

| Area | Evidence | Status |
|---|---|---|
| Incident assignment normalization | PR #9 merged to `main`; backend CI passed with 680 passed, 9 skipped, 2 warnings | PASS |
| Production incident update | Render request log recorded `PATCH /api/v1/incidents/PG-R2-F885435C` → HTTP 200 at 2026-11-25 19:21:58 UTC | PASS |
| Persisted assignment state | Supabase row for `PG-R2-F885435C` read back as `VERIFIED`, `assignment_type=TEAM`, `assigned_team_id=TEAM-DELTA`, `assigned_worker_id=NULL` | PASS |
| Original failing incident | `PG-R1-F885435C` remains `REPORTED` with `assignment_type=NONE` and all assignment fields NULL; it was not modified during this verification | PASS — preserved |
| GIS basemap default | Merged frontend source sets `osm_standard` as the default; CARTO Dark remains optional | PASS — source |
| GIS visual rendering | User confirmed the repeated API-key watermark is gone in the production UI | PASS — user visual confirmation |
| Deployment | PR #9 merged; Render deployment reported live; Vercel production deployment reported Ready | PASS |

## Previously verified Phase 4 baseline

- Disposable PostgreSQL 17 validation applied migrations 001–008; migration 008 reapplication/idempotency check passed.
- Disposable database backend suite: 673 passed.
- Backup/restore validation completed with object and representative row parity.
- Backend suite in GitHub Actions for PR #9: 680 passed, 9 skipped, 2 warnings.
- Frontend: 94 Vitest tests previously verified; PR #9 Vercel check passed.
- Production Render health/readiness and public status endpoints previously returned HTTP 200.
- Production Supabase health advisor had no findings at the time of the audit.
- Storage bucket `incident-evidence` is private; live upload/download flow was not verified.

These are separate test runs/configurations and must not be added together as a single test count.

## Remaining live acceptance checks

The following remain unverified end-to-end in production and are blockers to unconditional Phase 4 closure:

1. Supabase Auth login and refresh lifecycle.
2. Full JWT/RBAC matrix for citizen, municipality, admin, and worker roles.
3. Full incident write lifecycle across create, verify, assign, worker update, resolve/reject, and audit trail.
4. Private Storage evidence upload, authorized download, and cross-incident access denial.
5. Duplicate incident scan and confirmation workflow.
6. SAFE_HOLD transition and safety behavior.
7. Live rate-limit burst behavior (429 response).
8. Confirm deployed CORS behavior from the production frontend origin and rejection of an unapproved origin.

The recent PATCH verification proves one municipal incident update path, not the entire lifecycle or all roles.

## Security and operational notes

- Production incident transaction RPC execution is restricted to the backend `service_role`; browser clients should use the FastAPI boundary.
- Production Supabase migration history does not mirror the repository's original numbered migration sequence. Verify production state from live schema, privileges, and object behavior; do not infer that every repository migration number was applied from migration-history records.
- Supabase leaked-password protection remains disabled because it is a Pro-only feature and no paid upgrade was authorized.
- Nine internal tables were previously observed with RLS enabled and no direct policies; anon/authenticated effective privileges were audited as absent. Do not change these permissions without a separate review.
- Vercel had 16 identified unused environment-variable entries requiring manual review/removal. Keep only frontend-required public variables in Vercel; privileged backend credentials belong only on Render.
- No paid infrastructure changes are part of this acceptance work.

## Closure criteria

Phase 4 may be marked **PASS / CLOSED** only after the remaining live checks above are either executed successfully or explicitly scoped out with documented justification and stakeholder acceptance. Until then, the accurate status remains **CONDITIONAL PASS — OPEN**.

Flutter/Phase 5 work remains gated on formal Phase 4 closure.
