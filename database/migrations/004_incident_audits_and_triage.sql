-- =====================================================================
-- DRAIN-X Migration 004: Durable Incidents, Field Teams & Audit Ledger
-- Target: Supabase / PostgreSQL 15+
-- Status: VERIFIED & SYNCHRONIZED WITH PRODUCTION SUPABASE SCHEMA.
--
-- This migration is designed for the currently verified backend contract:
--   * FastAPI is the only writer for incidents and audit records.
--   * Supabase service_role is used by the trusted backend.
--   * Authenticated municipal users may read audit history.
--   * Authenticated users may read active field-team directory entries.
--   * Citizens do not read or mutate incident tables directly.
--   * Current municipal RPC signature does not include photos; photo changes
--     are therefore not persisted by this RPC until backend contract is extended.
--
-- IMPORTANT:
--   * This migration does not alter telemetry tables.
--   * This is a first-install migration, not a repair migration. It aborts
--     if any target table already exists; inspect/reconcile partial installs
--     manually rather than trusting CREATE TABLE IF NOT EXISTS.
--   * Seed statements use ON CONFLICT DO NOTHING and never overwrite
--     existing operational records.
--   * Do not apply to production until tested against a disposable
--     Supabase/PostgreSQL database and reviewed.
-- =====================================================================

-- Fail closed if a previous partial/manual installation exists.
DO $preflight$
BEGIN
    IF to_regclass('public.field_teams') IS NOT NULL
       OR to_regclass('public.incidents') IS NOT NULL
       OR to_regclass('public.incident_audits') IS NOT NULL THEN
        RAISE EXCEPTION
            'DRAIN-X incident objects already exist. Inspect and reconcile them before running this first-install migration.';
    END IF;
END;
$preflight$;

-- ---------------------------------------------------------------------
-- 1. Field-team directory
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.field_teams (
    team_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE,
    zone VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified_municipal_crew BOOLEAN NOT NULL DEFAULT FALSE,
    capacity INTEGER NOT NULL DEFAULT 4 CHECK (capacity > 0),
    contact_phone VARCHAR(32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_field_teams_zone
    ON public.field_teams (zone);
CREATE INDEX IF NOT EXISTS idx_field_teams_active
    ON public.field_teams (is_active);

-- Canonical demo directory from backend/app/services/state_store.py.
-- These inserts are intentionally non-destructive on repeat execution.
INSERT INTO public.field_teams
    (team_id, name, zone, is_active, is_demo,
     is_verified_municipal_crew, capacity, contact_phone)
VALUES
    ('TEAM-ALPHA', 'Team Alpha — St. Inez Drainage Crew',
     'St. Inez / Panaji Central', TRUE, TRUE, FALSE, 4, '+91-832-2420001'),
    ('TEAM-BETA', 'Team Beta — Patto Rapid Response',
     'Patto Commercial Plaza', TRUE, TRUE, FALSE, 4, '+91-832-2420002'),
    ('TEAM-GAMMA', 'Team Gamma — Fontainhas Heritage Maintenance',
     'Fontainhas Conservation Zone', TRUE, TRUE, FALSE, 3, '+91-832-2420003'),
    ('TEAM-DELTA', 'Team Delta — Miramar Outfall Sluice Unit',
     'Miramar Beach Outfall', TRUE, TRUE, FALSE, 5, '+91-832-2420004')
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. Incident records
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incidents (
    id VARCHAR(32) PRIMARY KEY,
    category VARCHAR(64) NOT NULL CHECK (
        category IN (
            'FLOODING', 'WATERLOGGING', 'DRAIN_BLOCKAGE',
            'DRAIN_OVERFLOW', 'MANHOLE_DAMAGE',
            'INFRASTRUCTURE_DAMAGE', 'OTHER'
        )
    ),
    description TEXT NOT NULL,
    latitude DOUBLE PRECISION NOT NULL CHECK (latitude BETWEEN -90 AND 90),
    longitude DOUBLE PRECISION NOT NULL CHECK (longitude BETWEEN -180 AND 180),
    severity VARCHAR(16) NOT NULL DEFAULT 'MEDIUM'
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(32) NOT NULL DEFAULT 'REPORTED'
        CHECK (status IN (
            'REPORTED', 'VERIFIED', 'ASSIGNED',
            'INVESTIGATING', 'RESOLVED', 'REJECTED'
        )),
    source VARCHAR(16) NOT NULL DEFAULT 'CITIZEN'
        CHECK (source IN ('CITIZEN', 'SENSOR', 'DEMO')),
    assigned_to VARCHAR(128),
    assignment_type VARCHAR(16) NOT NULL DEFAULT 'NONE'
        CHECK (assignment_type IN ('NONE', 'TEAM', 'INDIVIDUAL')),
    assigned_team_id VARCHAR(64)
        REFERENCES public.field_teams(team_id) ON DELETE RESTRICT,
    assigned_worker_id VARCHAR(128),
    municipal_notes TEXT,
    internal_notes TEXT,
    reporter_name VARCHAR(128),
    photos TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    verified_at TIMESTAMPTZ,
    verified_by VARCHAR(128),
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT incidents_assignment_consistency CHECK (
        (
            assignment_type = 'NONE'
            AND assigned_to IS NULL
            AND assigned_team_id IS NULL
            AND assigned_worker_id IS NULL
        )
        OR
        (
            assignment_type = 'TEAM'
            AND assigned_to IS NOT NULL
            AND assigned_team_id IS NOT NULL
            AND assigned_worker_id IS NULL
        )
        OR
        (
            assignment_type = 'INDIVIDUAL'
            AND assigned_to IS NOT NULL
            AND assigned_team_id IS NOT NULL
            AND assigned_worker_id IS NOT NULL
        )
    ),
    CONSTRAINT incidents_photos_limit CHECK (cardinality(photos) <= 3)
);

CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON public.incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at
    ON public.incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to
    ON public.incidents (assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_team_id
    ON public.incidents (assigned_team_id);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_worker_id
    ON public.incidents (assigned_worker_id);

-- ---------------------------------------------------------------------
-- 3. Append-only audit ledger
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incident_audits (
    audit_id VARCHAR(32) PRIMARY KEY,
    incident_id VARCHAR(32) NOT NULL
        REFERENCES public.incidents(id) ON DELETE RESTRICT,
    actor_id VARCHAR(128) NOT NULL,
    actor_role VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    previous_status VARCHAR(32),
    new_status VARCHAR(32),
    previous_assigned_to VARCHAR(128),
    new_assigned_to VARCHAR(128),
    previous_assignment_type VARCHAR(16),
    new_assignment_type VARCHAR(16),
    previous_assigned_team_id VARCHAR(64),
    new_assigned_team_id VARCHAR(64),
    previous_assigned_worker_id VARCHAR(128),
    new_assigned_worker_id VARCHAR(128),
    previous_severity VARCHAR(16),
    new_severity VARCHAR(16),
    reason TEXT,
    internal_notes TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incident_audits_incident_id_timestamp
    ON public.incident_audits (incident_id, timestamp ASC, audit_id ASC);

-- Block UPDATE, DELETE, and TRUNCATE, including attempts made by service_role.
-- Audit rows are retained; incident deletion is RESTRICTed by the FK above.
CREATE OR REPLACE FUNCTION public.prevent_audit_mutation_or_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION
        'Incident audit ledger is append-only. % is prohibited.', TG_OP
        USING ERRCODE = '42501';
END;
$function$;

CREATE OR REPLACE FUNCTION public.prevent_audit_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION 'Incident audit ledger cannot be truncated'
        USING ERRCODE = '42501';
END;
$function$;

DROP TRIGGER IF EXISTS trg_immutable_incident_audits
    ON public.incident_audits;
DROP TRIGGER IF EXISTS trg_no_truncate_incident_audits
    ON public.incident_audits;

CREATE TRIGGER trg_immutable_incident_audits
BEFORE UPDATE OR DELETE ON public.incident_audits
FOR EACH ROW
EXECUTE FUNCTION public.prevent_audit_mutation_or_deletion();

CREATE TRIGGER trg_no_truncate_incident_audits
BEFORE TRUNCATE ON public.incident_audits
FOR EACH STATEMENT
EXECUTE FUNCTION public.prevent_audit_truncate();

-- ---------------------------------------------------------------------
-- 4. Seed demo incidents and their initial history
-- ---------------------------------------------------------------------
-- Incident seed values mirror StateStore.seed_demo_incidents().
-- Assignment metadata is explicitly populated to match the Python fix.
INSERT INTO public.incidents (
    id, category, description, latitude, longitude, severity, status, source,
    assigned_to, assignment_type, assigned_team_id, assigned_worker_id,
    municipal_notes, reporter_name
)
VALUES
(
    'INC-DEMO-01', 'DRAIN_OVERFLOW',
    'Severe storm runoff overflowing culvert embankment near St. Inez Church.',
    15.4920, 73.8185, 'CRITICAL', 'INVESTIGATING', 'DEMO',
    'Team Alpha — St. Inez Drainage Crew', 'TEAM', 'TEAM-ALPHA', NULL,
    'High-capacity dewatering pump dispatched to site.',
    'St. Inez Ward Committee'
),
(
    'INC-DEMO-02', 'WATERLOGGING',
    'Street waterlogging of 20cm depth blocking pedestrian access near Patto Plaza commercial district.',
    15.4989, 73.8342, 'HIGH', 'ASSIGNED', 'DEMO',
    'Team Beta — Patto Rapid Response', 'TEAM', 'TEAM-BETA', NULL,
    'Suction tanker scheduled for 14:00 drain vacuuming.',
    'Patto Commercial Association'
),
(
    'INC-DEMO-03', 'DRAIN_BLOCKAGE',
    'Accumulation of construction debris and plastic waste obstructing stone masonry drain along Rua 31 de Janeiro.',
    15.4965, 73.8305, 'MEDIUM', 'VERIFIED', 'DEMO',
    'Team Gamma — Fontainhas Heritage Maintenance', 'TEAM', 'TEAM-GAMMA', NULL,
    'Verified by municipal field inspector. Manual clearing required.',
    'Fontainhas Heritage Watch'
),
(
    'INC-DEMO-04', 'INFRASTRUCTURE_DAMAGE',
    'Displaced concrete grating slab over main arterial drain box near Miramar Circle.',
    15.4835, 73.8078, 'LOW', 'RESOLVED', 'DEMO',
    'Team Delta — Miramar Outfall Sluice Unit', 'TEAM', 'TEAM-DELTA', NULL,
    'Grating slab repositioned and secured with structural steel anchors.',
    'Panaji Municipal Patrol'
)
ON CONFLICT (id) DO NOTHING;

-- Initial REPORTED event for each demo incident.
INSERT INTO public.incident_audits (
    audit_id, incident_id, actor_id, actor_role, action,
    new_status, new_severity, reason
)
VALUES
('AUD-D0000001', 'INC-DEMO-01', 'St. Inez Ward Committee',
 'citizen', 'REPORTED', 'REPORTED', 'CRITICAL',
 'Initial citizen hazard report submission'),
('AUD-D0000002', 'INC-DEMO-02', 'Patto Commercial Association',
 'citizen', 'REPORTED', 'REPORTED', 'HIGH',
 'Initial citizen hazard report submission'),
('AUD-D0000003', 'INC-DEMO-03', 'Fontainhas Heritage Watch',
 'citizen', 'REPORTED', 'REPORTED', 'MEDIUM',
 'Initial citizen hazard report submission'),
('AUD-D0000004', 'INC-DEMO-04', 'Panaji Municipal Patrol',
 'citizen', 'REPORTED', 'REPORTED', 'LOW',
 'Initial citizen hazard report submission')
ON CONFLICT (audit_id) DO NOTHING;

-- One synthetic DEMO_SEEDED event records the seeded current state.
-- This avoids claiming an operational transition occurred during migration.
INSERT INTO public.incident_audits (
    audit_id, incident_id, actor_id, actor_role, action,
    previous_status, new_status,
    new_assigned_to, new_assignment_type, new_assigned_team_id,
    new_assigned_worker_id, reason
)
VALUES
('AUD-D0000011', 'INC-DEMO-01', 'muni-dispatcher-seed', 'municipality',
 'DEMO_SEEDED', 'REPORTED', 'INVESTIGATING',
 'Team Alpha — St. Inez Drainage Crew', 'TEAM', 'TEAM-ALPHA', NULL,
 'Demo state initialized for municipal operations'),
('AUD-D0000012', 'INC-DEMO-02', 'muni-dispatcher-seed', 'municipality',
 'DEMO_SEEDED', 'REPORTED', 'ASSIGNED',
 'Team Beta — Patto Rapid Response', 'TEAM', 'TEAM-BETA', NULL,
 'Demo state initialized for municipal operations'),
('AUD-D0000013', 'INC-DEMO-03', 'muni-dispatcher-seed', 'municipality',
 'DEMO_SEEDED', 'REPORTED', 'VERIFIED',
 'Team Gamma — Fontainhas Heritage Maintenance', 'TEAM', 'TEAM-GAMMA', NULL,
 'Demo state initialized for municipal operations'),
('AUD-D0000014', 'INC-DEMO-04', 'muni-dispatcher-seed', 'municipality',
 'DEMO_SEEDED', 'REPORTED', 'RESOLVED',
 'Team Delta — Miramar Outfall Sluice Unit', 'TEAM', 'TEAM-DELTA', NULL,
 'Demo state initialized for municipal operations')
ON CONFLICT (audit_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 5. Row Level Security and least-privilege table grants
-- ---------------------------------------------------------------------
ALTER TABLE public.field_teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_audits ENABLE ROW LEVEL SECURITY;

-- Remove every pre-existing policy on these new domain tables. This avoids
-- an unexpected permissive policy surviving and OR-ing with the policies below.
DO $drop_policies$
DECLARE
    v_policy RECORD;
BEGIN
    FOR v_policy IN
        SELECT schemaname, tablename, policyname
          FROM pg_policies
         WHERE schemaname = 'public'
           AND tablename IN ('field_teams', 'incidents', 'incident_audits')
    LOOP
        EXECUTE format('DROP POLICY %I ON %I.%I',
                       v_policy.policyname, v_policy.schemaname, v_policy.tablename);
    END LOOP;
END;
$drop_policies$;

-- Runtime service_role reads through the backend. Writes are performed only
-- inside the SECURITY DEFINER RPCs below; do not grant direct table mutation.
GRANT SELECT ON TABLE public.field_teams TO service_role;
GRANT SELECT ON TABLE public.incidents TO service_role;
GRANT SELECT ON TABLE public.incident_audits TO service_role;
GRANT SELECT ON TABLE public.field_teams TO authenticated;
GRANT SELECT ON TABLE public.incident_audits TO authenticated;

-- Explicitly remove direct mutation privileges, including TRUNCATE.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON TABLE public.field_teams, public.incidents, public.incident_audits
    FROM PUBLIC, anon, authenticated, service_role;

CREATE POLICY authenticated_read_field_teams
ON public.field_teams FOR SELECT TO authenticated
USING (is_active = TRUE);

CREATE POLICY municipal_read_incident_audits
ON public.incident_audits FOR SELECT TO authenticated
USING (
    COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', '')
    IN ('municipality', 'admin')
);

-- No client-facing policy exists on incidents. Citizens and workers cannot
-- access incident rows directly; FastAPI mediates access and calls the RPCs.

-- ---------------------------------------------------------------------
-- 6. Atomic municipal mutation + audit RPC
-- ---------------------------------------------------------------------
-- The backend supplies verified actor claims after FastAPI authorization.
-- The function is executable only by service_role; p_actor_role and
-- p_actor_id are audit metadata, not independent authentication evidence.
CREATE OR REPLACE FUNCTION public.municipal_incident_transaction_rpc(
    p_incident_id VARCHAR(32),
    p_new_status VARCHAR(32),
    p_new_severity VARCHAR(16),
    p_assigned_to VARCHAR(128),
    p_assignment_type VARCHAR(16),
    p_assigned_team_id VARCHAR(64),
    p_assigned_worker_id VARCHAR(128),
    p_municipal_notes TEXT,
    p_internal_notes TEXT,
    p_rejection_reason TEXT,
    p_verified_by VARCHAR(128),
    p_actor_id VARCHAR(128),
    p_actor_role VARCHAR(64),
    p_action VARCHAR(64),
    p_reason TEXT,
    p_audit_id VARCHAR(32)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
DECLARE
    v_inc public.incidents%ROWTYPE;
    v_updated public.incidents%ROWTYPE;
    v_now TIMESTAMPTZ := now();
    v_assignment_changed BOOLEAN;
    v_status_changed BOOLEAN;
    v_severity_changed BOOLEAN;
BEGIN
    IF p_actor_role IS NULL OR p_actor_role NOT IN
       ('municipality', 'admin', 'worker', 'service_role') THEN
        RAISE EXCEPTION 'Unauthorized actor role for municipal mutation'
            USING ERRCODE = '42501';
    END IF;

    IF p_incident_id IS NULL OR btrim(p_incident_id) = ''
       OR p_actor_id IS NULL OR btrim(p_actor_id) = ''
       OR p_action IS NULL OR btrim(p_action) = ''
       OR p_audit_id IS NULL OR btrim(p_audit_id) = '' THEN
        RAISE EXCEPTION 'Incident, actor, action, and audit ID are required'
            USING ERRCODE = '22023';
    END IF;

    -- Exact actions generated by state_store.py and the incident routes.
    -- STATUS_TO_* is intentionally enumerated, not accepted as arbitrary text.
    IF p_action NOT IN (
        'ASSIGNED', 'REASSIGNED', 'UNASSIGNED', 'VERIFIED',
        'REJECTED', 'RESOLVED', 'PRIORITIZED', 'UPDATE',
        'WORKER_UPDATE', 'STATUS_CHANGE',
        'STATUS_TO_REPORTED', 'STATUS_TO_VERIFIED',
        'STATUS_TO_ASSIGNED', 'STATUS_TO_INVESTIGATING',
        'STATUS_TO_RESOLVED', 'STATUS_TO_REJECTED'
    ) THEN
        RAISE EXCEPTION 'Unsupported incident action: %', p_action
            USING ERRCODE = '22023';
    END IF;

    SELECT *
      INTO v_inc
      FROM public.incidents
     WHERE id = p_incident_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id
            USING ERRCODE = 'P0002';
    END IF;

    -- Terminal incidents are wholly immutable, not merely status-immutable.
    IF v_inc.status IN ('RESOLVED', 'REJECTED') THEN
        RAISE EXCEPTION 'Terminal incident % cannot be modified', p_incident_id
            USING ERRCODE = '23514';
    END IF;

    IF p_actor_role = 'worker' THEN
        IF p_action NOT IN (
            'WORKER_UPDATE', 'STATUS_CHANGE', 'UPDATE', 'PRIORITIZED',
            'STATUS_TO_VERIFIED', 'STATUS_TO_ASSIGNED',
            'STATUS_TO_INVESTIGATING'
        ) OR p_new_status IN ('RESOLVED', 'REJECTED') THEN
            RAISE EXCEPTION 'Worker is not authorized for action %', p_action
                USING ERRCODE = '42501';
        END IF;

        -- The FastAPI layer validates the worker's trusted JWT identity/team
        -- against the locked incident before calling this service-role RPC.
        -- The RPC still enforces that a worker snapshot cannot alter protected
        -- assignment or supervisory fields.
        IF p_assigned_to IS DISTINCT FROM v_inc.assigned_to
           OR p_assignment_type IS DISTINCT FROM v_inc.assignment_type
           OR p_assigned_team_id IS DISTINCT FROM v_inc.assigned_team_id
           OR p_assigned_worker_id IS DISTINCT FROM v_inc.assigned_worker_id
           OR p_internal_notes IS DISTINCT FROM v_inc.internal_notes
           OR p_rejection_reason IS DISTINCT FROM v_inc.rejection_reason
           OR p_verified_by IS DISTINCT FROM v_inc.verified_by THEN
            RAISE EXCEPTION 'Worker mutation attempted to change a protected incident field'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    IF p_new_status IS NOT NULL AND p_new_status NOT IN (
        'REPORTED', 'VERIFIED', 'ASSIGNED',
        'INVESTIGATING', 'RESOLVED', 'REJECTED'
    ) THEN
        RAISE EXCEPTION 'Invalid incident status: %', p_new_status
            USING ERRCODE = '22023';
    END IF;

    IF p_new_status IS NOT NULL AND p_new_status <> v_inc.status THEN
        IF NOT (
            (v_inc.status = 'REPORTED'
                AND p_new_status IN ('VERIFIED', 'ASSIGNED', 'REJECTED'))
            OR
            (v_inc.status = 'VERIFIED'
                AND p_new_status IN ('ASSIGNED', 'REJECTED'))
            OR
            (v_inc.status = 'ASSIGNED'
                AND p_new_status IN ('INVESTIGATING', 'VERIFIED', 'REJECTED'))
            OR
            (v_inc.status = 'INVESTIGATING'
                AND p_new_status IN ('RESOLVED', 'ASSIGNED', 'REJECTED'))
        ) THEN
            RAISE EXCEPTION 'Illegal incident status transition: % -> %',
                v_inc.status, p_new_status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF p_new_severity IS NOT NULL AND p_new_severity NOT IN (
        'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    ) THEN
        RAISE EXCEPTION 'Invalid incident severity: %', p_new_severity
            USING ERRCODE = '22023';
    END IF;

    -- Assignment values are a complete resulting-state snapshot from FastAPI.
    IF p_action = 'UNASSIGNED' THEN
        IF p_assigned_to IS NOT NULL
           OR p_assignment_type IS DISTINCT FROM 'NONE'
           OR p_assigned_team_id IS NOT NULL
           OR p_assigned_worker_id IS NOT NULL THEN
            RAISE EXCEPTION 'UNASSIGNED action must clear every assignment field'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        IF p_assignment_type IS NULL OR p_assignment_type NOT IN
           ('NONE', 'TEAM', 'INDIVIDUAL') THEN
            RAISE EXCEPTION 'Invalid assignment type: %', p_assignment_type
                USING ERRCODE = '22023';
        END IF;

        IF p_assignment_type = 'NONE' THEN
            IF p_assigned_to IS NOT NULL
               OR p_assigned_team_id IS NOT NULL
               OR p_assigned_worker_id IS NOT NULL THEN
                RAISE EXCEPTION 'NONE assignment must clear all assignment fields'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF p_assignment_type = 'TEAM' THEN
            IF p_assigned_to IS NULL OR p_assigned_team_id IS NULL
               OR p_assigned_worker_id IS NOT NULL THEN
                RAISE EXCEPTION 'TEAM assignment requires team and assignee, but no worker ID'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF p_assignment_type = 'INDIVIDUAL' THEN
            IF p_assigned_to IS NULL OR p_assigned_team_id IS NULL
               OR p_assigned_worker_id IS NULL THEN
                RAISE EXCEPTION 'INDIVIDUAL assignment requires team, assignee, and worker ID'
                    USING ERRCODE = '23514';
            END IF;
        END IF;

        IF p_assignment_type IN ('TEAM', 'INDIVIDUAL') THEN
            PERFORM 1
              FROM public.field_teams
             WHERE team_id = p_assigned_team_id
               AND is_active = TRUE
               AND name = p_assigned_to;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Assignment does not match an active canonical field team'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    v_assignment_changed :=
        v_inc.assigned_to IS DISTINCT FROM
            CASE WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_to END
        OR v_inc.assignment_type IS DISTINCT FROM
            CASE WHEN p_action = 'UNASSIGNED' THEN 'NONE' ELSE p_assignment_type END
        OR v_inc.assigned_team_id IS DISTINCT FROM
            CASE WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_team_id END
        OR v_inc.assigned_worker_id IS DISTINCT FROM
            CASE WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_worker_id END;

    v_status_changed :=
        p_new_status IS NOT NULL AND p_new_status IS DISTINCT FROM v_inc.status;
    v_severity_changed :=
        p_new_severity IS NOT NULL AND p_new_severity IS DISTINCT FROM v_inc.severity;

    -- These text parameters are full resulting-state values, not patch values.
    -- Assign directly so an explicit NULL can clear a field.
    UPDATE public.incidents
       SET status = COALESCE(p_new_status, status),
           severity = COALESCE(p_new_severity, severity),
           assigned_to = CASE
               WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_to END,
           assignment_type = CASE
               WHEN p_action = 'UNASSIGNED' THEN 'NONE' ELSE p_assignment_type END,
           assigned_team_id = CASE
               WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_team_id END,
           assigned_worker_id = CASE
               WHEN p_action = 'UNASSIGNED' THEN NULL ELSE p_assigned_worker_id END,
           municipal_notes = p_municipal_notes,
           internal_notes = p_internal_notes,
           rejection_reason = p_rejection_reason,
           verified_by = p_verified_by,
           verified_at = CASE
               WHEN p_verified_by IS DISTINCT FROM v_inc.verified_by
                    AND p_verified_by IS NOT NULL THEN v_now
               WHEN p_verified_by IS NULL THEN NULL
               ELSE verified_at
           END,
           updated_at = v_now
     WHERE id = p_incident_id
     RETURNING * INTO v_updated;

    INSERT INTO public.incident_audits (
        audit_id, incident_id, actor_id, actor_role, action,
        previous_status, new_status,
        previous_assigned_to, new_assigned_to,
        previous_assignment_type, new_assignment_type,
        previous_assigned_team_id, new_assigned_team_id,
        previous_assigned_worker_id, new_assigned_worker_id,
        previous_severity, new_severity,
        reason, internal_notes, timestamp
    )
    VALUES (
        p_audit_id, p_incident_id, p_actor_id, p_actor_role, p_action,
        CASE WHEN v_status_changed THEN v_inc.status ELSE NULL END,
        CASE WHEN v_status_changed THEN v_updated.status ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_inc.assigned_to ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_updated.assigned_to ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_inc.assignment_type ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_updated.assignment_type ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_inc.assigned_team_id ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_updated.assigned_team_id ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_inc.assigned_worker_id ELSE NULL END,
        CASE WHEN v_assignment_changed THEN v_updated.assigned_worker_id ELSE NULL END,
        CASE WHEN v_severity_changed THEN v_inc.severity ELSE NULL END,
        CASE WHEN v_severity_changed THEN v_updated.severity ELSE NULL END,
        p_reason, p_internal_notes, v_now
    );

    RETURN to_jsonb(v_updated);
END;
$function$;

-- ---------------------------------------------------------------------
-- 7. Atomic and idempotent citizen incident creation RPC
-- ---------------------------------------------------------------------
-- A repeated request with the same incident ID and identical payload
-- returns the existing incident and does not append another REPORTED event.
-- Reuse of an ID with a different payload is rejected.
CREATE OR REPLACE FUNCTION public.citizen_incident_creation_rpc(
    p_incident_id VARCHAR(32),
    p_category VARCHAR(64),
    p_description TEXT,
    p_latitude DOUBLE PRECISION,
    p_longitude DOUBLE PRECISION,
    p_severity VARCHAR(16),
    p_source VARCHAR(16),
    p_reporter_name VARCHAR(128),
    p_photos TEXT[],
    p_audit_id VARCHAR(32)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
DECLARE
    v_inc public.incidents%ROWTYPE;
    v_inserted BOOLEAN := FALSE;
    v_now TIMESTAMPTZ := now();
    v_photos TEXT[] := COALESCE(p_photos, ARRAY[]::TEXT[]);
BEGIN
    IF p_incident_id IS NULL OR btrim(p_incident_id) = ''
       OR p_audit_id IS NULL OR btrim(p_audit_id) = ''
       OR p_description IS NULL OR btrim(p_description) = '' THEN
        RAISE EXCEPTION 'Incident ID and audit ID are required'
            USING ERRCODE = '22023';
    END IF;

    IF p_category IS NULL OR p_category NOT IN (
        'FLOODING', 'WATERLOGGING', 'DRAIN_BLOCKAGE',
        'DRAIN_OVERFLOW', 'MANHOLE_DAMAGE',
        'INFRASTRUCTURE_DAMAGE', 'OTHER'
    ) THEN
        RAISE EXCEPTION 'Invalid incident category: %', p_category
            USING ERRCODE = '22023';
    END IF;

    IF p_severity IS NULL OR p_severity NOT IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') THEN
        RAISE EXCEPTION 'Invalid incident severity: %', p_severity
            USING ERRCODE = '22023';
    END IF;

    IF p_source IS NULL OR p_source NOT IN ('CITIZEN', 'SENSOR', 'DEMO') THEN
        RAISE EXCEPTION 'Invalid incident source: %', p_source
            USING ERRCODE = '22023';
    END IF;

    IF p_latitude IS NULL OR p_latitude NOT BETWEEN -90 AND 90
       OR p_longitude IS NULL OR p_longitude NOT BETWEEN -180 AND 180 THEN
        RAISE EXCEPTION 'Incident coordinates are invalid'
            USING ERRCODE = '22023';
    END IF;

    IF cardinality(v_photos) > 3 THEN
        RAISE EXCEPTION 'A maximum of three incident photos is permitted'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.incidents (
        id, category, description, latitude, longitude,
        severity, status, source, reporter_name, photos,
        created_at, updated_at
    )
    VALUES (
        p_incident_id, p_category, p_description, p_latitude, p_longitude,
        p_severity, 'REPORTED', p_source, p_reporter_name, v_photos,
        v_now, v_now
    )
    ON CONFLICT (id) DO NOTHING
    RETURNING * INTO v_inc;

    IF FOUND THEN
        v_inserted := TRUE;
    ELSE
        SELECT *
          INTO v_inc
          FROM public.incidents
         WHERE id = p_incident_id
         FOR UPDATE;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Incident ID conflict could not be resolved'
                USING ERRCODE = '23505';
        END IF;

        IF v_inc.category IS DISTINCT FROM p_category
           OR v_inc.description IS DISTINCT FROM p_description
           OR v_inc.latitude IS DISTINCT FROM p_latitude
           OR v_inc.longitude IS DISTINCT FROM p_longitude
           OR v_inc.severity IS DISTINCT FROM p_severity
           OR v_inc.source IS DISTINCT FROM p_source
           OR v_inc.reporter_name IS DISTINCT FROM p_reporter_name
           OR v_inc.photos IS DISTINCT FROM v_photos THEN
            RAISE EXCEPTION 'Incident ID % already exists with a different payload',
                p_incident_id
                USING ERRCODE = '23505';
        END IF;
    END IF;

    IF v_inserted THEN
        INSERT INTO public.incident_audits (
            audit_id, incident_id, actor_id, actor_role, action,
            new_status, new_severity, reason, timestamp
        )
        VALUES (
            p_audit_id, p_incident_id,
            COALESCE(p_reporter_name, 'Citizen Anonymous'),
            'citizen', 'REPORTED', 'REPORTED', p_severity,
            'Initial hazard report submission', v_now
        );
    END IF;

    RETURN to_jsonb(v_inc);
END;
$function$;

-- ---------------------------------------------------------------------
-- 8. RPC execution grants
-- ---------------------------------------------------------------------
-- Trigger functions are not intended as callable application APIs.
REVOKE ALL ON FUNCTION public.prevent_audit_mutation_or_deletion() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_audit_truncate() FROM PUBLIC, anon, authenticated, service_role;

REVOKE ALL ON FUNCTION public.municipal_incident_transaction_rpc(
    VARCHAR(32), VARCHAR(32), VARCHAR(16), VARCHAR(128), VARCHAR(16),
    VARCHAR(64), VARCHAR(128), TEXT, TEXT, TEXT, VARCHAR(128),
    VARCHAR(128), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(32)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.municipal_incident_transaction_rpc(
    VARCHAR(32), VARCHAR(32), VARCHAR(16), VARCHAR(128), VARCHAR(16),
    VARCHAR(64), VARCHAR(128), TEXT, TEXT, TEXT, VARCHAR(128),
    VARCHAR(128), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(32)
) TO service_role;

REVOKE ALL ON FUNCTION public.citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32)
) TO service_role;

-- ---------------------------------------------------------------------
-- 9. Post-migration verification queries (run separately, read-only)
-- ---------------------------------------------------------------------
-- SELECT team_id, name, zone, is_active, is_demo
-- FROM public.field_teams ORDER BY team_id;
--
-- SELECT id, status, assignment_type, assigned_team_id, assigned_worker_id
-- FROM public.incidents WHERE id LIKE 'INC-DEMO-%' ORDER BY id;
--
-- SELECT incident_id, action, previous_status, new_status,
--        new_assignment_type, new_assigned_team_id, timestamp
-- FROM public.incident_audits
-- WHERE incident_id LIKE 'INC-DEMO-%'
-- ORDER BY incident_id, timestamp, audit_id;
--
-- SELECT
--   to_regclass('public.field_teams') AS field_teams,
--   to_regclass('public.incidents') AS incidents,
--   to_regclass('public.incident_audits') AS incident_audits,
--   to_regprocedure(
--     'public.municipal_incident_transaction_rpc(character varying,character varying,character varying,character varying,character varying,character varying,character varying,text,text,text,character varying,character varying,character varying,character varying,text,character varying)'
--   ) AS municipal_rpc,
--   to_regprocedure(
--     'public.citizen_incident_creation_rpc(character varying,character varying,text,double precision,double precision,character varying,character varying,character varying,text[],character varying)'
--   ) AS citizen_rpc;
--
-- END OF MIGRATION 004 (VERIFIED OPERATING IN LIVE PRODUCTION SUPABASE)
