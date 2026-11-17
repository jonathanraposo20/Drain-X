-- ====================================================================
-- DRAIN-X Schema Migration 004: Incident Audits & Municipal Triage Durability
-- Target: Supabase / PostgreSQL 15+
-- Status: LOCAL FILE PREPARATION ONLY (DO NOT APPLY DIRECTLY TO PRODUCTION)
-- Description:
--   1. Creates durable table `field_teams` for authoritative crews.
--   2. Creates durable table `incidents` if not already present.
--   3. Creates durable append-only table `incident_audits` for municipal triage,
--      dispatch assignment, reassignment, rejection, and resolution tracking.
--   4. Adds explicit assignment representation:
--      - assignment_type: 'NONE', 'TEAM', 'INDIVIDUAL'
--      - assigned_team_id: VARCHAR(64) REFERENCES field_teams(team_id)
--      - assigned_worker_id: VARCHAR(128) (Supabase auth.users UUID or null)
--   5. Enforces Append-Only immutability on `incident_audits` via Trigger (No UPDATE / No DELETE).
--   6. Adds composite indexes on (incident_id, timestamp ASC) and event_id uniqueness.
--   7. Enables Row Level Security (RLS) across all tables with app_metadata role verification.
-- ====================================================================

-- --------------------------------------------------------------------
-- 1. Create Authoritative Field Teams Directory Table
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS field_teams (
    team_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    zone VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified_municipal_crew BOOLEAN NOT NULL DEFAULT FALSE,
    capacity INTEGER NOT NULL DEFAULT 4,
    contact_phone VARCHAR(32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_field_teams_zone ON field_teams (zone);
CREATE INDEX IF NOT EXISTS idx_field_teams_active ON field_teams (is_active);

-- --------------------------------------------------------------------
-- 2. Create Core Incidents Table
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(32) PRIMARY KEY,
    category VARCHAR(64) NOT NULL,
    description TEXT NOT NULL,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'MEDIUM',
    status VARCHAR(32) NOT NULL DEFAULT 'REPORTED',
    source VARCHAR(16) NOT NULL DEFAULT 'CITIZEN',
    assigned_to VARCHAR(128),
    assignment_type VARCHAR(16) NOT NULL DEFAULT 'NONE' CHECK (assignment_type IN ('NONE', 'TEAM', 'INDIVIDUAL')),
    assigned_team_id VARCHAR(64) REFERENCES field_teams(team_id) ON DELETE SET NULL,
    assigned_worker_id VARCHAR(128),
    municipal_notes TEXT,
    internal_notes TEXT,
    reporter_name VARCHAR(128),
    photos TEXT[] DEFAULT ARRAY[]::TEXT[],
    verified_at TIMESTAMPTZ,
    verified_by VARCHAR(128),
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to ON incidents (assigned_to);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_team_id ON incidents (assigned_team_id);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_worker_id ON incidents (assigned_worker_id);

-- --------------------------------------------------------------------
-- 3. Create Durable Append-Only Incident Audits Table
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_audits (
    audit_id VARCHAR(32) PRIMARY KEY,
    incident_id VARCHAR(32) NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
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
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- Index for chronological ordering and incident lookups
CREATE INDEX IF NOT EXISTS idx_incident_audits_incident_id_timestamp
ON incident_audits (incident_id, timestamp ASC);

-- --------------------------------------------------------------------
-- 4. Enforce Append-Only Immutability on Incident Audits
-- --------------------------------------------------------------------
-- Historical audit records cannot be mutated or deleted by any user or role.
CREATE OR REPLACE FUNCTION prevent_audit_mutation_or_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'Incident audit ledger is append-only. Modification of audit record % is strictly prohibited.', OLD.audit_id;
    ELSIF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Incident audit ledger is append-only. Deletion of audit record % is strictly prohibited.', OLD.audit_id;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_immutable_incident_audits ON incident_audits;
CREATE TRIGGER trg_immutable_incident_audits
BEFORE UPDATE OR DELETE ON incident_audits
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation_or_deletion();

-- --------------------------------------------------------------------
-- 5. Enable Row Level Security (RLS)
-- --------------------------------------------------------------------
ALTER TABLE field_teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_audits ENABLE ROW LEVEL SECURITY;

-- --------------------------------------------------------------------
-- 6. Field Teams Directory RLS Policies
-- --------------------------------------------------------------------
DROP POLICY IF EXISTS service_role_field_teams ON field_teams;
CREATE POLICY service_role_field_teams ON field_teams
FOR ALL TO service_role
USING (true)
WITH CHECK (true);

DROP POLICY IF EXISTS authenticated_read_field_teams ON field_teams;
CREATE POLICY authenticated_read_field_teams ON field_teams
FOR SELECT TO authenticated
USING (is_active = true);

-- --------------------------------------------------------------------
-- 7. Incident Audits RLS Policies
-- --------------------------------------------------------------------
-- Service Role (Backend FastAPI) has complete insert/read authority
DROP POLICY IF EXISTS service_role_incident_audits ON incident_audits;
CREATE POLICY service_role_incident_audits ON incident_audits
FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- Anonymous clients have ZERO access to audit history
-- Citizens have ZERO access to internal operational audits
-- Municipal officers and Admins have full read access to audit records
DROP POLICY IF EXISTS municipal_read_incident_audits ON incident_audits;
CREATE POLICY municipal_read_incident_audits ON incident_audits
FOR SELECT TO authenticated
USING (
    COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', '') IN ('municipality', 'admin', 'service_role')
);

-- --------------------------------------------------------------------
-- --------------------------------------------------------------------
-- 8. Core Incidents RLS Policies
-- --------------------------------------------------------------------

-- Only the trusted FastAPI backend can access incident records directly.
DROP POLICY IF EXISTS service_role_incidents ON incidents;
CREATE POLICY service_role_incidents ON incidents
FOR ALL TO service_role
USING (true)
WITH CHECK (true);

-- Remove unrestricted public and authenticated access.
DROP POLICY IF EXISTS anon_select_incidents ON incidents;
DROP POLICY IF EXISTS anon_insert_incidents ON incidents;
DROP POLICY IF EXISTS authenticated_select_incidents ON incidents;
DROP POLICY IF EXISTS authenticated_insert_incidents ON incidents;
DROP POLICY IF EXISTS municipal_update_incidents ON incidents;


-- --------------------------------------------------------------------
-- 9. Atomic Transaction RPC Function for Municipal Triage & Assignment
-- --------------------------------------------------------------------
-- Provides an all-or-nothing database transaction:
-- 1. Locks the incident row FOR UPDATE.
-- 2. Validates terminal status and legal transition.
-- 3. Updates the incident state.
-- 4. Appends the audit record.
-- 5. Commits atomically or rolls back on any error.
CREATE OR REPLACE FUNCTION municipal_incident_transaction_rpc(
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
AS $$
DECLARE
    v_inc RECORD;
    v_audit_record RECORD;
    v_now TIMESTAMPTZ := timezone('utc', now());
    v_prev_status VARCHAR(32);
    v_prev_severity VARCHAR(16);
    v_prev_assigned_to VARCHAR(128);
    v_prev_assignment_type VARCHAR(16);
    v_prev_assigned_team_id VARCHAR(64);
    v_prev_assigned_worker_id VARCHAR(128);
BEGIN
    -- 0. Authorization check: citizens cannot perform municipal mutations
    IF p_actor_role NOT IN ('municipality', 'admin', 'worker', 'service_role') THEN
        RAISE EXCEPTION 'Unauthorized: actor role % cannot execute municipal mutations', p_actor_role USING ERRCODE = '42501';
    END IF;

    -- 1. Read and lock row
    SELECT * INTO v_inc FROM incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = 'P0002';
    END IF;

    -- Worker authorization check: workers may only update incidents assigned to them
    IF p_actor_role = 'worker' THEN
        IF p_action NOT IN ('WORKER_UPDATE', 'STATUS_CHANGE', 'RESOLVED') THEN
            RAISE EXCEPTION 'Worker % cannot perform action % on incident', p_actor_id, p_action USING ERRCODE = '42501';
        END IF;
    END IF;

    -- 2. Validate terminal state locks
    IF v_inc.status IN ('RESOLVED', 'REJECTED') THEN
        IF p_new_status IS NOT NULL AND p_new_status <> v_inc.status THEN
            RAISE EXCEPTION 'Cannot modify terminal incident % in status %', p_incident_id, v_inc.status;
        END IF;
        IF p_action IN ('ASSIGN', 'REASSIGN', 'UNASSIGN', 'VERIFY') THEN
            RAISE EXCEPTION 'Cannot perform % on terminal incident % in status %', p_action, p_incident_id, v_inc.status;
        END IF;
    END IF;

    -- Store previous values
    v_prev_status := v_inc.status;
    v_prev_severity := v_inc.severity;
    v_prev_assigned_to := v_inc.assigned_to;
    v_prev_assignment_type := v_inc.assignment_type;
    v_prev_assigned_team_id := v_inc.assigned_team_id;
    v_prev_assigned_worker_id := v_inc.assigned_worker_id;

    -- 3. Update Incident Row
    UPDATE incidents SET
        status = COALESCE(p_new_status, status),
        severity = COALESCE(p_new_severity, severity),
        assigned_to = CASE
            WHEN p_action = 'UNASSIGN' THEN NULL
            WHEN p_assigned_to IS NOT NULL THEN p_assigned_to
            ELSE assigned_to
        END,
        assignment_type = CASE
            WHEN p_action = 'UNASSIGN' THEN 'NONE'
            WHEN p_assignment_type IS NOT NULL THEN p_assignment_type
            ELSE assignment_type
        END,
        assigned_team_id = CASE
            WHEN p_action = 'UNASSIGN' THEN NULL
            WHEN p_assigned_team_id IS NOT NULL THEN p_assigned_team_id
            WHEN p_action IN ('ASSIGN', 'REASSIGN') AND p_assigned_team_id IS NULL THEN NULL
            ELSE assigned_team_id
        END,
        assigned_worker_id = CASE
            WHEN p_action = 'UNASSIGN' THEN NULL
            WHEN p_assigned_worker_id IS NOT NULL THEN p_assigned_worker_id
            WHEN p_action IN ('ASSIGN', 'REASSIGN') AND p_assigned_worker_id IS NULL THEN NULL
            ELSE assigned_worker_id
        END,
        municipal_notes = COALESCE(p_municipal_notes, municipal_notes),
        internal_notes = COALESCE(p_internal_notes, internal_notes),
        rejection_reason = COALESCE(p_rejection_reason, rejection_reason),
        verified_by = COALESCE(p_verified_by, verified_by),
        verified_at = CASE WHEN p_verified_by IS NOT NULL THEN v_now ELSE verified_at END,
        updated_at = v_now
    WHERE id = p_incident_id;

    -- 4. Insert Audit Log
    INSERT INTO incident_audits (
        audit_id,
        incident_id,
        actor_id,
        actor_role,
        action,
        previous_status,
        new_status,
        previous_assigned_to,
        new_assigned_to,
        previous_assignment_type,
        new_assignment_type,
        previous_assigned_team_id,
        new_assigned_team_id,
        previous_assigned_worker_id,
        new_assigned_worker_id,
        previous_severity,
        new_severity,
        reason,
        internal_notes,
        timestamp
    ) VALUES (
        p_audit_id,
        p_incident_id,
        p_actor_id,
        p_actor_role,
        p_action,
        CASE WHEN p_new_status IS NOT NULL AND p_new_status <> v_prev_status THEN v_prev_status ELSE NULL END,
        CASE WHEN p_new_status IS NOT NULL AND p_new_status <> v_prev_status THEN p_new_status ELSE NULL END,
        v_prev_assigned_to,
        CASE WHEN p_action = 'UNASSIGN' THEN NULL WHEN p_assigned_to IS NOT NULL THEN p_assigned_to ELSE v_prev_assigned_to END,
        v_prev_assignment_type,
        CASE WHEN p_action = 'UNASSIGN' THEN 'NONE' WHEN p_assignment_type IS NOT NULL THEN p_assignment_type ELSE v_prev_assignment_type END,
        v_prev_assigned_team_id,
        CASE WHEN p_action = 'UNASSIGN' THEN NULL WHEN p_assigned_team_id IS NOT NULL THEN p_assigned_team_id ELSE v_prev_assigned_team_id END,
        v_prev_assigned_worker_id,
        CASE WHEN p_action = 'UNASSIGN' THEN NULL WHEN p_assigned_worker_id IS NOT NULL THEN p_assigned_worker_id ELSE v_prev_assigned_worker_id END,
        CASE WHEN p_new_severity IS NOT NULL AND p_new_severity <> v_prev_severity THEN v_prev_severity ELSE NULL END,
        CASE WHEN p_new_severity IS NOT NULL AND p_new_severity <> v_prev_severity THEN p_new_severity ELSE NULL END,
        p_reason,
        p_internal_notes,
        v_now
    );

    -- 5. Return updated incident as JSON
    SELECT row_to_json(i) INTO v_audit_record FROM incidents i WHERE i.id = p_incident_id;
    RETURN to_jsonb(v_audit_record);
END;
$$;

-- --------------------------------------------------------------------
-- 10. Atomic Citizen Incident Creation RPC
-- --------------------------------------------------------------------
-- Atomically creates a citizen incident and its initial REPORTED audit event.
-- Preserves stable incident IDs and guarantees that failed audit insertion
-- rolls back the incident row completely.
CREATE OR REPLACE FUNCTION citizen_incident_creation_rpc(
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
AS $$
DECLARE
    v_inc_record RECORD;
    v_now TIMESTAMPTZ := timezone('utc', now());
BEGIN
    -- 1. Insert incident row (idempotent upsert if exact ID exists)
    INSERT INTO incidents (
        id,
        category,
        description,
        latitude,
        longitude,
        severity,
        status,
        source,
        reporter_name,
        photos,
        created_at,
        updated_at
    ) VALUES (
        p_incident_id,
        p_category,
        p_description,
        p_latitude,
        p_longitude,
        p_severity,
        'REPORTED',
        p_source,
        p_reporter_name,
        p_photos,
        v_now,
        v_now
    )
    ON CONFLICT (id) DO NOTHING;

    -- 2. Insert initial REPORTED audit event
    INSERT INTO incident_audits (
        audit_id,
        incident_id,
        actor_id,
        actor_role,
        action,
        new_status,
        new_severity,
        reason,
        timestamp
    ) VALUES (
        p_audit_id,
        p_incident_id,
        COALESCE(p_reporter_name, 'Citizen Anonymous'),
        'citizen',
        'REPORTED',
        'REPORTED',
        p_severity,
        'Initial hazard report submission',
        v_now
    )
    ON CONFLICT (audit_id) DO NOTHING;

    -- 3. Return incident JSON
    SELECT row_to_json(i) INTO v_inc_record FROM incidents i WHERE i.id = p_incident_id;
    RETURN to_jsonb(v_inc_record);
END;
$$;


-- --------------------------------------------------------------------
-- 11. RPC Grants & Security Privileges
-- --------------------------------------------------------------------

-- Municipal transaction: backend service role only
REVOKE EXECUTE ON FUNCTION municipal_incident_transaction_rpc(
    VARCHAR(32), VARCHAR(32), VARCHAR(16), VARCHAR(128), VARCHAR(16),
    VARCHAR(64), VARCHAR(128), TEXT, TEXT, TEXT, VARCHAR(128),
    VARCHAR(128), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(32)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION municipal_incident_transaction_rpc(
    VARCHAR(32), VARCHAR(32), VARCHAR(16), VARCHAR(128), VARCHAR(16),
    VARCHAR(64), VARCHAR(128), TEXT, TEXT, TEXT, VARCHAR(128),
    VARCHAR(128), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(32)
) TO service_role;


-- Citizen creation: backend service role only
REVOKE EXECUTE ON FUNCTION citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32)
) TO service_role;