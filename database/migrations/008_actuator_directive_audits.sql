BEGIN;

-- =====================================================================
-- DRAIN-X Migration 008: Persistent Actuator Directive Audit Ledger
-- Target: Supabase / PostgreSQL 15+
-- =====================================================================
-- Foreign-Key Reconciliation Decision:
--   Migration 001 (001_initial_schema.sql) seeded 'SEC_SCREENING' in
--   public.drainage_sections, whereas ESP32 firmware (firmware/include/
--   config.h) and contract defaults emit SECTION_ID = 'SEC_SCREENING_01'.
--   Neither 001_initial_schema.sql nor firmware/include/config.h is
--   altered here; instead, Migration 008 idempotently seeds
--   'SEC_SCREENING_01' into public.drainage_sections with ON CONFLICT
--   DO NOTHING before creating the audit ledger so both identifiers are
--   valid ON DELETE RESTRICT foreign-key targets without breaking legacy
--   tests or physical hardware telemetry.
--
-- Security & Immutability Architecture:
--   1. Append-only ledger table public.actuator_directive_audits with
--      VARCHAR(64) audit_id, explicit typed columns (no JSONB blob),
--      STRICT CHECK constraints, and ON DELETE RESTRICT FKs.
--   2. Trigger functions (SECURITY DEFINER, pinned search_path) block
--      UPDATE, DELETE, and TRUNCATE with SQLSTATE '42501'.
--   3. Function EXECUTE privileges revoked from PUBLIC, anon, authenticated.
--   4. Row Level Security enabled; table privileges revoked from PUBLIC and
--      anon; authenticated granted SELECT only; service_role granted SELECT
--      and INSERT only (all UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER revoked).
--   5. RLS policies inspect trusted auth.jwt() -> 'app_metadata' exclusively:
--      - admin: unrestricted SELECT across all modes
--      - municipality: SELECT across all modes, respecting optional
--        assigned/allowed device and section scopes
--      - worker: SELECT restricted strictly to operational_mode = 'PHYSICAL'
--        and fail-closed against assigned device/section scopes
--      - service_role: SELECT and INSERT policies
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Reconcile physical firmware section ID without mutating Migration 001
-- ---------------------------------------------------------------------
INSERT INTO public.drainage_sections (
    section_id,
    name,
    description,
    length_cm,
    width_cm,
    depth_cm,
    critical_level_cm
)
VALUES (
    'SEC_SCREENING_01',
    'Primary Screening & Diversion Gate Node 01',
    'Physical ESP32 monitored screening and diversion gate section',
    30.0,
    10.0,
    15.0,
    12.0
)
ON CONFLICT (section_id) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. Append-Only Actuator Directive Audit Ledger Table
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.actuator_directive_audits (
    audit_id VARCHAR(64) PRIMARY KEY,
    directive_id VARCHAR(36) NOT NULL,
    event_type VARCHAR(32) NOT NULL,

    -- Foreign keys enforcing audit retention integrity
    device_id VARCHAR(64) NULL
        REFERENCES public.devices(device_id) ON DELETE RESTRICT,
    section_id VARCHAR(64) NOT NULL
        REFERENCES public.drainage_sections(section_id) ON DELETE RESTRICT,

    -- Operational partitioning
    operational_mode VARCHAR(32) NOT NULL,
    directive_type VARCHAR(32) NOT NULL DEFAULT 'DIVERSION_GATE',

    -- Commanded supervisory setpoint
    action VARCHAR(64) NOT NULL,
    gate_target_angle NUMERIC(5, 2) NOT NULL,
    reason TEXT NOT NULL,
    risk_level VARCHAR(16) NOT NULL DEFAULT 'INFO',
    emergency_stop BOOLEAN NOT NULL DEFAULT FALSE,

    -- Observed physical feedback (nullable for non-observation events)
    measured_gate_angle NUMERIC(5, 2) NULL,
    measured_gate_state VARCHAR(32) NULL,
    execution_divergence_deg NUMERIC(5, 2) NULL,

    -- Attribution & session-scoped monotonic telemetry counters
    issuer_type VARCHAR(32) NOT NULL DEFAULT 'AUTOMATED_ENGINE',
    issuer_id VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(64) NULL,
    device_session_epoch INTEGER NULL,
    baseline_device_sequence_number BIGINT NULL,
    device_sequence_number BIGINT NULL,
    device_uptime_ms BIGINT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),

    CONSTRAINT chk_directive_audits_audit_id_nonempty
        CHECK (pg_catalog.char_length(pg_catalog.btrim(audit_id)) BETWEEN 1 AND 64),
    CONSTRAINT chk_directive_audits_directive_id_nonempty
        CHECK (pg_catalog.char_length(pg_catalog.btrim(directive_id)) BETWEEN 1 AND 36),
    CONSTRAINT chk_directive_audits_event_type
        CHECK (
            event_type IN (
                'ISSUED',
                'FEEDBACK_RECEIVED',
                'ALIGNMENT_OBSERVED',
                'REJECTED',
                'EXECUTION_FAILED',
                'VERIFICATION_TIMEOUT',
                'SUPERSEDED',
                'CANCELLED'
            )
        ),
    CONSTRAINT chk_directive_audits_operational_mode
        CHECK (operational_mode IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD')),
    CONSTRAINT chk_directive_audits_directive_type
        CHECK (directive_type = 'DIVERSION_GATE'),
    CONSTRAINT chk_directive_audits_action_nonempty
        CHECK (pg_catalog.char_length(pg_catalog.btrim(action)) >= 1),
    CONSTRAINT chk_directive_audits_target_angle
        CHECK (gate_target_angle >= 0.0 AND gate_target_angle <= 90.0),
    CONSTRAINT chk_directive_audits_reason_nonempty
        CHECK (pg_catalog.char_length(pg_catalog.btrim(reason)) >= 1),
    CONSTRAINT chk_directive_audits_risk_level
        CHECK (risk_level IN ('INFO', 'WARNING', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_directive_audits_measured_angle
        CHECK (
            measured_gate_angle IS NULL
            OR (measured_gate_angle >= 0.0 AND measured_gate_angle <= 90.0)
        ),
    CONSTRAINT chk_directive_audits_measured_state
        CHECK (
            measured_gate_state IS NULL
            OR measured_gate_state IN ('CLOSED', 'OPEN', 'SAFE_HOLD', 'UNINITIALIZED')
        ),
    CONSTRAINT chk_directive_audits_divergence
        CHECK (
            execution_divergence_deg IS NULL
            OR (execution_divergence_deg >= 0.0 AND execution_divergence_deg <= 90.0)
        ),
    CONSTRAINT chk_directive_audits_issuer_type
        CHECK (issuer_type IN ('AUTOMATED_ENGINE', 'SAFETY_INTERLOCK', 'OPERATOR')),
    CONSTRAINT chk_directive_audits_issuer_id_nonempty
        CHECK (pg_catalog.char_length(pg_catalog.btrim(issuer_id)) >= 1),
    CONSTRAINT chk_directive_audits_session_epoch
        CHECK (device_session_epoch IS NULL OR device_session_epoch >= 0),
    CONSTRAINT chk_directive_audits_baseline_seq
        CHECK (
            baseline_device_sequence_number IS NULL
            OR (baseline_device_sequence_number >= 0 AND baseline_device_sequence_number <= 4294967295)
        ),
    CONSTRAINT chk_directive_audits_device_seq
        CHECK (
            device_sequence_number IS NULL
            OR (device_sequence_number >= 0 AND device_sequence_number <= 4294967295)
        ),
    CONSTRAINT chk_directive_audits_uptime_ms
        CHECK (
            device_uptime_ms IS NULL
            OR (device_uptime_ms >= 0 AND device_uptime_ms <= 4294967295)
        )
);

-- ---------------------------------------------------------------------
-- 3. Performance, Scoped Query & Startup Recovery Lookup Indexes
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_directive_audits_directive_seq
    ON public.actuator_directive_audits (directive_id, timestamp ASC, audit_id ASC);

CREATE INDEX IF NOT EXISTS idx_directive_audits_recovery_lookup
    ON public.actuator_directive_audits (directive_id, timestamp DESC, audit_id DESC);

CREATE INDEX IF NOT EXISTS idx_directive_audits_device_ts
    ON public.actuator_directive_audits (device_id, timestamp DESC)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_directive_audits_device_session
    ON public.actuator_directive_audits (device_id, device_session_epoch, timestamp ASC)
    WHERE device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_directive_audits_mode_ts
    ON public.actuator_directive_audits (operational_mode, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_directive_audits_mode_section_ts
    ON public.actuator_directive_audits (operational_mode, section_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_directive_audits_event_ts
    ON public.actuator_directive_audits (event_type, timestamp DESC);

-- ---------------------------------------------------------------------
-- 4. Immutability Enforcement: Block UPDATE, DELETE, and TRUNCATE
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.prevent_directive_audit_mutation_or_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION
        'Actuator directive audit ledger is strictly append-only. % is prohibited.', TG_OP
        USING ERRCODE = '42501';
END;
$function$;

CREATE OR REPLACE FUNCTION public.prevent_directive_audit_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION
        'Actuator directive audit ledger is strictly append-only. TRUNCATE is prohibited.'
        USING ERRCODE = '42501';
END;
$function$;

DROP TRIGGER IF EXISTS trg_immutable_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP TRIGGER IF EXISTS trg_no_truncate_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP TRIGGER IF EXISTS trg_prevent_directive_audit_mutation
    ON public.actuator_directive_audits;
DROP TRIGGER IF EXISTS trg_prevent_directive_audit_truncate
    ON public.actuator_directive_audits;

CREATE TRIGGER trg_prevent_directive_audit_mutation
    BEFORE UPDATE OR DELETE ON public.actuator_directive_audits
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_directive_audit_mutation_or_deletion();

CREATE TRIGGER trg_prevent_directive_audit_truncate
    BEFORE TRUNCATE ON public.actuator_directive_audits
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.prevent_directive_audit_truncate();

REVOKE ALL ON FUNCTION public.prevent_directive_audit_mutation_or_deletion()
    FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_directive_audit_truncate()
    FROM PUBLIC, anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- 5. Row Level Security & Least-Privilege Grants
-- ---------------------------------------------------------------------
ALTER TABLE public.actuator_directive_audits ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.actuator_directive_audits
    FROM PUBLIC, anon, authenticated, service_role;

GRANT SELECT ON TABLE public.actuator_directive_audits TO authenticated;
GRANT SELECT, INSERT ON TABLE public.actuator_directive_audits TO service_role;

REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON TABLE public.actuator_directive_audits
    FROM PUBLIC, anon, authenticated, service_role;

DROP POLICY IF EXISTS service_role_all_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP POLICY IF EXISTS service_role_select_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP POLICY IF EXISTS service_role_insert_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP POLICY IF EXISTS municipal_read_actuator_directive_audits
    ON public.actuator_directive_audits;
DROP POLICY IF EXISTS worker_read_physical_actuator_directive_audits
    ON public.actuator_directive_audits;

-- Service role policies scoped strictly to SELECT and INSERT
CREATE POLICY service_role_select_actuator_directive_audits
    ON public.actuator_directive_audits
    FOR SELECT
    TO service_role
    USING (true);

CREATE POLICY service_role_insert_actuator_directive_audits
    ON public.actuator_directive_audits
    FOR INSERT
    TO service_role
    WITH CHECK (true);

-- Admins (unrestricted) and municipality operators (canonical app_metadata arrays only)
CREATE POLICY municipal_read_actuator_directive_audits
    ON public.actuator_directive_audits
    FOR SELECT
    TO authenticated
    USING (
        pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata') = 'object'
        AND (
            COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', '') = 'admin'
            OR (
                COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', '') = 'municipality'
                AND NOT COALESCE(
                    (auth.jwt() -> 'app_metadata') ?| ARRAY[
                        'assigned_device',
                        'allowed_device',
                        'device_id',
                        'assigned_section',
                        'allowed_section',
                        'section_id'
                    ],
                    FALSE
                )
                AND (
                    NOT ((auth.jwt() -> 'app_metadata') ? 'assigned_devices')
                    OR (
                        device_id IS NOT NULL
                        AND pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'assigned_devices') = 'array'
                        AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'assigned_devices') > 0
                        AND NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'assigned_devices') AS elem
                            WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                               OR pg_catalog.btrim(elem #>> '{}') = ''
                               OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                        )
                        AND (auth.jwt() -> 'app_metadata' -> 'assigned_devices') ? device_id::text
                    )
                )
                AND (
                    NOT ((auth.jwt() -> 'app_metadata') ? 'allowed_devices')
                    OR (
                        device_id IS NOT NULL
                        AND pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'allowed_devices') = 'array'
                        AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'allowed_devices') > 0
                        AND NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'allowed_devices') AS elem
                            WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                               OR pg_catalog.btrim(elem #>> '{}') = ''
                               OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                        )
                        AND (auth.jwt() -> 'app_metadata' -> 'allowed_devices') ? device_id::text
                    )
                )
                AND (
                    NOT ((auth.jwt() -> 'app_metadata') ? 'assigned_sections')
                    OR (
                        pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'assigned_sections') = 'array'
                        AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'assigned_sections') > 0
                        AND NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'assigned_sections') AS elem
                            WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                               OR pg_catalog.btrim(elem #>> '{}') = ''
                               OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                        )
                        AND (auth.jwt() -> 'app_metadata' -> 'assigned_sections') ? section_id::text
                    )
                )
                AND (
                    NOT ((auth.jwt() -> 'app_metadata') ? 'allowed_sections')
                    OR (
                        pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'allowed_sections') = 'array'
                        AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'allowed_sections') > 0
                        AND NOT EXISTS (
                            SELECT 1
                            FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'allowed_sections') AS elem
                            WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                               OR pg_catalog.btrim(elem #>> '{}') = ''
                               OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                        )
                        AND (auth.jwt() -> 'app_metadata' -> 'allowed_sections') ? section_id::text
                    )
                )
            )
        )
    );

-- Field workers: strictly PHYSICAL mode only and fail-closed on canonical app_metadata arrays
CREATE POLICY worker_read_physical_actuator_directive_audits
    ON public.actuator_directive_audits
    FOR SELECT
    TO authenticated
    USING (
        pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata') = 'object'
        AND COALESCE(auth.jwt() -> 'app_metadata' ->> 'role', '') = 'worker'
        AND operational_mode = 'PHYSICAL'
        AND NOT COALESCE(
            (auth.jwt() -> 'app_metadata') ?| ARRAY[
                'assigned_device',
                'allowed_device',
                'device_id',
                'assigned_section',
                'allowed_section',
                'section_id'
            ],
            FALSE
        )
        AND COALESCE(
            (auth.jwt() -> 'app_metadata') ?| ARRAY[
                'assigned_devices',
                'allowed_devices',
                'assigned_sections',
                'allowed_sections'
            ],
            FALSE
        )
        AND (
            NOT ((auth.jwt() -> 'app_metadata') ? 'assigned_devices')
            OR (
                device_id IS NOT NULL
                AND pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'assigned_devices') = 'array'
                AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'assigned_devices') > 0
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'assigned_devices') AS elem
                    WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                       OR pg_catalog.btrim(elem #>> '{}') = ''
                       OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                )
                AND (auth.jwt() -> 'app_metadata' -> 'assigned_devices') ? device_id::text
            )
        )
        AND (
            NOT ((auth.jwt() -> 'app_metadata') ? 'allowed_devices')
            OR (
                device_id IS NOT NULL
                AND pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'allowed_devices') = 'array'
                AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'allowed_devices') > 0
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'allowed_devices') AS elem
                    WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                       OR pg_catalog.btrim(elem #>> '{}') = ''
                       OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                )
                AND (auth.jwt() -> 'app_metadata' -> 'allowed_devices') ? device_id::text
            )
        )
        AND (
            NOT ((auth.jwt() -> 'app_metadata') ? 'assigned_sections')
            OR (
                pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'assigned_sections') = 'array'
                AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'assigned_sections') > 0
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'assigned_sections') AS elem
                    WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                       OR pg_catalog.btrim(elem #>> '{}') = ''
                       OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                )
                AND (auth.jwt() -> 'app_metadata' -> 'assigned_sections') ? section_id::text
            )
        )
        AND (
            NOT ((auth.jwt() -> 'app_metadata') ? 'allowed_sections')
            OR (
                pg_catalog.jsonb_typeof(auth.jwt() -> 'app_metadata' -> 'allowed_sections') = 'array'
                AND pg_catalog.jsonb_array_length(auth.jwt() -> 'app_metadata' -> 'allowed_sections') > 0
                AND NOT EXISTS (
                    SELECT 1
                    FROM pg_catalog.jsonb_array_elements(auth.jwt() -> 'app_metadata' -> 'allowed_sections') AS elem
                    WHERE pg_catalog.jsonb_typeof(elem) <> 'string'
                       OR pg_catalog.btrim(elem #>> '{}') = ''
                       OR pg_catalog.btrim(elem #>> '{}') <> (elem #>> '{}')
                )
                AND (auth.jwt() -> 'app_metadata' -> 'allowed_sections') ? section_id::text
            )
        )
    );

COMMIT;
