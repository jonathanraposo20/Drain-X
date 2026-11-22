BEGIN;

-- =====================================================================
-- DRAIN-X Milestone 2 V3.1 Complete SQL Specification
-- Target Canonical Migration File (Future Implementation):
--   database/migrations/005_incident_photo_storage_registry_and_rpcs.sql
-- Canonical Storage Bucket:
--   incident-evidence
--
-- Actor-Role Normalization & Trust Boundary Contract:
--   1. Ordinary Photo Attachment (FastAPI -> PersistenceRepository -> RPCs 1..6, 9):
--      FastAPI verifies JWT claims (or unauthenticated public context) and maps:
--        * citizen / unauthenticated (None) -> 'citizen'
--        * municipality / municipal_officer -> 'municipal_officer'
--        * worker / field_worker            -> 'field_worker'
--        * admin                            -> 'admin'
--        * service_role / system            -> 'system'
--      Ordinary upload requests generate ONLY request leases (^req_lease_[a-f0-9]{32}$)
--      and MUST NEVER invoke RPC 7 (claim_expired_cleanup_operation_rpc) or
--      RPC 8 (reconcile_storage_orphan_rpc).
--   2. Privileged Recovery Operations (RPCs 7 & 8 + post-takeover RPCs 5 & 6):
--      Reachable ONLY via:
--        (a) Dedicated Admin endpoint gated by Depends(require_roles(["admin", "service_role"]))
--            deriving p_recovery_actor_id = claims["sub"] and p_recovery_actor_role = 'admin'
--            (or 'system' for service_role) strictly from verified JWT claims; OR
--        (b) Trusted internal background recovery worker passing fixed server identity
--            p_recovery_actor_id = 'system:storage-recovery-worker', p_recovery_actor_role = 'system'.
--      Recovery workers use ONLY recovery leases (^rec_lease_[a-f0-9]{32}$).
-- =====================================================================

-- =====================================================================
-- 0. Remove Milestone 1 Single-Stage 5-Parameter Bypass RPC (RESTRICT)
-- =====================================================================
DROP FUNCTION IF EXISTS public.attach_incident_photos_rpc(
    VARCHAR(32), TEXT[], VARCHAR(32), VARCHAR(128), VARCHAR(64)
) RESTRICT;

-- =====================================================================
-- 1. Tables & Constraints
-- =====================================================================
CREATE TABLE IF NOT EXISTS public.storage_object_registry (
    object_path TEXT PRIMARY KEY,
    incident_id VARCHAR(32) NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    bucket VARCHAR(64) NOT NULL DEFAULT 'incident-evidence',
    status VARCHAR(32) NOT NULL DEFAULT 'REGISTERED'
        CHECK (status IN ('REGISTERED', 'ATTACHED', 'CLEANUP_PENDING', 'DELETED', 'UNCERTAIN')),
    active_claim_count INT NOT NULL DEFAULT 0 CHECK (active_claim_count >= 0),
    created_by_lease VARCHAR(64) NOT NULL,
    claimed_by_lease VARCHAR(64),
    verified_by_lease VARCHAR(64),
    verified_sha256 CHAR(64),
    verified_mime VARCHAR(32),
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT valid_canonical_bucket CHECK (
        bucket = 'incident-evidence'
    ),
    CONSTRAINT valid_canonical_object_path CHECK (
        object_path ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$'
        AND split_part(object_path, '/', 1) = incident_id
    ),
    CONSTRAINT valid_verified_digest_and_mime CHECK (
        (
            last_verified_at IS NULL
            AND verified_sha256 IS NULL
            AND verified_mime IS NULL
            AND verified_by_lease IS NULL
        )
        OR (
            last_verified_at IS NOT NULL
            AND verified_sha256 IS NOT NULL
            AND verified_mime IS NOT NULL
            AND verified_by_lease IS NOT NULL
            AND verified_sha256 = substring(object_path from '/sha256_([a-f0-9]{64})\.')
            AND (
                (substring(object_path from '\.(jpg|png|webp)$') = 'jpg' AND verified_mime = 'image/jpeg')
                OR (substring(object_path from '\.(jpg|png|webp)$') = 'png' AND verified_mime = 'image/png')
                OR (substring(object_path from '\.(jpg|png|webp)$') = 'webp' AND verified_mime = 'image/webp')
            )
        )
    ),
    CONSTRAINT valid_cleanup_claim_lease_binding CHECK (
        (status IN ('CLEANUP_PENDING', 'UNCERTAIN') AND claimed_by_lease IS NOT NULL AND active_claim_count = 0)
        OR (status IN ('REGISTERED', 'ATTACHED', 'DELETED') AND claimed_by_lease IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_storage_object_registry_incident
    ON public.storage_object_registry (incident_id, status);

CREATE TABLE IF NOT EXISTS public.api_idempotency_keys (
    idempotency_key VARCHAR(64) NOT NULL,
    scope VARCHAR(64) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    incident_id VARCHAR(32) NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    request_fingerprint VARCHAR(64) NOT NULL,
    attempt_no INT NOT NULL DEFAULT 1 CHECK (attempt_no >= 1),
    lease_owner VARCHAR(64),
    expires_at TIMESTAMPTZ,
    status VARCHAR(24) NOT NULL DEFAULT 'IN_PROGRESS'
        CHECK (status IN (
            'IN_PROGRESS', 'COMPLETED', 'CLEANUP_PENDING', 'FAILED_CLEANED'
        )),
    response_body JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT pk_api_idempotency_keys PRIMARY KEY (idempotency_key, scope)
);

CREATE INDEX IF NOT EXISTS idx_api_idempotency_keys_incident
    ON public.api_idempotency_keys (incident_id, status);

CREATE TABLE IF NOT EXISTS public.api_idempotency_objects (
    idempotency_key VARCHAR(64) NOT NULL,
    scope VARCHAR(64) NOT NULL,
    object_path TEXT NOT NULL REFERENCES public.storage_object_registry(object_path) ON DELETE RESTRICT,
    claim_state VARCHAR(16) NOT NULL DEFAULT 'ACTIVE'
        CHECK (claim_state IN ('ACTIVE', 'RELEASED', 'FINALIZED')),
    verified_by_lease VARCHAR(64),
    verified_sha256 CHAR(64),
    verified_mime VARCHAR(32),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_api_idempotency_objects PRIMARY KEY (idempotency_key, scope, object_path),
    CONSTRAINT fk_idempotency_master FOREIGN KEY (idempotency_key, scope)
        REFERENCES public.api_idempotency_keys(idempotency_key, scope) ON DELETE CASCADE,
    CONSTRAINT valid_claim_verification_consistency CHECK (
        (
            verified_at IS NULL
            AND verified_sha256 IS NULL
            AND verified_mime IS NULL
            AND verified_by_lease IS NULL
        )
        OR (
            verified_at IS NOT NULL
            AND verified_sha256 IS NOT NULL
            AND verified_mime IS NOT NULL
            AND verified_by_lease IS NOT NULL
            AND verified_sha256 = substring(object_path from '/sha256_([a-f0-9]{64})\.')
            AND (
                (substring(object_path from '\.(jpg|png|webp)$') = 'jpg' AND verified_mime = 'image/jpeg')
                OR (substring(object_path from '\.(jpg|png|webp)$') = 'png' AND verified_mime = 'image/png')
                OR (substring(object_path from '\.(jpg|png|webp)$') = 'webp' AND verified_mime = 'image/webp')
            )
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_idempotency_objects_path
    ON public.api_idempotency_objects (object_path);

CREATE TABLE IF NOT EXISTS public.storage_cleanup_operations (
    cleanup_id VARCHAR(64) PRIMARY KEY,
    idempotency_key VARCHAR(64) NOT NULL,
    scope VARCHAR(64) NOT NULL,
    attempt_no INT NOT NULL,
    incident_id VARCHAR(32) NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    lease_owner VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PARTIAL', 'CONFIRMED', 'UNCERTAIN', 'NO_OP')),
    retained_shared_paths TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    recovery_actor_id VARCHAR(128),
    recovery_claimed_at TIMESTAMPTZ,
    recovery_count INT NOT NULL DEFAULT 0 CHECK (recovery_count >= 0),
    error_detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT uq_cleanup_reservation_attempt UNIQUE (idempotency_key, scope, attempt_no),
    CONSTRAINT fk_cleanup_idempotency FOREIGN KEY (idempotency_key, scope)
        REFERENCES public.api_idempotency_keys(idempotency_key, scope) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_storage_cleanup_ops_status_expires
    ON public.storage_cleanup_operations (status, expires_at);

CREATE TABLE IF NOT EXISTS public.storage_cleanup_operation_objects (
    cleanup_id VARCHAR(64) NOT NULL REFERENCES public.storage_cleanup_operations(cleanup_id) ON DELETE CASCADE,
    object_path TEXT NOT NULL REFERENCES public.storage_object_registry(object_path) ON DELETE RESTRICT,
    outcome_status VARCHAR(24) NOT NULL DEFAULT 'PENDING'
        CHECK (outcome_status IN ('PENDING', 'DELETED', 'UNCERTAIN')),
    error_detail TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_cleanup_op_objects PRIMARY KEY (cleanup_id, object_path)
);

-- =====================================================================
-- 2. Row Level Security & Table Privilege Hardening
-- =====================================================================
ALTER TABLE public.storage_object_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_idempotency_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_cleanup_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.storage_cleanup_operation_objects ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE
    public.storage_object_registry,
    public.api_idempotency_keys,
    public.api_idempotency_objects,
    public.storage_cleanup_operations,
    public.storage_cleanup_operation_objects
FROM PUBLIC, anon, authenticated, service_role;

GRANT SELECT ON TABLE
    public.storage_object_registry,
    public.api_idempotency_keys,
    public.api_idempotency_objects,
    public.storage_cleanup_operations,
    public.storage_cleanup_operation_objects
TO service_role;

-- =====================================================================
-- 3. Immutability & Reference-Count Triggers
-- =====================================================================
CREATE OR REPLACE FUNCTION public.enforce_storage_registry_immutability()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status = 'ATTACHED' THEN
            RAISE EXCEPTION 'Illegal deletion: ATTACHED storage object rows cannot be deleted'
                USING ERRCODE = '23505';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status = 'ATTACHED' THEN
        RAISE EXCEPTION 'Illegal mutation: ATTACHED storage object rows are completely immutable'
            USING ERRCODE = '23505';
    END IF;

    IF NEW.object_path IS DISTINCT FROM OLD.object_path
       OR NEW.incident_id IS DISTINCT FROM OLD.incident_id
       OR NEW.bucket IS DISTINCT FROM OLD.bucket THEN
        RAISE EXCEPTION 'Illegal mutation: object_path, incident_id, and bucket are immutable'
            USING ERRCODE = '23505';
    END IF;

    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.prevent_storage_registry_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION 'Storage object registry cannot be truncated'
        USING ERRCODE = '42501';
END;
$function$;

DROP TRIGGER IF EXISTS trg_storage_registry_immutability ON public.storage_object_registry;
DROP TRIGGER IF EXISTS trg_no_truncate_storage_registry ON public.storage_object_registry;

CREATE TRIGGER trg_storage_registry_immutability
    BEFORE UPDATE OR DELETE ON public.storage_object_registry
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_storage_registry_immutability();

CREATE TRIGGER trg_no_truncate_storage_registry
    BEFORE TRUNCATE ON public.storage_object_registry
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.prevent_storage_registry_truncate();

-- V3.1 Reference-Count Trigger:
-- 1. Never skips a decrement (no status <> 'ATTACHED' bypass).
-- 2. Permits active_claim_count mutations ONLY while storage_object_registry.status = 'REGISTERED'.
-- 3. Enforces complete immutability on FINALIZED claim mappings (blocks any UPDATE or DELETE when OLD.claim_state = 'FINALIZED').
CREATE OR REPLACE FUNCTION public.maintain_storage_active_claim_count()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_delta INT := 0;
    v_path TEXT;
    v_obj_status VARCHAR(32);
    v_updated_count INT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_path := NEW.object_path;
        IF NEW.claim_state <> 'ACTIVE' THEN
            RAISE EXCEPTION 'New api_idempotency_objects mappings must start in ACTIVE state'
                USING ERRCODE = '23505';
        END IF;
        v_delta := 1;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.claim_state = 'FINALIZED' THEN
            RAISE EXCEPTION 'Illegal mutation: FINALIZED claim mappings are completely immutable'
                USING ERRCODE = '23505';
        END IF;
        IF NEW.object_path IS DISTINCT FROM OLD.object_path
           OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
           OR NEW.scope IS DISTINCT FROM OLD.scope THEN
            RAISE EXCEPTION 'Cannot mutate primary key columns on api_idempotency_objects'
                USING ERRCODE = '23505';
        END IF;
        v_path := NEW.object_path;
        IF OLD.claim_state = 'RELEASED' AND NEW.claim_state = 'ACTIVE' THEN
            v_delta := 1;
        ELSIF OLD.claim_state = 'ACTIVE' AND NEW.claim_state IN ('RELEASED', 'FINALIZED') THEN
            v_delta := -1;
        ELSIF OLD.claim_state <> NEW.claim_state THEN
            RAISE EXCEPTION 'Illegal claim_state transition from % to %', OLD.claim_state, NEW.claim_state
                USING ERRCODE = '23505';
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.claim_state = 'FINALIZED' THEN
            RAISE EXCEPTION 'Illegal deletion: FINALIZED claim mappings cannot be deleted'
                USING ERRCODE = '23505';
        END IF;
        v_path := OLD.object_path;
        IF OLD.claim_state = 'ACTIVE' THEN
            v_delta := -1;
        END IF;
    END IF;

    IF v_delta <> 0 THEN
        SELECT status INTO v_obj_status
          FROM public.storage_object_registry
         WHERE object_path = v_path;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Registry row % missing during claim count update', v_path
                USING ERRCODE = '23505';
        END IF;

        IF v_obj_status <> 'REGISTERED' THEN
            RAISE EXCEPTION 'Cannot modify active_claim_count (delta %) for object % in non-REGISTERED state %',
                v_delta, v_path, v_obj_status
                USING ERRCODE = '23505';
        END IF;

        UPDATE public.storage_object_registry
           SET active_claim_count = active_claim_count + v_delta,
               updated_at = now()
         WHERE object_path = v_path
           AND status = 'REGISTERED';
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to apply active_claim_count delta for %', v_path
                USING ERRCODE = '23505';
        END IF;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$function$;

DROP TRIGGER IF EXISTS trg_maintain_storage_active_claim_count ON public.api_idempotency_objects;

CREATE TRIGGER trg_maintain_storage_active_claim_count
    AFTER INSERT OR UPDATE OR DELETE ON public.api_idempotency_objects
    FOR EACH ROW
    EXECUTE FUNCTION public.maintain_storage_active_claim_count();

REVOKE ALL ON FUNCTION public.enforce_storage_registry_immutability() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.prevent_storage_registry_truncate() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON FUNCTION public.maintain_storage_active_claim_count() FROM PUBLIC, anon, authenticated, service_role;

-- =====================================================================
-- 4. RPC 1: reserve_photo_attachment_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.reserve_photo_attachment_rpc(
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_actor_id VARCHAR(128),
    p_incident_id VARCHAR(32),
    p_request_fingerprint VARCHAR(64),
    p_object_paths TEXT[],
    p_lease_owner VARCHAR(64),
    p_lease_sec INT DEFAULT 60
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_sorted_paths TEXT[];
    v_inc public.incidents%ROWTYPE;
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_existing_paths TEXT[];
    v_path TEXT;
    v_existing_obj public.storage_object_registry%ROWTYPE;
    v_next_attempt INT;
    v_new_expires TIMESTAMPTZ;
    v_updated_count INT;
    v_lease_changed BOOLEAN;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_sec IS NULL OR p_lease_sec < 15 OR p_lease_sec > 300 THEN
        RAISE EXCEPTION 'Invalid p_lease_sec (%): must be between 15 and 300 seconds', p_lease_sec
            USING ERRCODE = '22023';
    END IF;
    v_new_expires := now() + make_interval(secs => p_lease_sec);

    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^req_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid request lease_owner format' USING ERRCODE = '22023';
    END IF;

    IF p_object_paths IS NULL OR cardinality(p_object_paths) = 0 OR cardinality(p_object_paths) > 3 THEN
        RAISE EXCEPTION 'Between 1 and 3 photo paths are required' USING ERRCODE = '22023';
    END IF;

    SELECT ARRAY(SELECT DISTINCT p FROM unnest(p_object_paths) AS p ORDER BY 1) INTO v_sorted_paths;
    IF cardinality(v_sorted_paths) <> cardinality(p_object_paths) THEN
        RAISE EXCEPTION 'Duplicate photo paths are not permitted in reservation' USING ERRCODE = '22023';
    END IF;

    FOREACH v_path IN ARRAY v_sorted_paths LOOP
        IF NOT (v_path ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$')
           OR split_part(v_path, '/', 1) IS DISTINCT FROM p_incident_id THEN
            RAISE EXCEPTION 'Canonical object path % does not match incident %', v_path, p_incident_id
                USING ERRCODE = '42501';
        END IF;
    END LOOP;

    -- Level 1: Lock Incident
    SELECT * INTO v_inc FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2: Upsert & Lock Idempotency Key
    INSERT INTO public.api_idempotency_keys (
        idempotency_key, scope, actor_id, incident_id,
        request_fingerprint, attempt_no, lease_owner, expires_at, status
    )
    VALUES (
        p_idempotency_key, p_scope, p_actor_id, p_incident_id,
        p_request_fingerprint, 1, p_lease_owner, v_new_expires, 'IN_PROGRESS'
    )
    ON CONFLICT (idempotency_key, scope) DO NOTHING;

    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key lock acquisition failed' USING ERRCODE = '22023';
    END IF;

    IF v_key_record.actor_id IS DISTINCT FROM p_actor_id
       OR v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_key_record.request_fingerprint IS DISTINCT FROM p_request_fingerprint THEN
        RAISE EXCEPTION 'Idempotency key conflict on actor, incident, or payload fingerprint'
            USING ERRCODE = '23505';
    END IF;

    SELECT array_agg(object_path ORDER BY object_path ASC) INTO v_existing_paths
      FROM public.api_idempotency_objects
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;

    IF v_existing_paths IS NOT NULL AND v_existing_paths IS DISTINCT FROM v_sorted_paths THEN
        RAISE EXCEPTION 'Idempotency key conflict on normalized object mapping'
            USING ERRCODE = '23505';
    END IF;

    -- Legitimate idempotent replay of an already-completed reservation returns cached response at Level 2
    IF v_key_record.status = 'COMPLETED' THEN
        IF v_existing_paths IS NULL OR v_existing_paths IS DISTINCT FROM v_sorted_paths THEN
            RAISE EXCEPTION 'Idempotency key conflict on completed object mapping'
                USING ERRCODE = '23505';
        END IF;
        RETURN jsonb_build_object('status', 'COMPLETED', 'response', v_key_record.response_body);
    END IF;

    -- Reject terminal RESOLVED or REJECTED incidents after handling completed idempotent replay
    IF v_inc.status IN ('RESOLVED', 'REJECTED') THEN
        RAISE EXCEPTION 'Cannot attach photos to terminal incident % in status %', p_incident_id, v_inc.status
            USING ERRCODE = '23514';
    END IF;

    IF v_key_record.status = 'CLEANUP_PENDING' THEN
        RETURN jsonb_build_object('status', 'CLEANUP_IN_FLIGHT');
    END IF;
    IF v_key_record.status = 'IN_PROGRESS'
       AND v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       AND v_key_record.expires_at > now() THEN
        RETURN jsonb_build_object('status', 'ACTIVE_LOCK', 'expires_at', v_key_record.expires_at);
    END IF;

    -- Reject if any requested path is already attached to the incident photos array
    IF COALESCE(v_inc.photos, ARRAY[]::TEXT[]) && v_sorted_paths THEN
        RAISE EXCEPTION 'One or more photo paths are already attached to incident %', p_incident_id
            USING ERRCODE = '23505';
    END IF;

    v_lease_changed := (v_key_record.lease_owner IS DISTINCT FROM p_lease_owner);

    v_next_attempt := CASE
        WHEN v_key_record.status = 'FAILED_CLEANED'
        THEN v_key_record.attempt_no + 1
        ELSE v_key_record.attempt_no
    END;

    UPDATE public.api_idempotency_keys
       SET status = 'IN_PROGRESS',
           attempt_no = v_next_attempt,
           lease_owner = p_lease_owner,
           expires_at = v_new_expires
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update idempotency reservation lease' USING ERRCODE = '23505';
    END IF;

    -- Level 3: Register missing rows (count=0, claimed_by_lease=NULL) & Lock all rows alphabetically
    FOREACH v_path IN ARRAY v_sorted_paths LOOP
        INSERT INTO public.storage_object_registry (
            object_path, incident_id, bucket, status, active_claim_count, created_by_lease, claimed_by_lease
        )
        VALUES (v_path, p_incident_id, 'incident-evidence', 'REGISTERED', 0, p_lease_owner, NULL)
        ON CONFLICT (object_path) DO NOTHING;
    END LOOP;

    PERFORM 1
       FROM public.storage_object_registry
      WHERE object_path = ANY(v_sorted_paths)
      ORDER BY object_path ASC
        FOR UPDATE;

    FOREACH v_path IN ARRAY v_sorted_paths LOOP
        SELECT * INTO v_existing_obj FROM public.storage_object_registry WHERE object_path = v_path;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Registry row % unexpectedly missing', v_path USING ERRCODE = '22023';
        END IF;
        IF v_existing_obj.incident_id IS DISTINCT FROM p_incident_id THEN
            RAISE EXCEPTION 'Cross-incident object path violation: %', v_path USING ERRCODE = '42501';
        END IF;

        -- Reject terminal ATTACHED as well as CLEANUP_PENDING and UNCERTAIN objects
        IF v_existing_obj.status IN ('ATTACHED', 'CLEANUP_PENDING', 'UNCERTAIN') THEN
            RAISE EXCEPTION 'Object % cannot be reserved in state %', v_path, v_existing_obj.status
                USING ERRCODE = '23505';
        END IF;

        -- DELETED -> REGISTERED transition: reset verification metadata and ensure claimed_by_lease is NULL
        IF v_existing_obj.status = 'DELETED' THEN
            UPDATE public.storage_object_registry
               SET status = 'REGISTERED',
                   claimed_by_lease = NULL,
                   verified_by_lease = NULL,
                   verified_sha256 = NULL,
                   verified_mime = NULL,
                   last_verified_at = NULL,
                   updated_at = now()
             WHERE object_path = v_path
               AND status = 'DELETED';
            GET DIAGNOSTICS v_updated_count = ROW_COUNT;
            IF v_updated_count <> 1 THEN
                RAISE EXCEPTION 'Failed to transition DELETED object % to REGISTERED', v_path USING ERRCODE = '23505';
            END IF;
        END IF;
    END LOOP;

    -- Insert new ACTIVE claim, reactivate RELEASED claim, or reset per-claim verification on expired lease takeover
    INSERT INTO public.api_idempotency_objects (
        idempotency_key, scope, object_path, claim_state,
        verified_by_lease, verified_sha256, verified_mime, verified_at
    )
    SELECT p_idempotency_key, p_scope, p, 'ACTIVE', NULL, NULL, NULL, NULL
      FROM unnest(v_sorted_paths) AS p
    ON CONFLICT (idempotency_key, scope, object_path) DO UPDATE
       SET claim_state = 'ACTIVE',
           verified_by_lease = NULL,
           verified_sha256 = NULL,
           verified_mime = NULL,
           verified_at = NULL,
           updated_at = now()
     WHERE public.api_idempotency_objects.claim_state = 'RELEASED'
        OR v_lease_changed;

    IF EXISTS (
        SELECT 1 FROM public.storage_object_registry
         WHERE object_path = ANY(v_sorted_paths)
           AND (status <> 'REGISTERED' OR active_claim_count < 1)
    ) THEN
        RAISE EXCEPTION 'Invariant violation: reserved object is not REGISTERED with active_claim_count >= 1'
            USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object('status', 'RESERVED', 'attempt_no', v_next_attempt);
END;
$function$;

-- =====================================================================
-- 5. RPC 2: verify_and_register_storage_object_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.verify_and_register_storage_object_rpc(
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_lease_owner VARCHAR(64),
    p_object_path TEXT,
    p_verified_sha256 CHAR(64),
    p_verified_mime VARCHAR(32)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_obj_record public.storage_object_registry%ROWTYPE;
    v_expected_sha256 TEXT;
    v_ext TEXT;
    v_updated_count INT;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^req_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid request lease_owner format' USING ERRCODE = '22023';
    END IF;

    IF p_object_path IS NULL
       OR NOT (p_object_path ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$')
       OR split_part(p_object_path, '/', 1) IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Canonical object path % does not match incident %', p_object_path, p_incident_id
            USING ERRCODE = '42501';
    END IF;

    v_expected_sha256 := substring(p_object_path from '/sha256_([a-f0-9]{64})\.');
    v_ext := substring(p_object_path from '\.(jpg|png|webp)$');
    IF v_expected_sha256 IS NULL OR v_expected_sha256 IS DISTINCT FROM p_verified_sha256 THEN
        RAISE EXCEPTION 'Verified SHA-256 does not match canonical object path' USING ERRCODE = '22023';
    END IF;
    IF (v_ext = 'jpg' AND p_verified_mime IS DISTINCT FROM 'image/jpeg')
       OR (v_ext = 'png' AND p_verified_mime IS DISTINCT FROM 'image/png')
       OR (v_ext = 'webp' AND p_verified_mime IS DISTINCT FROM 'image/webp') THEN
        RAISE EXCEPTION 'Verified MIME type % does not match extension .%', p_verified_mime, v_ext USING ERRCODE = '22023';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Reservation not found' USING ERRCODE = '22023';
    END IF;
    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Reservation incident mismatch' USING ERRCODE = '42501';
    END IF;
    IF v_key_record.status <> 'IN_PROGRESS'
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now() THEN
        RAISE EXCEPTION 'Stale or expired lease cannot verify object' USING ERRCODE = '42501';
    END IF;

    -- Level 3: Lock Object Registry Row (Reject ATTACHED as well as non-REGISTERED states)
    SELECT * INTO v_obj_record
      FROM public.storage_object_registry
     WHERE object_path = p_object_path
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Registry object % missing', p_object_path USING ERRCODE = '22023';
    END IF;
    IF v_obj_record.incident_id IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Registry object belongs to different incident' USING ERRCODE = '42501';
    END IF;
    IF v_obj_record.status <> 'REGISTERED' OR v_obj_record.active_claim_count < 1 THEN
        RAISE EXCEPTION 'Object % in state % (claims: %) cannot be verified', p_object_path, v_obj_record.status, v_obj_record.active_claim_count
            USING ERRCODE = '23505';
    END IF;

    -- Record verification on the specific reservation claim row
    UPDATE public.api_idempotency_objects
       SET verified_by_lease = p_lease_owner,
           verified_sha256 = p_verified_sha256,
           verified_mime = p_verified_mime,
           verified_at = now(),
           updated_at = now()
     WHERE idempotency_key = p_idempotency_key
       AND scope = p_scope
       AND object_path = p_object_path
       AND claim_state = 'ACTIVE';
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Object % is not an active claim of this reservation', p_object_path USING ERRCODE = '42501';
    END IF;

    -- Update object-level verification provenance (keeping claimed_by_lease NULL while REGISTERED)
    UPDATE public.storage_object_registry
       SET verified_by_lease = p_lease_owner,
           verified_sha256 = p_verified_sha256,
           verified_mime = p_verified_mime,
           last_verified_at = now(),
           claimed_by_lease = NULL,
           updated_at = now()
     WHERE object_path = p_object_path
       AND status = 'REGISTERED';
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update verification state for %', p_object_path USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object('status', 'VERIFIED_REGISTERED');
END;
$function$;

-- =====================================================================
-- 6. RPC 3: finalize_photo_attachment_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.finalize_photo_attachment_rpc(
    p_incident_id VARCHAR(32),
    p_photos TEXT[],
    p_audit_id VARCHAR(32),
    p_actor_id VARCHAR(128),
    p_actor_role VARCHAR(64),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_request_fingerprint VARCHAR(64),
    p_lease_owner VARCHAR(64)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_sorted_paths TEXT[];
    v_inc public.incidents%ROWTYPE;
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_mapped_paths TEXT[];
    v_finalized_paths TEXT[];
    v_unverified_claim_count INT;
    v_found_count INT;
    v_invalid_count INT;
    v_updated_count INT;
    v_merged TEXT[];
    v_p TEXT;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;
    IF p_actor_role IS NULL OR p_actor_role NOT IN ('citizen', 'municipal_officer', 'field_worker', 'admin', 'system') THEN
        RAISE EXCEPTION 'Invalid actor role: %', p_actor_role USING ERRCODE = '22023';
    END IF;
    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^req_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid request lease_owner format' USING ERRCODE = '22023';
    END IF;
    IF p_photos IS NULL OR cardinality(p_photos) = 0 OR cardinality(p_photos) > 3 THEN
        RAISE EXCEPTION 'Between 1 and 3 photo paths are required' USING ERRCODE = '22023';
    END IF;

    SELECT ARRAY(SELECT DISTINCT p FROM unnest(p_photos) AS p ORDER BY 1) INTO v_sorted_paths;
    IF cardinality(v_sorted_paths) <> cardinality(p_photos) THEN
        RAISE EXCEPTION 'Duplicate photo paths are not permitted in finalization' USING ERRCODE = '22023';
    END IF;

    FOREACH v_p IN ARRAY v_sorted_paths LOOP
        IF NOT (v_p ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$')
           OR split_part(v_p, '/', 1) IS DISTINCT FROM p_incident_id THEN
            RAISE EXCEPTION 'Canonical object path % does not match incident %', v_p, p_incident_id USING ERRCODE = '42501';
        END IF;
    END LOOP;

    -- Level 1: Lock Incident
    SELECT * INTO v_inc FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2: Lock Idempotency Key
    SELECT * INTO v_key_record FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency reservation not found' USING ERRCODE = '22023';
    END IF;

    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_key_record.actor_id IS DISTINCT FROM p_actor_id
       OR v_key_record.request_fingerprint IS DISTINCT FROM p_request_fingerprint THEN
        RAISE EXCEPTION 'Idempotency identity or fingerprint mismatch' USING ERRCODE = '42501';
    END IF;

    -- Lost-response idempotent replay of an already-completed finalization
    IF v_key_record.status = 'COMPLETED' THEN
        SELECT array_agg(object_path ORDER BY object_path ASC)
          INTO v_finalized_paths
          FROM public.api_idempotency_objects
         WHERE idempotency_key = p_idempotency_key
           AND scope = p_scope
           AND claim_state = 'FINALIZED';

        IF v_finalized_paths IS NULL OR v_finalized_paths IS DISTINCT FROM v_sorted_paths THEN
            RAISE EXCEPTION 'Completed finalization replay photo paths do not match finalized mapping'
                USING ERRCODE = '23505';
        END IF;

        RETURN v_key_record.response_body;
    END IF;

    -- Reject terminal RESOLVED or REJECTED incidents after handling completed idempotent replay
    IF v_inc.status IN ('RESOLVED', 'REJECTED') THEN
        RAISE EXCEPTION 'Cannot finalize photos on terminal incident % in status %', p_incident_id, v_inc.status
            USING ERRCODE = '23514';
    END IF;

    IF v_key_record.status <> 'IN_PROGRESS'
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now() THEN
        RAISE EXCEPTION 'Stale, expired, or non-active lease during finalization' USING ERRCODE = '42501';
    END IF;

    -- Verify exact active mapping AND per-claim verification by THIS exact p_lease_owner
    SELECT array_agg(object_path ORDER BY object_path ASC),
           count(*) FILTER (WHERE
               verified_at IS NULL
               OR verified_by_lease IS NULL
               OR verified_by_lease IS DISTINCT FROM p_lease_owner
               OR verified_sha256 IS NULL
               OR verified_mime IS NULL
               OR verified_sha256 IS DISTINCT FROM substring(object_path from '/sha256_([a-f0-9]{64})\.')
           )
      INTO v_mapped_paths, v_unverified_claim_count
      FROM public.api_idempotency_objects
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope AND claim_state = 'ACTIVE';

    IF v_mapped_paths IS NULL OR v_mapped_paths IS DISTINCT FROM v_sorted_paths THEN
        RAISE EXCEPTION 'Finalization photo paths do not match active reservation mapping' USING ERRCODE = '23505';
    END IF;
    IF v_unverified_claim_count > 0 THEN
        RAISE EXCEPTION 'One or more active reservation claims have not been verified by current lease %', p_lease_owner
            USING ERRCODE = '23505';
    END IF;

    -- Reject if any photo is already present in v_inc.photos (no silent skipping)
    IF COALESCE(v_inc.photos, ARRAY[]::TEXT[]) && v_sorted_paths THEN
        RAISE EXCEPTION 'One or more photo paths are already attached to incident %', p_incident_id
            USING ERRCODE = '23505';
    END IF;

    -- Level 3: Lock Object Registry Rows Alphabetically
    PERFORM 1 FROM public.storage_object_registry
     WHERE object_path = ANY(v_sorted_paths) ORDER BY object_path ASC FOR UPDATE;

    -- Require status = 'REGISTERED' (reject ATTACHED, CLEANUP_PENDING, UNCERTAIN, DELETED) and valid verification
    SELECT count(*),
           count(*) FILTER (WHERE
               incident_id IS DISTINCT FROM p_incident_id
               OR status <> 'REGISTERED'
               OR active_claim_count < 1
               OR last_verified_at IS NULL
               OR verified_mime IS NULL
               OR verified_sha256 IS DISTINCT FROM substring(object_path from '/sha256_([a-f0-9]{64})\.')
           )
      INTO v_found_count, v_invalid_count
      FROM public.storage_object_registry
     WHERE object_path = ANY(v_sorted_paths);

    IF v_found_count <> cardinality(v_sorted_paths) OR v_invalid_count > 0 THEN
        RAISE EXCEPTION 'One or more objects failed existence, REGISTERED state, claim, or verification checks'
            USING ERRCODE = '23505';
    END IF;

    v_merged := array_cat(COALESCE(v_inc.photos, ARRAY[]::TEXT[]), v_sorted_paths);
    IF cardinality(v_merged) > 3 THEN
        RAISE EXCEPTION 'Cannot exceed maximum limit of 3 photos per incident' USING ERRCODE = '22023';
    END IF;

    -- Step 1: Finalize caller's claims (trigger decrements active_claim_count by 1 for each object)
    UPDATE public.api_idempotency_objects
       SET claim_state = 'FINALIZED', updated_at = now()
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       AND object_path = ANY(v_sorted_paths) AND claim_state = 'ACTIVE';
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_sorted_paths) THEN
        RAISE EXCEPTION 'Failed to transition all active reservation mappings to FINALIZED' USING ERRCODE = '23505';
    END IF;

    -- Step 2: Transition REGISTERED -> ATTACHED ONLY where active_claim_count = 0 (never overwrite positive count!)
    UPDATE public.storage_object_registry
       SET status = 'ATTACHED', claimed_by_lease = NULL, updated_at = now()
     WHERE object_path = ANY(v_sorted_paths)
       AND status = 'REGISTERED'
       AND active_claim_count = 0;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_sorted_paths) THEN
        RAISE EXCEPTION 'Cannot transition to ATTACHED: competing active claims remain on one or more objects (expected %, updated %)',
            cardinality(v_sorted_paths), v_updated_count USING ERRCODE = '23505';
    END IF;

    -- Step 3: Update incident photos array
    UPDATE public.incidents SET photos = v_merged, updated_at = now()
     WHERE id = p_incident_id RETURNING * INTO v_inc;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Failed to update incident photos array' USING ERRCODE = '23505';
    END IF;

    -- Step 4: Append immutable audit record
    INSERT INTO public.incident_audits (
        audit_id, incident_id, actor_id, actor_role, action,
        new_status, new_severity, reason, timestamp
    )
    VALUES (
        p_audit_id, p_incident_id, p_actor_id, p_actor_role, 'ATTACH_PHOTOS',
        v_inc.status, v_inc.severity, format('ATTACH_PHOTOS count:%s fp:%s', cardinality(v_sorted_paths), p_request_fingerprint), now()
    );

    -- Step 5: Complete idempotency key
    UPDATE public.api_idempotency_keys
       SET status = 'COMPLETED', response_body = to_jsonb(v_inc),
           lease_owner = NULL, expires_at = NULL, completed_at = now()
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to mark idempotency reservation COMPLETED' USING ERRCODE = '23505';
    END IF;

    RETURN to_jsonb(v_inc);
END;
$function$;

-- =====================================================================
-- 7. RPC 4: initiate_storage_cleanup_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.initiate_storage_cleanup_rpc(
    p_cleanup_id VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_lease_owner VARCHAR(64),
    p_object_paths TEXT[],
    p_lease_sec INT DEFAULT 60
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_sorted_paths TEXT[];
    v_all_mapped_paths TEXT[];
    v_active_mapped_paths TEXT[];
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_existing_op public.storage_cleanup_operations%ROWTYPE;
    v_p TEXT;
    v_obj public.storage_object_registry%ROWTYPE;
    v_delete_authorized TEXT[] := ARRAY[]::TEXT[];
    v_retained_shared TEXT[] := ARRAY[]::TEXT[];
    v_new_expires TIMESTAMPTZ;
    v_updated_count INT;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_sec IS NULL OR p_lease_sec < 15 OR p_lease_sec > 300 THEN
        RAISE EXCEPTION 'Invalid p_lease_sec (%): must be between 15 and 300 seconds', p_lease_sec
            USING ERRCODE = '22023';
    END IF;
    v_new_expires := now() + make_interval(secs => p_lease_sec);

    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^req_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid request lease_owner format for cleanup initiation' USING ERRCODE = '22023';
    END IF;

    IF p_object_paths IS NULL OR cardinality(p_object_paths) = 0 OR cardinality(p_object_paths) > 3 THEN
        RAISE EXCEPTION 'Between 1 and 3 object paths are required' USING ERRCODE = '22023';
    END IF;

    SELECT ARRAY(SELECT DISTINCT p FROM unnest(p_object_paths) AS p ORDER BY 1) INTO v_sorted_paths;
    IF cardinality(v_sorted_paths) <> cardinality(p_object_paths) THEN
        RAISE EXCEPTION 'Duplicate object paths are not permitted' USING ERRCODE = '22023';
    END IF;

    FOREACH v_p IN ARRAY v_sorted_paths LOOP
        IF NOT (v_p ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$')
           OR split_part(v_p, '/', 1) IS DISTINCT FROM p_incident_id THEN
            RAISE EXCEPTION 'Canonical object path % does not match incident %', v_p, p_incident_id USING ERRCODE = '42501';
        END IF;
    END LOOP;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;
    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Idempotency key incident mismatch' USING ERRCODE = '42501';
    END IF;

    SELECT array_agg(object_path ORDER BY object_path ASC),
           array_agg(object_path ORDER BY object_path ASC) FILTER (WHERE claim_state = 'ACTIVE')
      INTO v_all_mapped_paths, v_active_mapped_paths
      FROM public.api_idempotency_objects
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;

    IF v_all_mapped_paths IS NULL OR v_sorted_paths IS DISTINCT FROM v_all_mapped_paths THEN
        RAISE EXCEPTION 'Cleanup paths do not match reservation normalized object mapping' USING ERRCODE = '42501';
    END IF;

    -- If finalization already succeeded before a lost HTTP response, return ALREADY_COMPLETED and never authorize deletion
    IF v_key_record.status = 'COMPLETED' THEN
        RETURN jsonb_build_object(
            'cleanup_id', NULL,
            'status', 'ALREADY_COMPLETED',
            'delete_authorized_paths', ARRAY[]::TEXT[],
            'retained_shared_paths', v_sorted_paths,
            'response', v_key_record.response_body,
            'idempotent_replay', true
        );
    END IF;

    -- Safe Idempotent Replay Check for this attempt_no
    SELECT * INTO v_existing_op
      FROM public.storage_cleanup_operations
     WHERE idempotency_key = p_idempotency_key
       AND scope = p_scope
       AND attempt_no = v_key_record.attempt_no
       FOR UPDATE;

    IF FOUND THEN
        IF v_existing_op.lease_owner IS NULL
           OR v_existing_op.lease_owner IS DISTINCT FROM p_lease_owner THEN
            RAISE EXCEPTION 'Cleanup replay denied: lease owner mismatch' USING ERRCODE = '42501';
        END IF;

        IF v_existing_op.status = 'CONFIRMED' THEN
            RETURN jsonb_build_object(
                'cleanup_id', v_existing_op.cleanup_id,
                'status', 'CLEANUP_ALREADY_CONFIRMED',
                'delete_authorized_paths', ARRAY[]::TEXT[],
                'retained_shared_paths', v_existing_op.retained_shared_paths,
                'idempotent_replay', true
            );
        END IF;

        IF v_existing_op.status = 'NO_OP' THEN
            RETURN jsonb_build_object(
                'cleanup_id', v_existing_op.cleanup_id,
                'status', 'NO_STORAGE_DELETE_REQUIRED',
                'delete_authorized_paths', ARRAY[]::TEXT[],
                'retained_shared_paths', v_existing_op.retained_shared_paths,
                'idempotent_replay', true
            );
        END IF;

        IF v_key_record.status <> 'CLEANUP_PENDING'
           OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
           OR v_key_record.expires_at IS NULL
           OR v_key_record.expires_at <= now()
           OR v_existing_op.expires_at IS NULL
           OR v_existing_op.expires_at <= now() THEN
            RAISE EXCEPTION 'Cleanup replay denied: cleanup lease has expired or key state changed' USING ERRCODE = '42501';
        END IF;

        PERFORM 1
           FROM public.storage_object_registry
          WHERE object_path = ANY(v_sorted_paths)
          ORDER BY object_path ASC
            FOR UPDATE;

        SELECT COALESCE(array_agg(coo.object_path ORDER BY coo.object_path ASC), ARRAY[]::TEXT[])
          INTO v_delete_authorized
          FROM public.storage_cleanup_operation_objects coo
          JOIN public.storage_object_registry sor ON sor.object_path = coo.object_path
         WHERE coo.cleanup_id = v_existing_op.cleanup_id
           AND coo.outcome_status IN ('PENDING', 'UNCERTAIN')
           AND sor.incident_id = p_incident_id
           AND sor.status IN ('CLEANUP_PENDING', 'UNCERTAIN')
           AND sor.active_claim_count = 0
           AND sor.claimed_by_lease = p_lease_owner;

        RETURN jsonb_build_object(
            'cleanup_id', v_existing_op.cleanup_id,
            'status', 'CLEANUP_AUTHORIZED',
            'delete_authorized_paths', v_delete_authorized,
            'retained_shared_paths', v_existing_op.retained_shared_paths,
            'idempotent_replay', true
        );
    END IF;

    IF v_key_record.status <> 'IN_PROGRESS'
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now() THEN
        RAISE EXCEPTION 'Cleanup denied: stale, expired, or non-active reservation lease' USING ERRCODE = '42501';
    END IF;

    IF v_active_mapped_paths IS DISTINCT FROM v_all_mapped_paths THEN
        RAISE EXCEPTION 'Reservation claims are not all in ACTIVE state' USING ERRCODE = '23505';
    END IF;

    -- Level 3: Lock Object Registry Rows Alphabetically
    PERFORM 1
       FROM public.storage_object_registry
      WHERE object_path = ANY(v_sorted_paths)
      ORDER BY object_path ASC
        FOR UPDATE;

    -- Release ONLY ACTIVE claims belonging to this reservation and clear per-claim verification metadata
    UPDATE public.api_idempotency_objects
       SET claim_state = 'RELEASED',
           verified_by_lease = NULL,
           verified_sha256 = NULL,
           verified_mime = NULL,
           verified_at = NULL,
           updated_at = now()
     WHERE idempotency_key = p_idempotency_key
       AND scope = p_scope
       AND object_path = ANY(v_sorted_paths)
       AND claim_state = 'ACTIVE';
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_sorted_paths) THEN
        RAISE EXCEPTION 'Failed to release all active reservation claims during cleanup initiation' USING ERRCODE = '23505';
    END IF;

    FOREACH v_p IN ARRAY v_sorted_paths LOOP
        SELECT * INTO v_obj FROM public.storage_object_registry WHERE object_path = v_p;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Object % missing from registry', v_p USING ERRCODE = '22023';
        END IF;
        IF v_obj.incident_id IS DISTINCT FROM p_incident_id THEN
            RAISE EXCEPTION 'Cross-incident violation for %', v_p USING ERRCODE = '42501';
        END IF;

        IF v_obj.status = 'ATTACHED'
           OR v_obj.active_claim_count > 0
           OR EXISTS (SELECT 1 FROM public.incidents WHERE photos @> ARRAY[v_p]) THEN
            v_retained_shared := array_append(v_retained_shared, v_p);
        ELSIF v_obj.status = 'REGISTERED' AND v_obj.active_claim_count = 0 THEN
            -- Immediately clear verification metadata and bind exclusive cleanup lease owner on CLEANUP_PENDING transition
            UPDATE public.storage_object_registry
               SET status = 'CLEANUP_PENDING',
                   claimed_by_lease = p_lease_owner,
                   verified_by_lease = NULL,
                   verified_sha256 = NULL,
                   verified_mime = NULL,
                   last_verified_at = NULL,
                   updated_at = now()
             WHERE object_path = v_p
               AND status = 'REGISTERED'
               AND active_claim_count = 0;
            GET DIAGNOSTICS v_updated_count = ROW_COUNT;
            IF v_updated_count <> 1 THEN
                RAISE EXCEPTION 'Failed to transition object % to CLEANUP_PENDING', v_p USING ERRCODE = '23505';
            END IF;
            v_delete_authorized := array_append(v_delete_authorized, v_p);
        ELSE
            v_retained_shared := array_append(v_retained_shared, v_p);
        END IF;
    END LOOP;

    IF cardinality(v_delete_authorized) = 0 THEN
        INSERT INTO public.storage_cleanup_operations (
            cleanup_id, idempotency_key, scope, attempt_no, incident_id,
            lease_owner, expires_at, status, retained_shared_paths, completed_at
        ) VALUES (
            p_cleanup_id, p_idempotency_key, p_scope, v_key_record.attempt_no, p_incident_id,
            p_lease_owner, v_new_expires, 'NO_OP', v_retained_shared, now()
        );

        UPDATE public.api_idempotency_keys
           SET status = 'FAILED_CLEANED', lease_owner = NULL, expires_at = NULL
         WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to transition key to FAILED_CLEANED' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object(
            'cleanup_id', p_cleanup_id,
            'status', 'NO_STORAGE_DELETE_REQUIRED',
            'delete_authorized_paths', v_delete_authorized,
            'retained_shared_paths', v_retained_shared,
            'idempotent_replay', false
        );
    END IF;

    INSERT INTO public.storage_cleanup_operations (
        cleanup_id, idempotency_key, scope, attempt_no, incident_id,
        lease_owner, expires_at, status, retained_shared_paths
    ) VALUES (
        p_cleanup_id, p_idempotency_key, p_scope, v_key_record.attempt_no, p_incident_id,
        p_lease_owner, v_new_expires, 'PENDING', v_retained_shared
    );

    INSERT INTO public.storage_cleanup_operation_objects (cleanup_id, object_path, outcome_status)
    SELECT p_cleanup_id, p, 'PENDING' FROM unnest(v_delete_authorized) AS p;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_delete_authorized) THEN
        RAISE EXCEPTION 'Failed to insert all authorized cleanup operation objects' USING ERRCODE = '23505';
    END IF;

    UPDATE public.api_idempotency_keys
       SET status = 'CLEANUP_PENDING', lease_owner = p_lease_owner, expires_at = v_new_expires
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to transition key to CLEANUP_PENDING' USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object(
        'cleanup_id', p_cleanup_id,
        'status', 'CLEANUP_AUTHORIZED',
        'delete_authorized_paths', v_delete_authorized,
        'retained_shared_paths', v_retained_shared,
        'idempotent_replay', false
    );
END;
$function$;

-- =====================================================================
-- 8. RPC 5: confirm_storage_cleanup_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.confirm_storage_cleanup_rpc(
    p_cleanup_id VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_lease_owner VARCHAR(64),
    p_confirmed_paths TEXT[]
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_sorted_confirmed TEXT[];
    v_authorized_paths TEXT[];
    v_pending_to_confirm TEXT[];
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_op_record public.storage_cleanup_operations%ROWTYPE;
    v_found_count INT;
    v_invalid_count INT;
    v_updated_count INT;
    v_remaining_count INT;
    v_uncertain_remaining_count INT;
    v_next_op_status VARCHAR(24);
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^(req|rec)_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid cleanup or recovery lease_owner format' USING ERRCODE = '22023';
    END IF;

    IF p_confirmed_paths IS NULL OR cardinality(p_confirmed_paths) = 0 THEN
        RAISE EXCEPTION 'Confirmed paths cannot be empty' USING ERRCODE = '22023';
    END IF;

    SELECT ARRAY(SELECT DISTINCT p FROM unnest(p_confirmed_paths) AS p ORDER BY 1) INTO v_sorted_confirmed;
    IF cardinality(v_sorted_confirmed) <> cardinality(p_confirmed_paths) THEN
        RAISE EXCEPTION 'Duplicate confirmed paths are not permitted' USING ERRCODE = '22023';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2A: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;

    -- Level 2B: Lock Cleanup Operation
    SELECT * INTO v_op_record
      FROM public.storage_cleanup_operations
     WHERE cleanup_id = p_cleanup_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Cleanup operation % not found', p_cleanup_id USING ERRCODE = '22023';
    END IF;

    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.idempotency_key IS DISTINCT FROM p_idempotency_key
       OR v_op_record.scope IS DISTINCT FROM p_scope
       OR v_op_record.attempt_no IS DISTINCT FROM v_key_record.attempt_no THEN
        RAISE EXCEPTION 'Cleanup operation identity or attempt_no mismatch' USING ERRCODE = '42501';
    END IF;

    SELECT array_agg(object_path ORDER BY object_path ASC) INTO v_authorized_paths
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id;

    IF v_authorized_paths IS NULL OR NOT (v_authorized_paths @> v_sorted_confirmed) THEN
        RAISE EXCEPTION 'Confirmed paths include objects not authorized by this cleanup operation' USING ERRCODE = '42501';
    END IF;

    IF v_op_record.status = 'CONFIRMED' THEN
        IF v_op_record.lease_owner IS DISTINCT FROM p_lease_owner THEN
            RAISE EXCEPTION 'Cleanup confirmation replay denied: lease owner mismatch' USING ERRCODE = '42501';
        END IF;
        RETURN jsonb_build_object('status', 'CLEANUP_ALREADY_CONFIRMED', 'remaining_count', 0);
    END IF;

    IF v_op_record.status NOT IN ('PENDING', 'PARTIAL', 'UNCERTAIN')
       OR v_op_record.lease_owner IS NULL
       OR v_op_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_op_record.expires_at IS NULL
       OR v_op_record.expires_at <= now()
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now()
       OR v_key_record.status <> 'CLEANUP_PENDING' THEN
        RAISE EXCEPTION 'Cleanup confirmation denied: stale, expired, or invalid cleanup lease' USING ERRCODE = '42501';
    END IF;

    SELECT COALESCE(array_agg(object_path ORDER BY object_path ASC), ARRAY[]::TEXT[])
      INTO v_pending_to_confirm
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id
       AND object_path = ANY(v_sorted_confirmed)
       AND outcome_status IN ('PENDING', 'UNCERTAIN');

    IF cardinality(v_pending_to_confirm) > 0 THEN
        -- Level 3: Lock Registry Rows Alphabetically
        PERFORM 1
           FROM public.storage_object_registry
          WHERE object_path = ANY(v_pending_to_confirm)
          ORDER BY object_path ASC
            FOR UPDATE;

        SELECT count(*),
               count(*) FILTER (WHERE
                   incident_id IS DISTINCT FROM p_incident_id
                   OR status NOT IN ('CLEANUP_PENDING', 'UNCERTAIN')
                   OR active_claim_count <> 0
                   OR claimed_by_lease IS DISTINCT FROM p_lease_owner
               )
          INTO v_found_count, v_invalid_count
          FROM public.storage_object_registry
         WHERE object_path = ANY(v_pending_to_confirm);

        IF v_found_count <> cardinality(v_pending_to_confirm) OR v_invalid_count > 0 THEN
            RAISE EXCEPTION 'One or more objects are missing or ineligible for deletion confirmation' USING ERRCODE = '23505';
        END IF;

        UPDATE public.storage_object_registry
           SET status = 'DELETED',
               claimed_by_lease = NULL,
               verified_by_lease = NULL,
               verified_sha256 = NULL,
               verified_mime = NULL,
               last_verified_at = NULL,
               updated_at = now()
         WHERE object_path = ANY(v_pending_to_confirm)
           AND status IN ('CLEANUP_PENDING', 'UNCERTAIN')
           AND active_claim_count = 0
           AND claimed_by_lease = p_lease_owner;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> cardinality(v_pending_to_confirm) THEN
            RAISE EXCEPTION 'Registry update row count mismatch during confirmation' USING ERRCODE = '23505';
        END IF;

        UPDATE public.storage_cleanup_operation_objects
           SET outcome_status = 'DELETED', error_detail = NULL, updated_at = now()
         WHERE cleanup_id = p_cleanup_id
           AND object_path = ANY(v_pending_to_confirm)
           AND outcome_status IN ('PENDING', 'UNCERTAIN');
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> cardinality(v_pending_to_confirm) THEN
            RAISE EXCEPTION 'Cleanup operation objects row count mismatch during confirmation' USING ERRCODE = '23505';
        END IF;
    END IF;

    SELECT count(*) FILTER (WHERE outcome_status <> 'DELETED'),
           count(*) FILTER (WHERE outcome_status = 'UNCERTAIN')
      INTO v_remaining_count, v_uncertain_remaining_count
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id;

    IF v_remaining_count = 0 THEN
        UPDATE public.storage_cleanup_operations
           SET status = 'CONFIRMED', completed_at = now()
         WHERE cleanup_id = p_cleanup_id;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to mark cleanup operation CONFIRMED' USING ERRCODE = '23505';
        END IF;

        UPDATE public.api_idempotency_keys
           SET status = 'FAILED_CLEANED', lease_owner = NULL, expires_at = NULL
         WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to mark idempotency key FAILED_CLEANED' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object('status', 'CLEANUP_CONFIRMED', 'remaining_count', 0);
    ELSE
        v_next_op_status := CASE WHEN v_uncertain_remaining_count > 0 THEN 'UNCERTAIN' ELSE 'PARTIAL' END;

        UPDATE public.storage_cleanup_operations
           SET status = v_next_op_status
         WHERE cleanup_id = p_cleanup_id;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to update partial cleanup operation status' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object(
            'status', 'CLEANUP_PARTIAL_CONFIRMED',
            'operation_status', v_next_op_status,
            'remaining_count', v_remaining_count
        );
    END IF;
END;
$function$;

-- =====================================================================
-- 9. RPC 6: record_storage_cleanup_uncertain_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.record_storage_cleanup_uncertain_rpc(
    p_cleanup_id VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_lease_owner VARCHAR(64),
    p_uncertain_paths TEXT[],
    p_error_detail TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_sorted_uncertain TEXT[];
    v_authorized_paths TEXT[];
    v_already_deleted_count INT;
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_op_record public.storage_cleanup_operations%ROWTYPE;
    v_found_count INT;
    v_invalid_count INT;
    v_updated_count INT;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_owner IS NULL OR NOT (p_lease_owner ~ '^(req|rec)_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid cleanup or recovery lease_owner format' USING ERRCODE = '22023';
    END IF;

    IF p_uncertain_paths IS NULL OR cardinality(p_uncertain_paths) = 0 THEN
        RAISE EXCEPTION 'Uncertain paths cannot be empty' USING ERRCODE = '22023';
    END IF;

    SELECT ARRAY(SELECT DISTINCT p FROM unnest(p_uncertain_paths) AS p ORDER BY 1) INTO v_sorted_uncertain;
    IF cardinality(v_sorted_uncertain) <> cardinality(p_uncertain_paths) THEN
        RAISE EXCEPTION 'Duplicate uncertain paths are not permitted' USING ERRCODE = '22023';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2A: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;

    -- Level 2B: Lock Cleanup Operation
    SELECT * INTO v_op_record
      FROM public.storage_cleanup_operations
     WHERE cleanup_id = p_cleanup_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Cleanup operation % not found', p_cleanup_id USING ERRCODE = '22023';
    END IF;

    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.idempotency_key IS DISTINCT FROM p_idempotency_key
       OR v_op_record.scope IS DISTINCT FROM p_scope
       OR v_op_record.attempt_no IS DISTINCT FROM v_key_record.attempt_no
       OR v_op_record.status NOT IN ('PENDING', 'PARTIAL', 'UNCERTAIN')
       OR v_op_record.lease_owner IS NULL
       OR v_op_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_op_record.expires_at IS NULL
       OR v_op_record.expires_at <= now()
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now()
       OR v_key_record.status <> 'CLEANUP_PENDING' THEN
        RAISE EXCEPTION 'Unauthorized, stale, or expired cleanup uncertainty report' USING ERRCODE = '42501';
    END IF;

    SELECT array_agg(object_path ORDER BY object_path ASC) INTO v_authorized_paths
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id;

    IF v_authorized_paths IS NULL OR NOT (v_authorized_paths @> v_sorted_uncertain) THEN
        RAISE EXCEPTION 'Submitted paths include objects not authorized by this cleanup operation' USING ERRCODE = '42501';
    END IF;

    SELECT count(*) INTO v_already_deleted_count
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id
       AND object_path = ANY(v_sorted_uncertain)
       AND outcome_status = 'DELETED';

    IF v_already_deleted_count > 0 THEN
        RAISE EXCEPTION 'Cannot downgrade confirmed DELETED object to UNCERTAIN' USING ERRCODE = '23505';
    END IF;

    -- Level 3: Lock Uncertain Objects Alphabetically
    PERFORM 1
       FROM public.storage_object_registry
      WHERE object_path = ANY(v_sorted_uncertain)
      ORDER BY object_path ASC
        FOR UPDATE;

    SELECT count(*),
           count(*) FILTER (WHERE
               incident_id IS DISTINCT FROM p_incident_id
               OR status NOT IN ('CLEANUP_PENDING', 'UNCERTAIN')
               OR active_claim_count <> 0
               OR claimed_by_lease IS DISTINCT FROM p_lease_owner
           )
      INTO v_found_count, v_invalid_count
      FROM public.storage_object_registry
     WHERE object_path = ANY(v_sorted_uncertain);

    IF v_found_count <> cardinality(v_sorted_uncertain) OR v_invalid_count > 0 THEN
        RAISE EXCEPTION 'Cannot mark missing, non-CLEANUP_PENDING, or claimed object UNCERTAIN' USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_object_registry
       SET status = 'UNCERTAIN', updated_at = now()
     WHERE object_path = ANY(v_sorted_uncertain)
       AND status IN ('CLEANUP_PENDING', 'UNCERTAIN')
       AND active_claim_count = 0
       AND claimed_by_lease = p_lease_owner;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_sorted_uncertain) THEN
        RAISE EXCEPTION 'Registry update row count mismatch during uncertainty recording' USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_cleanup_operation_objects
       SET outcome_status = 'UNCERTAIN',
           error_detail = left(COALESCE(p_error_detail, 'timeout'), 500),
           updated_at = now()
     WHERE cleanup_id = p_cleanup_id
       AND object_path = ANY(v_sorted_uncertain)
       AND outcome_status IN ('PENDING', 'UNCERTAIN');
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> cardinality(v_sorted_uncertain) THEN
        RAISE EXCEPTION 'Cleanup operation objects row count mismatch during uncertainty recording' USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_cleanup_operations
       SET status = 'UNCERTAIN',
           error_detail = left(COALESCE(p_error_detail, 'timeout'), 500)
     WHERE cleanup_id = p_cleanup_id;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update cleanup operation status to UNCERTAIN' USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object('status', 'UNCERTAIN_RECORDED', 'uncertain_paths', v_sorted_uncertain);
END;
$function$;

-- =====================================================================
-- 10. RPC 7: claim_expired_cleanup_operation_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.claim_expired_cleanup_operation_rpc(
    p_cleanup_id VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_recovery_actor_id VARCHAR(128),
    p_recovery_actor_role VARCHAR(64),
    p_recovery_lease_owner VARCHAR(64),
    p_lease_sec INT DEFAULT 60
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_op_record public.storage_cleanup_operations%ROWTYPE;
    v_remaining_paths TEXT[];
    v_old_lease VARCHAR(64);
    v_found_count INT;
    v_invalid_count INT;
    v_updated_count INT;
    v_new_expires TIMESTAMPTZ;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_sec IS NULL OR p_lease_sec < 15 OR p_lease_sec > 300 THEN
        RAISE EXCEPTION 'Invalid p_lease_sec (%): must be between 15 and 300 seconds', p_lease_sec
            USING ERRCODE = '22023';
    END IF;
    v_new_expires := now() + make_interval(secs => p_lease_sec);

    IF p_recovery_actor_role IS NULL OR p_recovery_actor_role NOT IN ('system', 'admin') THEN
        RAISE EXCEPTION 'Recovery operation denied: requires system or admin recovery role' USING ERRCODE = '42501';
    END IF;
    IF p_recovery_actor_id IS NULL OR NOT (p_recovery_actor_id ~ '^[A-Za-z0-9_@.-]{1,128}$') THEN
        RAISE EXCEPTION 'Invalid recovery_actor_id format' USING ERRCODE = '22023';
    END IF;
    IF p_recovery_lease_owner IS NULL OR NOT (p_recovery_lease_owner ~ '^rec_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid recovery lease token: must match ^rec_lease_[a-f0-9]{32}$' USING ERRCODE = '22023';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2A: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;

    -- Level 2B: Lock Cleanup Operation
    SELECT * INTO v_op_record
      FROM public.storage_cleanup_operations
     WHERE cleanup_id = p_cleanup_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Cleanup operation % not found', p_cleanup_id USING ERRCODE = '22023';
    END IF;

    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.idempotency_key IS DISTINCT FROM p_idempotency_key
       OR v_op_record.scope IS DISTINCT FROM p_scope
       OR v_op_record.attempt_no IS DISTINCT FROM v_key_record.attempt_no THEN
        RAISE EXCEPTION 'Cleanup operation identity or attempt_no mismatch' USING ERRCODE = '42501';
    END IF;

    IF v_op_record.status IN ('CONFIRMED', 'NO_OP') THEN
        RETURN jsonb_build_object('status', 'CLEANUP_ALREADY_CONFIRMED', 'remaining_paths', ARRAY[]::TEXT[]);
    END IF;

    IF v_key_record.status <> 'CLEANUP_PENDING' THEN
        RAISE EXCEPTION 'Idempotency key is not in CLEANUP_PENDING state' USING ERRCODE = '23505';
    END IF;

    SELECT COALESCE(array_agg(object_path ORDER BY object_path ASC), ARRAY[]::TEXT[])
      INTO v_remaining_paths
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id
       AND outcome_status IN ('PENDING', 'UNCERTAIN');

    IF cardinality(v_remaining_paths) = 0 THEN
        RAISE EXCEPTION 'No remaining pending or uncertain objects in cleanup operation' USING ERRCODE = '23505';
    END IF;

    -- Same-owner active recovery lease retry (lost HTTP response) or pre-expiry lease renewal
    IF v_op_record.lease_owner = p_recovery_lease_owner
       AND v_key_record.lease_owner = p_recovery_lease_owner
       AND v_op_record.expires_at IS NOT NULL
       AND v_key_record.expires_at IS NOT NULL
       AND v_op_record.expires_at > now()
       AND v_key_record.expires_at > now() THEN

        PERFORM 1
           FROM public.storage_object_registry
          WHERE object_path = ANY(v_remaining_paths)
          ORDER BY object_path ASC
            FOR UPDATE;

        SELECT count(*),
               count(*) FILTER (WHERE
                   incident_id IS DISTINCT FROM p_incident_id
                   OR status NOT IN ('CLEANUP_PENDING', 'UNCERTAIN')
                   OR active_claim_count <> 0
                   OR claimed_by_lease IS DISTINCT FROM p_recovery_lease_owner
               )
          INTO v_found_count, v_invalid_count
          FROM public.storage_object_registry
         WHERE object_path = ANY(v_remaining_paths);

        IF v_found_count <> cardinality(v_remaining_paths) OR v_invalid_count > 0 THEN
            RAISE EXCEPTION 'One or more remaining registry objects failed validation during recovery renewal'
                USING ERRCODE = '23505';
        END IF;

        UPDATE public.storage_cleanup_operations
           SET expires_at = v_new_expires,
               recovery_actor_id = p_recovery_actor_id
         WHERE cleanup_id = p_cleanup_id;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to renew cleanup operation lease' USING ERRCODE = '23505';
        END IF;

        UPDATE public.api_idempotency_keys
           SET expires_at = v_new_expires
         WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to renew idempotency key cleanup lease' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object(
            'status', 'CLEANUP_RECOVERY_CLAIMED',
            'cleanup_id', p_cleanup_id,
            'superseded_lease', p_recovery_lease_owner,
            'remaining_paths', v_remaining_paths,
            'idempotent_replay', true
        );
    END IF;

    -- Expired lease takeover by a distinct recovery lease owner
    IF v_op_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS NULL
       OR v_op_record.lease_owner IS DISTINCT FROM v_key_record.lease_owner
       OR p_recovery_lease_owner = v_op_record.lease_owner
       OR v_op_record.expires_at IS NULL
       OR v_key_record.expires_at IS NULL
       OR v_op_record.expires_at > now()
       OR v_key_record.expires_at > now() THEN
        RAISE EXCEPTION 'Cannot claim cleanup operation: current lease has not expired or recovery lease is not distinct'
            USING ERRCODE = '42501';
    END IF;

    v_old_lease := v_op_record.lease_owner;

    -- Level 3: Lock Remaining Objects Alphabetically
    PERFORM 1
       FROM public.storage_object_registry
      WHERE object_path = ANY(v_remaining_paths)
      ORDER BY object_path ASC
        FOR UPDATE;

    SELECT count(*),
           count(*) FILTER (WHERE
               incident_id IS DISTINCT FROM p_incident_id
               OR status NOT IN ('CLEANUP_PENDING', 'UNCERTAIN')
               OR active_claim_count <> 0
               OR claimed_by_lease IS DISTINCT FROM v_old_lease
           )
      INTO v_found_count, v_invalid_count
      FROM public.storage_object_registry
     WHERE object_path = ANY(v_remaining_paths);

    IF v_found_count <> cardinality(v_remaining_paths) OR v_invalid_count > 0 THEN
        RAISE EXCEPTION 'One or more remaining registry objects failed validation during recovery takeover'
            USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_object_registry
       SET claimed_by_lease = p_recovery_lease_owner, updated_at = now()
     WHERE object_path = ANY(v_remaining_paths)
       AND status IN ('CLEANUP_PENDING', 'UNCERTAIN')
       AND active_claim_count = 0
       AND claimed_by_lease = v_old_lease;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;

    IF v_updated_count <> cardinality(v_remaining_paths) THEN
        RAISE EXCEPTION 'Incomplete registry claim transfer during recovery takeover (expected %, updated %)',
            cardinality(v_remaining_paths), v_updated_count
            USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_cleanup_operations
       SET lease_owner = p_recovery_lease_owner,
           expires_at = v_new_expires,
           recovery_actor_id = p_recovery_actor_id,
           recovery_claimed_at = now(),
           recovery_count = recovery_count + 1
     WHERE cleanup_id = p_cleanup_id;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update cleanup operation lease during recovery takeover' USING ERRCODE = '23505';
    END IF;

    UPDATE public.api_idempotency_keys
       SET lease_owner = p_recovery_lease_owner,
           expires_at = v_new_expires
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update idempotency key lease during recovery takeover' USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object(
        'status', 'CLEANUP_RECOVERY_CLAIMED',
        'cleanup_id', p_cleanup_id,
        'superseded_lease', v_old_lease,
        'remaining_paths', v_remaining_paths,
        'idempotent_replay', false
    );
END;
$function$;

-- =====================================================================
-- 11. RPC 8: reconcile_storage_orphan_rpc
-- =====================================================================
CREATE OR REPLACE FUNCTION public.reconcile_storage_orphan_rpc(
    p_cleanup_id VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_object_path TEXT,
    p_recovery_actor_id VARCHAR(128),
    p_recovery_actor_role VARCHAR(64),
    p_recovery_lease_owner VARCHAR(64)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_op_record public.storage_cleanup_operations%ROWTYPE;
    v_obj_record public.storage_object_registry%ROWTYPE;
    v_item_outcome VARCHAR(24);
    v_updated_count INT;
    v_remaining_count INT;
    v_uncertain_remaining_count INT;
    v_next_op_status VARCHAR(24);
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_recovery_actor_role IS NULL OR p_recovery_actor_role NOT IN ('system', 'admin') THEN
        RAISE EXCEPTION 'Orphan reconciliation denied: requires system or admin recovery role' USING ERRCODE = '42501';
    END IF;
    IF p_recovery_actor_id IS NULL OR NOT (p_recovery_actor_id ~ '^[A-Za-z0-9_@.-]{1,128}$') THEN
        RAISE EXCEPTION 'Invalid recovery_actor_id format' USING ERRCODE = '22023';
    END IF;
    IF p_recovery_lease_owner IS NULL OR NOT (p_recovery_lease_owner ~ '^rec_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid recovery lease token: must match ^rec_lease_[a-f0-9]{32}$' USING ERRCODE = '22023';
    END IF;

    IF p_object_path IS NULL
       OR NOT (p_object_path ~ '^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}\.(jpg|png|webp)$')
       OR split_part(p_object_path, '/', 1) IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Canonical object path % does not match incident %', p_object_path, p_incident_id
            USING ERRCODE = '42501';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2A: Lock Idempotency Key
    SELECT * INTO v_key_record
      FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;

    -- Level 2B: Lock Cleanup Operation
    SELECT * INTO v_op_record
      FROM public.storage_cleanup_operations
     WHERE cleanup_id = p_cleanup_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Cleanup operation % not found', p_cleanup_id USING ERRCODE = '22023';
    END IF;

    IF v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_op_record.idempotency_key IS DISTINCT FROM p_idempotency_key
       OR v_op_record.scope IS DISTINCT FROM p_scope
       OR v_op_record.attempt_no IS DISTINCT FROM v_key_record.attempt_no THEN
        RAISE EXCEPTION 'Cleanup operation identity or attempt_no mismatch' USING ERRCODE = '42501';
    END IF;

    SELECT outcome_status INTO v_item_outcome
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id
       AND object_path = p_object_path;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object % is not authorized by cleanup operation %', p_object_path, p_cleanup_id
            USING ERRCODE = '42501';
    END IF;

    -- Safe idempotent replay if this object outcome was already reconciled to DELETED by this recovery lease
    IF v_item_outcome = 'DELETED' THEN
        IF v_op_record.lease_owner IS DISTINCT FROM p_recovery_lease_owner THEN
            RAISE EXCEPTION 'Orphan reconciliation replay denied: lease owner mismatch' USING ERRCODE = '42501';
        END IF;

        IF v_op_record.status = 'CONFIRMED' THEN
            RETURN jsonb_build_object(
                'status', 'RECONCILED_DELETED_OP_CONFIRMED',
                'object_path', p_object_path,
                'remaining_count', 0,
                'idempotent_replay', true
            );
        END IF;

        IF v_op_record.status NOT IN ('PENDING', 'PARTIAL', 'UNCERTAIN')
           OR v_op_record.expires_at IS NULL
           OR v_op_record.expires_at <= now()
           OR v_key_record.lease_owner IS DISTINCT FROM p_recovery_lease_owner
           OR v_key_record.expires_at IS NULL
           OR v_key_record.expires_at <= now()
           OR v_key_record.status <> 'CLEANUP_PENDING' THEN
            RAISE EXCEPTION 'Orphan reconciliation replay denied: recovery lease expired or invalid state'
                USING ERRCODE = '42501';
        END IF;

        SELECT count(*) FILTER (WHERE outcome_status <> 'DELETED')
          INTO v_remaining_count
          FROM public.storage_cleanup_operation_objects
         WHERE cleanup_id = p_cleanup_id;

        RETURN jsonb_build_object(
            'status', 'RECONCILED_DELETED_OP_PARTIAL',
            'object_path', p_object_path,
            'remaining_count', v_remaining_count,
            'idempotent_replay', true
        );
    END IF;

    IF v_op_record.status NOT IN ('PENDING', 'PARTIAL', 'UNCERTAIN')
       OR v_op_record.lease_owner IS NULL
       OR v_op_record.lease_owner IS DISTINCT FROM p_recovery_lease_owner
       OR v_op_record.expires_at IS NULL
       OR v_op_record.expires_at <= now()
       OR v_key_record.lease_owner IS NULL
       OR v_key_record.lease_owner IS DISTINCT FROM p_recovery_lease_owner
       OR v_key_record.expires_at IS NULL
       OR v_key_record.expires_at <= now()
       OR v_key_record.status <> 'CLEANUP_PENDING' THEN
        RAISE EXCEPTION 'Orphan reconciliation denied: active recovery lease required' USING ERRCODE = '42501';
    END IF;

    -- Level 3: Lock Object Registry Row
    SELECT * INTO v_obj_record
      FROM public.storage_object_registry
     WHERE object_path = p_object_path
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Object % not found in registry', p_object_path USING ERRCODE = '22023';
    END IF;

    IF v_obj_record.incident_id IS DISTINCT FROM p_incident_id THEN
        RAISE EXCEPTION 'Cross-incident object path violation' USING ERRCODE = '42501';
    END IF;

    IF v_obj_record.status = 'ATTACHED'
       OR EXISTS (SELECT 1 FROM public.incidents WHERE photos @> ARRAY[p_object_path]) THEN
        RAISE EXCEPTION 'Cannot reconcile an ATTACHED object' USING ERRCODE = '23505';
    END IF;

    IF v_obj_record.status <> 'UNCERTAIN'
       OR v_obj_record.active_claim_count <> 0
       OR v_obj_record.claimed_by_lease IS DISTINCT FROM p_recovery_lease_owner THEN
        RAISE EXCEPTION 'Object % is not in an owned UNCERTAIN state (status: %, claims: %)',
            p_object_path, v_obj_record.status, v_obj_record.active_claim_count
            USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_object_registry
       SET status = 'DELETED',
           claimed_by_lease = NULL,
           verified_by_lease = NULL,
           verified_sha256 = NULL,
           verified_mime = NULL,
           last_verified_at = NULL,
           updated_at = now()
     WHERE object_path = p_object_path
       AND status = 'UNCERTAIN'
       AND active_claim_count = 0
       AND claimed_by_lease = p_recovery_lease_owner;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to reconcile object % to DELETED', p_object_path USING ERRCODE = '23505';
    END IF;

    UPDATE public.storage_cleanup_operation_objects
       SET outcome_status = 'DELETED',
           error_detail = NULL,
           updated_at = now()
     WHERE cleanup_id = p_cleanup_id
       AND object_path = p_object_path
       AND outcome_status = 'UNCERTAIN';
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update cleanup operation object outcome for %', p_object_path USING ERRCODE = '23505';
    END IF;

    SELECT count(*) FILTER (WHERE outcome_status <> 'DELETED'),
           count(*) FILTER (WHERE outcome_status = 'UNCERTAIN')
      INTO v_remaining_count, v_uncertain_remaining_count
      FROM public.storage_cleanup_operation_objects
     WHERE cleanup_id = p_cleanup_id;

    IF v_remaining_count = 0 THEN
        UPDATE public.storage_cleanup_operations
           SET status = 'CONFIRMED', completed_at = now()
         WHERE cleanup_id = p_cleanup_id;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to mark cleanup operation CONFIRMED' USING ERRCODE = '23505';
        END IF;

        UPDATE public.api_idempotency_keys
           SET status = 'FAILED_CLEANED', lease_owner = NULL, expires_at = NULL
         WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to mark idempotency key FAILED_CLEANED' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object(
            'status', 'RECONCILED_DELETED_OP_CONFIRMED',
            'object_path', p_object_path,
            'remaining_count', 0,
            'idempotent_replay', false
        );
    ELSE
        v_next_op_status := CASE WHEN v_uncertain_remaining_count > 0 THEN 'UNCERTAIN' ELSE 'PARTIAL' END;
        UPDATE public.storage_cleanup_operations
           SET status = v_next_op_status
         WHERE cleanup_id = p_cleanup_id;
        GET DIAGNOSTICS v_updated_count = ROW_COUNT;
        IF v_updated_count <> 1 THEN
            RAISE EXCEPTION 'Failed to update cleanup operation status' USING ERRCODE = '23505';
        END IF;

        RETURN jsonb_build_object(
            'status', 'RECONCILED_DELETED_OP_PARTIAL',
            'object_path', p_object_path,
            'remaining_count', v_remaining_count,
            'idempotent_replay', false
        );
    END IF;
END;
$function$;

-- =====================================================================
-- 12. RPC 9: renew_or_takeover_lease_rpc (Upload Reservation Lease)
-- =====================================================================
CREATE OR REPLACE FUNCTION public.renew_or_takeover_lease_rpc(
    p_idempotency_key VARCHAR(64),
    p_scope VARCHAR(64),
    p_incident_id VARCHAR(32),
    p_actor_id VARCHAR(128),
    p_request_fingerprint VARCHAR(64),
    p_incoming_lease_owner VARCHAR(64),
    p_lease_sec INT DEFAULT 60
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_key_record public.api_idempotency_keys%ROWTYPE;
    v_mapped_paths TEXT[];
    v_old_lease VARCHAR(64);
    v_found_count INT;
    v_updated_count INT;
    v_new_expires TIMESTAMPTZ;
    v_caller_role TEXT;
BEGIN
    v_caller_role := COALESCE(NULLIF(current_setting('request.jwt.claim.role', true), ''), current_user);
    IF v_caller_role <> 'service_role' THEN
        RAISE EXCEPTION 'Access denied: service_role required' USING ERRCODE = '42501';
    END IF;

    IF p_lease_sec IS NULL OR p_lease_sec < 15 OR p_lease_sec > 300 THEN
        RAISE EXCEPTION 'Invalid p_lease_sec (%): must be between 15 and 300 seconds', p_lease_sec
            USING ERRCODE = '22023';
    END IF;
    v_new_expires := now() + make_interval(secs => p_lease_sec);

    IF p_incoming_lease_owner IS NULL OR NOT (p_incoming_lease_owner ~ '^req_lease_[a-f0-9]{32}$') THEN
        RAISE EXCEPTION 'Invalid request lease_owner format' USING ERRCODE = '22023';
    END IF;

    -- Level 1: Lock Incident
    PERFORM 1 FROM public.incidents WHERE id = p_incident_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '22023';
    END IF;

    -- Level 2: Lock Idempotency Key
    SELECT * INTO v_key_record FROM public.api_idempotency_keys
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Idempotency key not found' USING ERRCODE = '22023';
    END IF;

    IF v_key_record.actor_id IS DISTINCT FROM p_actor_id
       OR v_key_record.incident_id IS DISTINCT FROM p_incident_id
       OR v_key_record.request_fingerprint IS DISTINCT FROM p_request_fingerprint THEN
        RAISE EXCEPTION 'Idempotency identity or fingerprint mismatch' USING ERRCODE = '23505';
    END IF;
    IF v_key_record.status IN ('COMPLETED', 'CLEANUP_PENDING') THEN
        RAISE EXCEPTION 'Lease cannot be renewed or taken over in state %', v_key_record.status USING ERRCODE = '23505';
    END IF;

    IF v_key_record.status = 'IN_PROGRESS' AND v_key_record.expires_at > now() THEN
        IF v_key_record.lease_owner = p_incoming_lease_owner THEN
            UPDATE public.api_idempotency_keys
               SET expires_at = v_new_expires
             WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
            GET DIAGNOSTICS v_updated_count = ROW_COUNT;
            IF v_updated_count <> 1 THEN
                RAISE EXCEPTION 'Failed to renew active reservation lease' USING ERRCODE = '23505';
            END IF;
            RETURN jsonb_build_object('status', 'RENEWED');
        ELSE
            RETURN jsonb_build_object('status', 'ACTIVE_LOCK', 'expires_at', v_key_record.expires_at);
        END IF;
    END IF;

    IF v_key_record.lease_owner = p_incoming_lease_owner THEN
        RAISE EXCEPTION 'Expired lease takeover requires a new distinct lease_owner token' USING ERRCODE = '42501';
    END IF;

    SELECT array_agg(object_path ORDER BY object_path ASC) INTO v_mapped_paths
      FROM public.api_idempotency_objects
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope AND claim_state = 'ACTIVE';

    v_old_lease := v_key_record.lease_owner;

    IF v_mapped_paths IS NOT NULL THEN
        -- Level 3: Lock mapped objects alphabetically & verify they are still REGISTERED
        PERFORM 1 FROM public.storage_object_registry
         WHERE object_path = ANY(v_mapped_paths) ORDER BY object_path ASC FOR UPDATE;

        SELECT count(*) INTO v_found_count
          FROM public.storage_object_registry
         WHERE object_path = ANY(v_mapped_paths)
           AND status = 'REGISTERED'
           AND active_claim_count >= 1;
        IF v_found_count <> cardinality(v_mapped_paths) THEN
            RAISE EXCEPTION 'Mapped registry objects missing or not REGISTERED during takeover' USING ERRCODE = '23505';
        END IF;

        -- Reset per-claim verification metadata on all active claims associated with this reservation on takeover
        UPDATE public.api_idempotency_objects
           SET verified_by_lease = NULL,
               verified_sha256 = NULL,
               verified_mime = NULL,
               verified_at = NULL,
               updated_at = now()
         WHERE idempotency_key = p_idempotency_key
           AND scope = p_scope
           AND claim_state = 'ACTIVE';
    END IF;

    UPDATE public.api_idempotency_keys
       SET status = 'IN_PROGRESS',
           lease_owner = p_incoming_lease_owner,
           expires_at = v_new_expires
     WHERE idempotency_key = p_idempotency_key AND scope = p_scope;
    GET DIAGNOSTICS v_updated_count = ROW_COUNT;
    IF v_updated_count <> 1 THEN
        RAISE EXCEPTION 'Failed to update idempotency key lease during takeover' USING ERRCODE = '23505';
    END IF;

    RETURN jsonb_build_object('status', 'TAKEOVER_GRANTED', 'superseded_lease', v_old_lease);
END;
$function$;

-- =====================================================================
-- 13. RPC Execution Grants
-- =====================================================================
REVOKE ALL ON FUNCTION public.reserve_photo_attachment_rpc(
    VARCHAR(64), VARCHAR(64), VARCHAR(128), VARCHAR(32), VARCHAR(64), TEXT[], VARCHAR(64), INT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reserve_photo_attachment_rpc(
    VARCHAR(64), VARCHAR(64), VARCHAR(128), VARCHAR(32), VARCHAR(64), TEXT[], VARCHAR(64), INT
) TO service_role;

REVOKE ALL ON FUNCTION public.verify_and_register_storage_object_rpc(
    VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT, CHAR(64), VARCHAR(32)
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verify_and_register_storage_object_rpc(
    VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT, CHAR(64), VARCHAR(32)
) TO service_role;

REVOKE ALL ON FUNCTION public.finalize_photo_attachment_rpc(
    VARCHAR(32), TEXT[], VARCHAR(32), VARCHAR(128), VARCHAR(64), VARCHAR(64), VARCHAR(64), VARCHAR(64), VARCHAR(64)
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.finalize_photo_attachment_rpc(
    VARCHAR(32), TEXT[], VARCHAR(32), VARCHAR(128), VARCHAR(64), VARCHAR(64), VARCHAR(64), VARCHAR(64), VARCHAR(64)
) TO service_role;

REVOKE ALL ON FUNCTION public.initiate_storage_cleanup_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[], INT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.initiate_storage_cleanup_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[], INT
) TO service_role;

REVOKE ALL ON FUNCTION public.confirm_storage_cleanup_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[]
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.confirm_storage_cleanup_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[]
) TO service_role;

REVOKE ALL ON FUNCTION public.record_storage_cleanup_uncertain_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[], TEXT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_storage_cleanup_uncertain_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(64), TEXT[], TEXT
) TO service_role;

REVOKE ALL ON FUNCTION public.claim_expired_cleanup_operation_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(128), VARCHAR(64), VARCHAR(64), INT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_expired_cleanup_operation_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), VARCHAR(128), VARCHAR(64), VARCHAR(64), INT
) TO service_role;

REVOKE ALL ON FUNCTION public.reconcile_storage_orphan_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(128), VARCHAR(64), VARCHAR(64)
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.reconcile_storage_orphan_rpc(
    VARCHAR(64), VARCHAR(32), VARCHAR(64), VARCHAR(64), TEXT, VARCHAR(128), VARCHAR(64), VARCHAR(64)
) TO service_role;

REVOKE ALL ON FUNCTION public.renew_or_takeover_lease_rpc(
    VARCHAR(64), VARCHAR(64), VARCHAR(32), VARCHAR(128), VARCHAR(64), VARCHAR(64), INT
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.renew_or_takeover_lease_rpc(
    VARCHAR(64), VARCHAR(64), VARCHAR(32), VARCHAR(128), VARCHAR(64), VARCHAR(64), INT
) TO service_role;

-- =====================================================================
-- 14. End-of-Migration Fail-Fast Catalog & RPC Assertions
-- =====================================================================
DO $verify_schema$
DECLARE
    v_missing_cols INT;
    v_missing_cons INT;
    v_bad_fks INT;
    v_rls_off INT;
    v_missing_trgs INT;
    v_missing_rpcs INT;
BEGIN
    SELECT count(*) INTO v_missing_cols
      FROM (VALUES
          ('storage_object_registry', 'object_path'),
          ('storage_object_registry', 'incident_id'),
          ('storage_object_registry', 'bucket'),
          ('storage_object_registry', 'status'),
          ('storage_object_registry', 'active_claim_count'),
          ('storage_object_registry', 'claimed_by_lease'),
          ('storage_object_registry', 'verified_by_lease'),
          ('storage_object_registry', 'verified_sha256'),
          ('storage_object_registry', 'verified_mime'),
          ('storage_object_registry', 'last_verified_at'),
          ('api_idempotency_keys', 'idempotency_key'),
          ('api_idempotency_keys', 'scope'),
          ('api_idempotency_keys', 'attempt_no'),
          ('api_idempotency_keys', 'lease_owner'),
          ('api_idempotency_keys', 'expires_at'),
          ('api_idempotency_objects', 'claim_state'),
          ('api_idempotency_objects', 'verified_by_lease'),
          ('api_idempotency_objects', 'verified_sha256'),
          ('api_idempotency_objects', 'verified_mime'),
          ('api_idempotency_objects', 'verified_at'),
          ('storage_cleanup_operations', 'cleanup_id'),
          ('storage_cleanup_operations', 'attempt_no'),
          ('storage_cleanup_operations', 'expires_at'),
          ('storage_cleanup_operations', 'retained_shared_paths'),
          ('storage_cleanup_operations', 'recovery_actor_id'),
          ('storage_cleanup_operations', 'recovery_count'),
          ('storage_cleanup_operation_objects', 'outcome_status')
      ) AS req(tbl, col)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_attribute a
           JOIN pg_catalog.pg_class c ON a.attrelid = c.oid
           JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
          WHERE n.nspname = 'public'
            AND c.relname = req.tbl
            AND a.attname = req.col
            AND a.attnum > 0
            AND NOT a.attisdropped
     );

    IF v_missing_cols > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: % required Milestone 2 V3.1 columns are missing', v_missing_cols
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO v_missing_cons
      FROM (VALUES
          ('storage_object_registry', 'valid_canonical_bucket'),
          ('storage_object_registry', 'valid_canonical_object_path'),
          ('storage_object_registry', 'valid_verified_digest_and_mime'),
          ('storage_object_registry', 'valid_cleanup_claim_lease_binding'),
          ('api_idempotency_objects', 'valid_claim_verification_consistency')
      ) AS req(tbl, con)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_constraint k
           JOIN pg_catalog.pg_class c ON k.conrelid = c.oid
           JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
          WHERE n.nspname = 'public'
            AND c.relname = req.tbl
            AND k.conname = req.con
     );

    IF v_missing_cons > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: % required Milestone 2 V3.1 CHECK constraints are missing', v_missing_cons
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO v_bad_fks
      FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class rel ON con.conrelid = rel.oid
      JOIN pg_catalog.pg_namespace nsp ON rel.relnamespace = nsp.oid
      JOIN pg_catalog.pg_class frel ON con.confrelid = frel.oid
     WHERE nsp.nspname = 'public'
       AND rel.relname IN (
           'storage_object_registry', 'api_idempotency_keys', 'api_idempotency_objects',
           'storage_cleanup_operations', 'storage_cleanup_operation_objects'
       )
       AND frel.relname IN ('incidents', 'storage_object_registry')
       AND con.contype = 'f'
       AND con.confdeltype <> 'r';

    IF v_bad_fks > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: % foreign keys to incidents or storage_object_registry do not enforce ON DELETE RESTRICT', v_bad_fks
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO v_rls_off
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
     WHERE n.nspname = 'public'
       AND c.relname IN (
           'storage_object_registry', 'api_idempotency_keys', 'api_idempotency_objects',
           'storage_cleanup_operations', 'storage_cleanup_operation_objects'
       )
       AND NOT c.relrowsecurity;

    IF v_rls_off > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: RLS is not enabled on % Milestone 2 tables', v_rls_off
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO v_missing_trgs
      FROM (VALUES
          ('storage_object_registry', 'trg_storage_registry_immutability'),
          ('storage_object_registry', 'trg_no_truncate_storage_registry'),
          ('api_idempotency_objects', 'trg_maintain_storage_active_claim_count')
      ) AS req(tbl, trg)
     WHERE NOT EXISTS (
         SELECT 1
           FROM pg_catalog.pg_trigger t
           JOIN pg_catalog.pg_class c ON t.tgrelid = c.oid
           JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
          WHERE n.nspname = 'public'
            AND c.relname = req.tbl
            AND t.tgname = req.trg
            AND t.tgenabled = 'O'
     );

    IF v_missing_trgs > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: % required Milestone 2 triggers are missing or disabled', v_missing_trgs
            USING ERRCODE = '55000';
    END IF;

    IF to_regprocedure('public.attach_incident_photos_rpc(character varying,text[],character varying,character varying,character varying)') IS NOT NULL THEN
        RAISE EXCEPTION 'Schema drift detected: obsolete 5-parameter attach_incident_photos_rpc still exists'
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO v_missing_rpcs
      FROM (VALUES
          ('public.reserve_photo_attachment_rpc(character varying,character varying,character varying,character varying,character varying,text[],character varying,integer)'),
          ('public.verify_and_register_storage_object_rpc(character varying,character varying,character varying,character varying,text,character,character varying)'),
          ('public.finalize_photo_attachment_rpc(character varying,text[],character varying,character varying,character varying,character varying,character varying,character varying,character varying)'),
          ('public.initiate_storage_cleanup_rpc(character varying,character varying,character varying,character varying,character varying,text[],integer)'),
          ('public.confirm_storage_cleanup_rpc(character varying,character varying,character varying,character varying,character varying,text[])'),
          ('public.record_storage_cleanup_uncertain_rpc(character varying,character varying,character varying,character varying,character varying,text[],text)'),
          ('public.claim_expired_cleanup_operation_rpc(character varying,character varying,character varying,character varying,character varying,character varying,character varying,integer)'),
          ('public.reconcile_storage_orphan_rpc(character varying,character varying,character varying,character varying,text,character varying,character varying,character varying)'),
          ('public.renew_or_takeover_lease_rpc(character varying,character varying,character varying,character varying,character varying,character varying,integer)')
      ) AS req(sig)
     WHERE to_regprocedure(req.sig) IS NULL
        OR NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_proc p
             WHERE p.oid = to_regprocedure(req.sig)
               AND p.prosecdef = TRUE
               AND has_function_privilege('service_role', p.oid, 'EXECUTE')
               AND NOT has_function_privilege('anon', p.oid, 'EXECUTE')
               AND NOT has_function_privilege('authenticated', p.oid, 'EXECUTE')
        );

    IF v_missing_rpcs > 0 THEN
        RAISE EXCEPTION 'Schema drift detected: % required Milestone 2 V3.1 RPC signatures or SECURITY DEFINER / privilege invariants are missing', v_missing_rpcs
            USING ERRCODE = '55000';
    END IF;
END;
$verify_schema$;

NOTIFY pgrst, 'reload schema';

COMMIT;
