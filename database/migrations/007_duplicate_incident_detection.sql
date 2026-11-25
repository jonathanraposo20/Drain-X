BEGIN;

-- =====================================================================
-- DRAIN-X Milestone 3 Duplicate Incident Detection & Link Management
-- Canonical Migration File:
--   database/migrations/007_duplicate_incident_detection.sql
--
-- Security & Operational Architecture:
--   1. Schema extensions:
--      - public.incidents.origin_operational_mode VARCHAR(16) NULL
--        CHECK (origin_operational_mode IS NULL OR origin_operational_mode IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD'))
--      - Seed DEMO incidents backfilled to 'SIMULATION'.
--      - Partial covering index idx_incidents_dup_time_window.
--   2. Tables:
--      - public.incident_duplicate_links: canonical undirected pairs
--        (incident_low_id COLLATE "C" < incident_high_id COLLATE "C"),
--        link_status ('SUSPECTED', 'CONFIRMED', 'DISMISSED'), optimistic review_version,
--        uq_dup_single_confirmed_primary on (duplicate_incident_id) WHERE link_status = 'CONFIRMED',
--        and ON DELETE RESTRICT foreign keys.
--      - public.incident_duplicate_scan_jobs: durable outbox table with lease binding,
--        retry/backoff state (PENDING, IN_PROGRESS, COMPLETED, FAILED_PERMANENT),
--        max_attempts = 5, and ON DELETE RESTRICT foreign key.
--   3. Least-Privilege Boundaries (matching Migrations 005 & 006):
--      - RLS enabled on both tables; zero anon/authenticated policies.
--      - Direct table privileges REVOKED from PUBLIC, anon, authenticated, and service_role.
--      - Minimal SELECT-only privilege GRANTED to service_role on incident_duplicate_links
--        (zero direct table privileges on incident_duplicate_scan_jobs).
--      - All mutations occur exclusively via SECURITY DEFINER RPCs pinned to
--        SET search_path = pg_catalog, public, pg_temp and granted solely to service_role.
--   4. RPCs:
--      - citizen_incident_creation_rpc (11-arg replacement, backward-compatible 10-arg calls)
--      - claim_duplicate_scan_jobs_rpc
--      - fetch_duplicate_candidates_rpc
--      - record_duplicate_candidates_rpc
--      - release_duplicate_scan_job_rpc
--      - reset_duplicate_scan_job_rpc
--      - review_incident_duplicate_link_rpc
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Schema extensions on public.incidents
-- ---------------------------------------------------------------------
ALTER TABLE public.incidents
    ADD COLUMN IF NOT EXISTS origin_operational_mode VARCHAR(16) NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'chk_incidents_origin_operational_mode'
    ) THEN
        ALTER TABLE public.incidents
            ADD CONSTRAINT chk_incidents_origin_operational_mode
            CHECK (origin_operational_mode IS NULL OR origin_operational_mode IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD'));
    END IF;
END $$;

UPDATE public.incidents
   SET origin_operational_mode = 'SIMULATION'
 WHERE source = 'DEMO'
   AND origin_operational_mode IS NULL;

CREATE INDEX IF NOT EXISTS idx_incidents_dup_time_window
    ON public.incidents (source, created_at DESC)
    INCLUDE (latitude, longitude, category, status, origin_operational_mode)
    WHERE status <> 'REJECTED';

-- ---------------------------------------------------------------------
-- 2. Table: public.incident_duplicate_links (Canonical Undirected Pairs)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incident_duplicate_links (
    link_id VARCHAR(32) PRIMARY KEY,
    incident_low_id VARCHAR(32) NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    incident_high_id VARCHAR(32) NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    link_status VARCHAR(24) NOT NULL DEFAULT 'SUSPECTED',
    primary_incident_id VARCHAR(32) NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    duplicate_incident_id VARCHAR(32) NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    detection_origin VARCHAR(16) NOT NULL DEFAULT 'AUTOMATED',
    detected_in_mode VARCHAR(16) NOT NULL,
    distance_meters DOUBLE PRECISION NOT NULL,
    time_delta_seconds INTEGER NOT NULL,
    confidence_score NUMERIC(4, 3) NOT NULL,
    confidence_band VARCHAR(16) NOT NULL,
    match_reasons TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    review_version INTEGER NOT NULL DEFAULT 0,
    reviewed_by VARCHAR(128) NULL,
    reviewed_role VARCHAR(64) NULL,
    reviewed_at TIMESTAMPTZ NULL,
    review_reason TEXT NULL,
    internal_notes TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT chk_dup_link_id_len CHECK (pg_catalog.char_length(link_id) BETWEEN 5 AND 32),
    CONSTRAINT chk_dup_not_self CHECK (incident_low_id <> incident_high_id),
    CONSTRAINT chk_dup_canonical_pair_order CHECK (incident_low_id COLLATE "C" < incident_high_id COLLATE "C"),
    CONSTRAINT uq_dup_canonical_pair UNIQUE (incident_low_id, incident_high_id),
    CONSTRAINT chk_dup_status CHECK (link_status IN ('SUSPECTED', 'CONFIRMED', 'DISMISSED')),
    CONSTRAINT chk_dup_detection_origin CHECK (detection_origin IN ('AUTOMATED', 'MANUAL')),
    CONSTRAINT chk_dup_detected_in_mode CHECK (detected_in_mode IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD')),
    CONSTRAINT chk_dup_distance_meters CHECK (distance_meters >= 0.0 AND distance_meters <= 25000000.0),
    CONSTRAINT chk_dup_time_delta CHECK (time_delta_seconds >= 0),
    CONSTRAINT chk_dup_confidence_score CHECK (confidence_score >= 0.000 AND confidence_score <= 1.000),
    CONSTRAINT chk_dup_confidence_band CHECK (confidence_band IN ('LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT chk_dup_review_version CHECK (review_version >= 0),
    CONSTRAINT chk_dup_review_state_consistency CHECK (
        (
            link_status = 'SUSPECTED'
            AND primary_incident_id IS NULL
            AND duplicate_incident_id IS NULL
            AND reviewed_by IS NULL
            AND reviewed_role IS NULL
            AND reviewed_at IS NULL
        )
        OR (
            link_status = 'CONFIRMED'
            AND primary_incident_id IS NOT NULL
            AND duplicate_incident_id IS NOT NULL
            AND primary_incident_id <> duplicate_incident_id
            AND primary_incident_id IN (incident_low_id, incident_high_id)
            AND duplicate_incident_id IN (incident_low_id, incident_high_id)
            AND reviewed_by IS NOT NULL
            AND reviewed_role IS NOT NULL
            AND reviewed_at IS NOT NULL
            AND review_reason IS NOT NULL
            AND pg_catalog.btrim(review_reason) <> ''
        )
        OR (
            link_status = 'DISMISSED'
            AND primary_incident_id IS NULL
            AND duplicate_incident_id IS NULL
            AND reviewed_by IS NOT NULL
            AND reviewed_role IS NOT NULL
            AND reviewed_at IS NOT NULL
            AND review_reason IS NOT NULL
            AND pg_catalog.btrim(review_reason) <> ''
        )
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_dup_single_confirmed_primary
    ON public.incident_duplicate_links (duplicate_incident_id)
    WHERE link_status = 'CONFIRMED';

CREATE INDEX IF NOT EXISTS idx_dup_links_status_score
    ON public.incident_duplicate_links (link_status, confidence_score DESC, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_dup_links_low
    ON public.incident_duplicate_links (incident_low_id, link_status);

CREATE INDEX IF NOT EXISTS idx_dup_links_high
    ON public.incident_duplicate_links (incident_high_id, link_status);

CREATE INDEX IF NOT EXISTS idx_dup_links_primary
    ON public.incident_duplicate_links (primary_incident_id)
    WHERE primary_incident_id IS NOT NULL;

ALTER TABLE public.incident_duplicate_links ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.incident_duplicate_links FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.incident_duplicate_links TO service_role;

-- ---------------------------------------------------------------------
-- 3. Table: public.incident_duplicate_scan_jobs (Durable Outbox)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.incident_duplicate_scan_jobs (
    incident_id VARCHAR(32) PRIMARY KEY REFERENCES public.incidents(id) ON DELETE RESTRICT,
    status VARCHAR(24) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    lease_owner VARCHAR(64) NULL,
    lease_expires_at TIMESTAMPTZ NULL,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    last_error_code VARCHAR(64) NULL,
    detected_links_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    completed_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_dup_scan_status CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED_PERMANENT')),
    CONSTRAINT chk_dup_scan_attempt CHECK (attempt_count >= 0),
    CONSTRAINT chk_dup_scan_max_attempts CHECK (max_attempts >= 1 AND max_attempts <= 20),
    CONSTRAINT chk_dup_scan_detected_count CHECK (detected_links_count >= 0),
    CONSTRAINT chk_scan_job_lease_binding CHECK (
        (status = 'IN_PROGRESS' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'IN_PROGRESS' AND lease_owner IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_dup_scan_jobs_runnable
    ON public.incident_duplicate_scan_jobs (status, next_retry_at ASC)
    WHERE status IN ('PENDING', 'IN_PROGRESS');

ALTER TABLE public.incident_duplicate_scan_jobs ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.incident_duplicate_scan_jobs FROM PUBLIC, anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- 4. Replace citizen_incident_creation_rpc (Single 11-Arg Signature)
-- ---------------------------------------------------------------------
DROP FUNCTION IF EXISTS public.citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32)
) RESTRICT;

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
    p_audit_id VARCHAR(32),
    p_origin_operational_mode VARCHAR(16) DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_inc public.incidents%ROWTYPE;
    v_inserted BOOLEAN := FALSE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_photos TEXT[] := COALESCE(p_photos, ARRAY[]::TEXT[]);
BEGIN
    IF p_incident_id IS NULL OR pg_catalog.btrim(p_incident_id) = ''
       OR p_audit_id IS NULL OR pg_catalog.btrim(p_audit_id) = ''
       OR p_description IS NULL OR pg_catalog.btrim(p_description) = '' THEN
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

    IF p_origin_operational_mode IS NOT NULL
       AND p_origin_operational_mode NOT IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD') THEN
        RAISE EXCEPTION 'Invalid origin operational mode: %', p_origin_operational_mode
            USING ERRCODE = '22023';
    END IF;

    IF p_latitude IS NULL OR NOT (p_latitude BETWEEN -90.0 AND 90.0)
       OR p_longitude IS NULL OR NOT (p_longitude BETWEEN -180.0 AND 180.0) THEN
        RAISE EXCEPTION 'Incident coordinates are invalid'
            USING ERRCODE = '22023';
    END IF;

    IF pg_catalog.cardinality(v_photos) > 3 THEN
        RAISE EXCEPTION 'A maximum of three incident photos is permitted'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.incidents (
        id, category, description, latitude, longitude,
        severity, status, source, reporter_name, photos,
        created_at, updated_at, origin_operational_mode
    )
    VALUES (
        p_incident_id, p_category, p_description, p_latitude, p_longitude,
        p_severity, 'REPORTED', p_source, p_reporter_name, v_photos,
        v_now, v_now, p_origin_operational_mode
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
           OR v_inc.photos IS DISTINCT FROM v_photos
           OR v_inc.origin_operational_mode IS DISTINCT FROM p_origin_operational_mode THEN
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

        INSERT INTO public.incident_duplicate_scan_jobs (
            incident_id, status, attempt_count, max_attempts,
            next_retry_at, created_at, updated_at
        )
        VALUES (
            p_incident_id, 'PENDING', 0, 5,
            v_now, v_now, v_now
        )
        ON CONFLICT (incident_id) DO NOTHING;
    END IF;

    RETURN pg_catalog.to_jsonb(v_inc);
END;
$function$;

REVOKE ALL ON FUNCTION public.citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32), VARCHAR(16)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.citizen_incident_creation_rpc(
    VARCHAR(32), VARCHAR(64), TEXT, DOUBLE PRECISION, DOUBLE PRECISION,
    VARCHAR(16), VARCHAR(16), VARCHAR(128), TEXT[], VARCHAR(32), VARCHAR(16)
) TO service_role;

-- ---------------------------------------------------------------------
-- 5. Outbox Management RPCs
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.claim_duplicate_scan_jobs_rpc(
    p_lease_owner VARCHAR(64),
    p_incident_id VARCHAR(32) DEFAULT NULL,
    p_batch_size INT DEFAULT 10,
    p_lease_sec INT DEFAULT 60
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_expires TIMESTAMPTZ;
    v_batch INT;
    v_claimed JSONB;
BEGIN
    IF p_lease_owner IS NULL OR p_lease_owner !~ '^dup_lease_[a-f0-9]{32}$' THEN
        RAISE EXCEPTION 'Invalid p_lease_owner: must match dup_lease_<32 hex chars>'
            USING ERRCODE = '22023';
    END IF;

    IF p_incident_id IS NOT NULL AND pg_catalog.btrim(p_incident_id) = '' THEN
        RAISE EXCEPTION 'p_incident_id cannot be blank when provided'
            USING ERRCODE = '22023';
    END IF;

    v_batch := COALESCE(p_batch_size, 10);
    IF v_batch < 1 OR v_batch > 100 THEN
        RAISE EXCEPTION 'p_batch_size must be between 1 and 100'
            USING ERRCODE = '22023';
    END IF;

    IF p_lease_sec IS NULL OR p_lease_sec < 5 OR p_lease_sec > 3600 THEN
        RAISE EXCEPTION 'p_lease_sec must be between 5 and 3600'
            USING ERRCODE = '22023';
    END IF;

    v_expires := v_now + pg_catalog.make_interval(secs => p_lease_sec);

    -- Convert expired IN_PROGRESS jobs that already reached max_attempts into FAILED_PERMANENT
    WITH expired_exhausted AS (
        SELECT j.incident_id
          FROM public.incident_duplicate_scan_jobs j
         WHERE (p_incident_id IS NULL OR j.incident_id = p_incident_id)
           AND j.status = 'IN_PROGRESS'
           AND j.lease_expires_at IS NOT NULL
           AND j.lease_expires_at <= v_now
           AND j.attempt_count >= j.max_attempts
         FOR UPDATE SKIP LOCKED
    )
    UPDATE public.incident_duplicate_scan_jobs u
       SET status = 'FAILED_PERMANENT',
           lease_owner = NULL,
           lease_expires_at = NULL,
           last_error_code = COALESCE(u.last_error_code, 'LEASE_EXPIRED_MAX_ATTEMPTS'),
           updated_at = v_now
      FROM expired_exhausted e
     WHERE u.incident_id = e.incident_id;

    -- Atomically claim eligible PENDING (retry ready) or expired-lease IN_PROGRESS jobs
    WITH claimable AS (
        SELECT j.incident_id
          FROM public.incident_duplicate_scan_jobs j
         WHERE (p_incident_id IS NULL OR j.incident_id = p_incident_id)
           AND (
               (j.status = 'PENDING' AND j.next_retry_at <= v_now)
               OR (j.status = 'IN_PROGRESS' AND j.lease_expires_at IS NOT NULL AND j.lease_expires_at <= v_now)
           )
           AND j.attempt_count < j.max_attempts
         ORDER BY j.next_retry_at ASC, j.created_at ASC, j.incident_id ASC
         LIMIT v_batch
         FOR UPDATE SKIP LOCKED
    ),
    updated AS (
        UPDATE public.incident_duplicate_scan_jobs u
           SET status = 'IN_PROGRESS',
               lease_owner = p_lease_owner,
               lease_expires_at = v_expires,
               attempt_count = u.attempt_count + 1,
               updated_at = v_now
          FROM claimable c
         WHERE u.incident_id = c.incident_id
        RETURNING u.*
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(updated)), '[]'::jsonb)
      INTO v_claimed
      FROM updated;

    RETURN COALESCE(v_claimed, '[]'::jsonb);
END;
$function$;

REVOKE ALL ON FUNCTION public.claim_duplicate_scan_jobs_rpc(
    VARCHAR(64), VARCHAR(32), INT, INT
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.claim_duplicate_scan_jobs_rpc(
    VARCHAR(64), VARCHAR(32), INT, INT
) TO service_role;

CREATE OR REPLACE FUNCTION public.fetch_duplicate_candidates_rpc(
    p_incident_id VARCHAR(32),
    p_max_radius_m DOUBLE PRECISION,
    p_time_window_sec INT,
    p_allowed_categories TEXT[],
    p_include_resolved BOOLEAN DEFAULT FALSE,
    p_match_citizen_physical_sensor BOOLEAN DEFAULT TRUE,
    p_limit INT DEFAULT 200
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_src public.incidents%ROWTYPE;
    v_earth_radius CONSTANT DOUBLE PRECISION := 6371000.0;
    v_radius_buf DOUBLE PRECISION;
    v_delta_buf DOUBLE PRECISION;
    v_dlat_deg DOUBLE PRECISION;
    v_dlon_deg DOUBLE PRECISION;
    v_cos_lat DOUBLE PRECISION;
    v_lat_min DOUBLE PRECISION;
    v_lat_max DOUBLE PRECISION;
    v_lon_min DOUBLE PRECISION;
    v_lon_max DOUBLE PRECISION;
    v_use_lon_box BOOLEAN := TRUE;
    v_window_interval INTERVAL;
    v_effective_limit INT;
    v_candidates JSONB;
BEGIN
    IF p_incident_id IS NULL OR pg_catalog.btrim(p_incident_id) = '' THEN
        RAISE EXCEPTION 'p_incident_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_max_radius_m IS NULL OR NOT (p_max_radius_m > 0.0 AND p_max_radius_m <= 10000.0) THEN
        RAISE EXCEPTION 'p_max_radius_m must be in (0, 10000]' USING ERRCODE = '22023';
    END IF;

    IF p_time_window_sec IS NULL OR p_time_window_sec < 60 OR p_time_window_sec > 2592000 THEN
        RAISE EXCEPTION 'p_time_window_sec must be between 60 and 2592000' USING ERRCODE = '22023';
    END IF;

    v_effective_limit := LEAST(GREATEST(COALESCE(p_limit, 200), 1), 200);

    SELECT *
      INTO v_src
      FROM public.incidents
     WHERE id = p_incident_id;

    IF NOT FOUND THEN
        RETURN pg_catalog.jsonb_build_object(
            'source_incident', NULL,
            'candidates', '[]'::jsonb
        );
    END IF;

    -- Explicit coordinate bounds & NaN/Inf guards + Null Island + DEMO + status eligibility
    IF v_src.latitude IS NULL OR NOT (v_src.latitude BETWEEN -90.0 AND 90.0)
       OR v_src.longitude IS NULL OR NOT (v_src.longitude BETWEEN -180.0 AND 180.0)
       OR (pg_catalog.abs(v_src.latitude) < 0.0001 AND pg_catalog.abs(v_src.longitude) < 0.0001)
       OR v_src.source = 'DEMO'
       OR v_src.status = 'REJECTED'
       OR (NOT COALESCE(p_include_resolved, FALSE) AND v_src.status = 'RESOLVED') THEN
        RETURN pg_catalog.jsonb_build_object(
            'source_incident', pg_catalog.to_jsonb(v_src),
            'candidates', '[]'::jsonb
        );
    END IF;

    v_radius_buf := p_max_radius_m + 1.0;
    v_delta_buf := v_radius_buf / v_earth_radius;
    v_dlat_deg := pg_catalog.degrees(v_delta_buf) + 1e-7;
    v_lat_min := GREATEST(-90.0::double precision, v_src.latitude - v_dlat_deg);
    v_lat_max := LEAST(90.0::double precision, v_src.latitude + v_dlat_deg);
    v_cos_lat := pg_catalog.cos(pg_catalog.radians(v_src.latitude));

    IF pg_catalog.abs(v_src.latitude) + v_dlat_deg >= 89.999
       OR v_delta_buf >= (pg_catalog.pi() / 2.0)
       OR v_cos_lat <= 1e-9
       OR (pg_catalog.sin(v_delta_buf) / v_cos_lat) >= 0.999999 THEN
        v_use_lon_box := FALSE;
    ELSE
        v_dlon_deg := pg_catalog.degrees(pg_catalog.asin(pg_catalog.sin(v_delta_buf) / v_cos_lat)) + 1e-7;
        IF v_dlon_deg >= 180.0 THEN
            v_use_lon_box := FALSE;
        ELSE
            v_lon_min := v_src.longitude - v_dlon_deg;
            v_lon_max := v_src.longitude + v_dlon_deg;
            v_use_lon_box := TRUE;
        END IF;
    END IF;

    v_window_interval := pg_catalog.make_interval(secs => p_time_window_sec);

    WITH candidates AS (
        SELECT
            c.id,
            c.category,
            c.description,
            c.latitude,
            c.longitude,
            c.severity,
            c.status,
            c.source,
            c.origin_operational_mode,
            c.created_at,
            c.updated_at,
            (
                2.0 * v_earth_radius * pg_catalog.asin(
                    pg_catalog.sqrt(
                        LEAST(
                            1.0::double precision,
                            GREATEST(
                                0.0::double precision,
                                pg_catalog.power(pg_catalog.sin(pg_catalog.radians(c.latitude - v_src.latitude) / 2.0), 2)
                                + v_cos_lat
                                * pg_catalog.cos(pg_catalog.radians(c.latitude))
                                * pg_catalog.power(pg_catalog.sin(pg_catalog.radians(c.longitude - v_src.longitude) / 2.0), 2)
                            )
                        )
                    )
                )
            ) AS distance_meters
          FROM public.incidents c
         WHERE c.id <> v_src.id
           AND c.status <> 'REJECTED'
           AND (COALESCE(p_include_resolved, FALSE) OR c.status <> 'RESOLVED')
           AND c.source <> 'DEMO'
           AND c.latitude IS NOT NULL
           AND c.longitude IS NOT NULL
           AND (c.latitude BETWEEN -90.0 AND 90.0)
           AND (c.longitude BETWEEN -180.0 AND 180.0)
           AND NOT (pg_catalog.abs(c.latitude) < 0.0001 AND pg_catalog.abs(c.longitude) < 0.0001)
           AND c.latitude BETWEEN v_lat_min AND v_lat_max
           AND (
               NOT v_use_lon_box
               OR (v_lon_min >= -180.0 AND v_lon_max <= 180.0 AND c.longitude BETWEEN v_lon_min AND v_lon_max)
               OR (v_lon_min < -180.0 AND (c.longitude >= (v_lon_min + 360.0) OR c.longitude <= v_lon_max))
               OR (v_lon_max > 180.0 AND (c.longitude >= v_lon_min OR c.longitude <= (v_lon_max - 360.0)))
           )
           AND c.created_at >= (v_src.created_at - v_window_interval)
           AND c.created_at <= (v_src.created_at + v_window_interval)
           AND (
               p_allowed_categories IS NULL
               OR pg_catalog.cardinality(p_allowed_categories) = 0
               OR c.category = ANY(p_allowed_categories)
           )
           AND (
               (v_src.source = 'CITIZEN' AND (
                   c.source = 'CITIZEN'
                   OR (COALESCE(p_match_citizen_physical_sensor, TRUE) AND c.source = 'SENSOR' AND c.origin_operational_mode IN ('PHYSICAL', 'SAFE_HOLD'))
               ))
               OR (v_src.source = 'SENSOR' AND v_src.origin_operational_mode = 'SIMULATION' AND (
                   c.source = 'SENSOR' AND c.origin_operational_mode = 'SIMULATION'
               ))
               OR (v_src.source = 'SENSOR' AND v_src.origin_operational_mode IN ('PHYSICAL', 'SAFE_HOLD') AND (
                   (c.source = 'SENSOR' AND c.origin_operational_mode IN ('PHYSICAL', 'SAFE_HOLD'))
                   OR (COALESCE(p_match_citizen_physical_sensor, TRUE) AND c.source = 'CITIZEN')
               ))
           )
    ),
    filtered AS (
        SELECT *
          FROM candidates
         WHERE distance_meters <= v_radius_buf
         ORDER BY distance_meters ASC, created_at ASC, id ASC
         LIMIT v_effective_limit
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(filtered)), '[]'::jsonb)
      INTO v_candidates
      FROM filtered;

    RETURN pg_catalog.jsonb_build_object(
        'source_incident', pg_catalog.to_jsonb(v_src),
        'candidates', COALESCE(v_candidates, '[]'::jsonb)
    );
END;
$function$;

REVOKE ALL ON FUNCTION public.fetch_duplicate_candidates_rpc(
    VARCHAR(32), DOUBLE PRECISION, INT, TEXT[], BOOLEAN, BOOLEAN, INT
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.fetch_duplicate_candidates_rpc(
    VARCHAR(32), DOUBLE PRECISION, INT, TEXT[], BOOLEAN, BOOLEAN, INT
) TO service_role;

CREATE OR REPLACE FUNCTION public.record_duplicate_candidates_rpc(
    p_incident_id VARCHAR(32),
    p_detected_in_mode VARCHAR(16),
    p_candidates JSONB,
    p_lease_owner VARCHAR(64)
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_job public.incident_duplicate_scan_jobs%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_item JSONB;
    v_cand_id VARCHAR(32);
    v_low_id VARCHAR(32);
    v_high_id VARCHAR(32);
    v_link_id VARCHAR(32);
    v_origin VARCHAR(16);
    v_band VARCHAR(16);
    v_dist DOUBLE PRECISION;
    v_delta INTEGER;
    v_score NUMERIC(4, 3);
    v_reasons TEXT[];
    v_inserted_count INTEGER := 0;
    v_total_links INTEGER := 0;
BEGIN
    IF p_incident_id IS NULL OR pg_catalog.btrim(p_incident_id) = '' THEN
        RAISE EXCEPTION 'p_incident_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_detected_in_mode IS NULL OR p_detected_in_mode NOT IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD') THEN
        RAISE EXCEPTION 'Invalid p_detected_in_mode: %', p_detected_in_mode USING ERRCODE = '22023';
    END IF;

    IF p_lease_owner IS NULL OR p_lease_owner !~ '^dup_lease_[a-f0-9]{32}$' THEN
        RAISE EXCEPTION 'Invalid p_lease_owner: must match dup_lease_<32 hex chars>' USING ERRCODE = '22023';
    END IF;

    SELECT *
      INTO v_job
      FROM public.incident_duplicate_scan_jobs
     WHERE incident_id = p_incident_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Duplicate scan job for incident % not found', p_incident_id
            USING ERRCODE = '02000';
    END IF;

    -- Strict active-lease verification BEFORE inserting any links
    IF v_job.status <> 'IN_PROGRESS'
       OR v_job.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_job.lease_expires_at IS NULL
       OR v_job.lease_expires_at <= v_now THEN
        RAISE EXCEPTION 'Stale or non-owned lease for incident % scan job', p_incident_id
            USING ERRCODE = 'P0412';
    END IF;

    IF p_candidates IS NOT NULL AND pg_catalog.jsonb_typeof(p_candidates) <> 'array' THEN
        RAISE EXCEPTION 'p_candidates must be a JSON array when provided'
            USING ERRCODE = '22023';
    END IF;

    IF p_candidates IS NOT NULL AND pg_catalog.jsonb_typeof(p_candidates) = 'array' THEN
        FOR v_item IN SELECT value FROM pg_catalog.jsonb_array_elements(p_candidates)
        LOOP
            v_cand_id := pg_catalog.btrim(COALESCE(v_item->>'candidate_incident_id', ''));
            IF v_cand_id = '' OR v_cand_id = p_incident_id THEN
                RAISE EXCEPTION 'Invalid candidate_incident_id in payload' USING ERRCODE = '22023';
            END IF;

            IF p_incident_id COLLATE "C" < v_cand_id COLLATE "C" THEN
                v_low_id := p_incident_id;
                v_high_id := v_cand_id;
            ELSE
                v_low_id := v_cand_id;
                v_high_id := p_incident_id;
            END IF;

            v_link_id := NULLIF(pg_catalog.btrim(COALESCE(v_item->>'link_id', '')), '');
            IF v_link_id IS NULL
               OR pg_catalog.char_length(v_link_id) < 5
               OR pg_catalog.char_length(v_link_id) > 32 THEN
                v_link_id := 'lnk_' || pg_catalog.substr(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 1, 24);
            END IF;

            v_origin := COALESCE(NULLIF(pg_catalog.btrim(v_item->>'detection_origin'), ''), 'AUTOMATED');
            v_dist := (v_item->>'distance_meters')::double precision;
            v_delta := (v_item->>'time_delta_seconds')::integer;
            v_score := (v_item->>'confidence_score')::numeric(4, 3);
            v_band := pg_catalog.btrim(COALESCE(v_item->>'confidence_band', ''));

            IF v_item ? 'match_reasons' AND pg_catalog.jsonb_typeof(v_item->'match_reasons') = 'array' THEN
                SELECT COALESCE(pg_catalog.array_agg(t.val), ARRAY[]::TEXT[])
                  INTO v_reasons
                  FROM pg_catalog.jsonb_array_elements_text(v_item->'match_reasons') AS t(val);
            ELSE
                v_reasons := ARRAY[]::TEXT[];
            END IF;

            INSERT INTO public.incident_duplicate_links (
                link_id,
                incident_low_id,
                incident_high_id,
                link_status,
                primary_incident_id,
                duplicate_incident_id,
                detection_origin,
                detected_in_mode,
                distance_meters,
                time_delta_seconds,
                confidence_score,
                confidence_band,
                match_reasons,
                review_version,
                created_at,
                updated_at
            )
            VALUES (
                v_link_id,
                v_low_id,
                v_high_id,
                'SUSPECTED',
                NULL,
                NULL,
                v_origin,
                p_detected_in_mode,
                v_dist,
                v_delta,
                v_score,
                v_band,
                COALESCE(v_reasons, ARRAY[]::TEXT[]),
                0,
                v_now,
                v_now
            )
            ON CONFLICT (incident_low_id, incident_high_id) DO NOTHING;

            IF FOUND THEN
                v_inserted_count := v_inserted_count + 1;
            END IF;
        END LOOP;
    END IF;

    UPDATE public.incident_duplicate_scan_jobs
       SET status = 'COMPLETED',
           lease_owner = NULL,
           lease_expires_at = NULL,
           last_error_code = NULL,
           detected_links_count = v_inserted_count,
           completed_at = v_now,
           updated_at = v_now
     WHERE incident_id = p_incident_id
       AND status = 'IN_PROGRESS'
       AND lease_owner = p_lease_owner;

    SELECT pg_catalog.count(*)::integer
      INTO v_total_links
      FROM public.incident_duplicate_links
     WHERE incident_low_id = p_incident_id OR incident_high_id = p_incident_id;

    RETURN pg_catalog.jsonb_build_object(
        'incident_id', p_incident_id,
        'status', 'COMPLETED',
        'links_created', v_inserted_count,
        'total_links', COALESCE(v_total_links, 0)
    );
END;
$function$;

REVOKE ALL ON FUNCTION public.record_duplicate_candidates_rpc(
    VARCHAR(32), VARCHAR(16), JSONB, VARCHAR(64)
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.record_duplicate_candidates_rpc(
    VARCHAR(32), VARCHAR(16), JSONB, VARCHAR(64)
) TO service_role;

CREATE OR REPLACE FUNCTION public.release_duplicate_scan_job_rpc(
    p_incident_id VARCHAR(32),
    p_lease_owner VARCHAR(64),
    p_error_code VARCHAR(64),
    p_backoff_sec INT DEFAULT NULL,
    p_permanent BOOLEAN DEFAULT FALSE
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_job public.incident_duplicate_scan_jobs%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_backoff_schedule CONSTANT INT[] := ARRAY[30, 120, 600, 1800, 3600];
    v_resolved_backoff INT;
    v_clean_error VARCHAR(64);
    v_target_status VARCHAR(24);
    v_next_retry TIMESTAMPTZ;
BEGIN
    IF p_incident_id IS NULL OR pg_catalog.btrim(p_incident_id) = '' THEN
        RAISE EXCEPTION 'p_incident_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_lease_owner IS NULL OR p_lease_owner !~ '^dup_lease_[a-f0-9]{32}$' THEN
        RAISE EXCEPTION 'Invalid p_lease_owner: must match dup_lease_<32 hex chars>' USING ERRCODE = '22023';
    END IF;

    v_clean_error := pg_catalog.left(pg_catalog.btrim(COALESCE(p_error_code, '')), 64);
    IF v_clean_error = '' THEN
        RAISE EXCEPTION 'p_error_code is required' USING ERRCODE = '22023';
    END IF;

    IF p_backoff_sec IS NOT NULL AND (p_backoff_sec < 1 OR p_backoff_sec > 86400) THEN
        RAISE EXCEPTION 'p_backoff_sec must be between 1 and 86400' USING ERRCODE = '22023';
    END IF;

    SELECT *
      INTO v_job
      FROM public.incident_duplicate_scan_jobs
     WHERE incident_id = p_incident_id
     FOR UPDATE;

    -- Stale workers or expired leases must produce ZERO mutations
    IF NOT FOUND
       OR v_job.status <> 'IN_PROGRESS'
       OR v_job.lease_owner IS DISTINCT FROM p_lease_owner
       OR v_job.lease_expires_at IS NULL
       OR v_job.lease_expires_at <= v_now THEN
        RETURN pg_catalog.jsonb_build_object(
            'released', FALSE,
            'reason', 'LEASE_NOT_OWNED_OR_EXPIRED',
            'status', COALESCE(v_job.status, 'NOT_FOUND')
        );
    END IF;

    v_resolved_backoff := COALESCE(
        p_backoff_sec,
        v_backoff_schedule[GREATEST(1, LEAST(v_job.attempt_count, 5))]
    );

    IF COALESCE(p_permanent, FALSE) OR v_job.attempt_count >= v_job.max_attempts THEN
        v_target_status := 'FAILED_PERMANENT';
        v_next_retry := v_job.next_retry_at;

        UPDATE public.incident_duplicate_scan_jobs
           SET status = 'FAILED_PERMANENT',
               lease_owner = NULL,
               lease_expires_at = NULL,
               last_error_code = v_clean_error,
               updated_at = v_now
         WHERE incident_id = p_incident_id
           AND status = 'IN_PROGRESS'
           AND lease_owner = p_lease_owner;
    ELSE
        v_target_status := 'PENDING';
        v_next_retry := v_now + pg_catalog.make_interval(secs => v_resolved_backoff);

        UPDATE public.incident_duplicate_scan_jobs
           SET status = 'PENDING',
               lease_owner = NULL,
               lease_expires_at = NULL,
               next_retry_at = v_next_retry,
               last_error_code = v_clean_error,
               updated_at = v_now
         WHERE incident_id = p_incident_id
           AND status = 'IN_PROGRESS'
           AND lease_owner = p_lease_owner;
    END IF;

    RETURN pg_catalog.jsonb_build_object(
        'released', TRUE,
        'status', v_target_status,
        'attempt_count', v_job.attempt_count,
        'max_attempts', v_job.max_attempts,
        'backoff_sec', v_resolved_backoff,
        'next_retry_at', v_next_retry
    );
END;
$function$;

REVOKE ALL ON FUNCTION public.release_duplicate_scan_job_rpc(
    VARCHAR(32), VARCHAR(64), VARCHAR(64), INT, BOOLEAN
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.release_duplicate_scan_job_rpc(
    VARCHAR(32), VARCHAR(64), VARCHAR(64), INT, BOOLEAN
) TO service_role;

CREATE OR REPLACE FUNCTION public.reset_duplicate_scan_job_rpc(
    p_incident_id VARCHAR(32),
    p_actor_id VARCHAR(128),
    p_actor_role VARCHAR(64),
    p_reason TEXT DEFAULT 'Manual duplicate scan job reset'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_job public.incident_duplicate_scan_jobs%ROWTYPE;
    v_inc public.incidents%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_prev_status VARCHAR(24);
    v_prev_attempts INTEGER;
    v_clean_reason TEXT;
    v_audit_id VARCHAR(32);
BEGIN
    IF p_incident_id IS NULL OR pg_catalog.btrim(p_incident_id) = '' THEN
        RAISE EXCEPTION 'p_incident_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_actor_id IS NULL OR pg_catalog.btrim(p_actor_id) = '' THEN
        RAISE EXCEPTION 'p_actor_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_actor_role IS NULL OR p_actor_role NOT IN ('municipality', 'admin', 'service_role') THEN
        RAISE EXCEPTION 'Unauthorized: reset requires municipality, admin, or service_role credentials'
            USING ERRCODE = '42501';
    END IF;

    SELECT *
      INTO v_inc
      FROM public.incidents
     WHERE id = p_incident_id
     FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % not found', p_incident_id USING ERRCODE = '02000';
    END IF;

    SELECT *
      INTO v_job
      FROM public.incident_duplicate_scan_jobs
     WHERE incident_id = p_incident_id
     FOR UPDATE;

    IF NOT FOUND THEN
        v_prev_status := 'MISSING';
        v_prev_attempts := 0;

        INSERT INTO public.incident_duplicate_scan_jobs (
            incident_id, status, attempt_count, max_attempts,
            next_retry_at, created_at, updated_at
        )
        VALUES (
            p_incident_id, 'PENDING', 0, 5,
            v_now, v_now, v_now
        )
        RETURNING * INTO v_job;
    ELSE
        IF v_job.status = 'IN_PROGRESS'
           AND v_job.lease_expires_at IS NOT NULL
           AND v_job.lease_expires_at > v_now THEN
            RAISE EXCEPTION 'Cannot reset duplicate scan job % while an active lease is held by %',
                p_incident_id, v_job.lease_owner
                USING ERRCODE = '23514';
        END IF;

        v_prev_status := v_job.status;
        v_prev_attempts := v_job.attempt_count;

        UPDATE public.incident_duplicate_scan_jobs
           SET status = 'PENDING',
               attempt_count = 0,
               lease_owner = NULL,
               lease_expires_at = NULL,
               next_retry_at = v_now,
               last_error_code = NULL,
               completed_at = NULL,
               updated_at = v_now
         WHERE incident_id = p_incident_id
        RETURNING * INTO v_job;
    END IF;

    v_clean_reason := COALESCE(NULLIF(pg_catalog.btrim(p_reason), ''), 'Manual duplicate scan job reset');
    v_audit_id := 'aud_' || pg_catalog.substr(pg_catalog.replace(pg_catalog.gen_random_uuid()::text, '-', ''), 1, 24);

    INSERT INTO public.incident_audits (
        audit_id, incident_id, actor_id, actor_role, action,
        previous_status, new_status, reason, internal_notes, timestamp
    ) VALUES (
        v_audit_id,
        p_incident_id,
        pg_catalog.left(pg_catalog.btrim(p_actor_id), 128),
        p_actor_role,
        'DUPLICATE_SCAN_RESET',
        NULL,
        NULL,
        v_clean_reason,
        'previous_status=' || v_prev_status || ';previous_attempts=' || v_prev_attempts::text,
        v_now
    );

    RETURN pg_catalog.to_jsonb(v_job);
END;
$function$;

REVOKE ALL ON FUNCTION public.reset_duplicate_scan_job_rpc(
    VARCHAR(32), VARCHAR(128), VARCHAR(64), TEXT
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.reset_duplicate_scan_job_rpc(
    VARCHAR(32), VARCHAR(128), VARCHAR(64), TEXT
) TO service_role;

-- ---------------------------------------------------------------------
-- 6. Review duplicate link RPC
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.review_incident_duplicate_link_rpc(
    p_link_id VARCHAR(32),
    p_target_status VARCHAR(24),
    p_actor_id VARCHAR(128),
    p_actor_role VARCHAR(64),
    p_reason TEXT,
    p_audit_id_low VARCHAR(32),
    p_audit_id_high VARCHAR(32),
    p_primary_incident_id VARCHAR(32) DEFAULT NULL,
    p_internal_notes TEXT DEFAULT NULL,
    p_override BOOLEAN DEFAULT FALSE,
    p_expected_version INT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_link public.incident_duplicate_links%ROWTYPE;
    v_inc_low public.incidents%ROWTYPE;
    v_inc_high public.incidents%ROWTYPE;
    v_inc_primary public.incidents%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_is_override BOOLEAN := FALSE;
    v_duplicate_id VARCHAR(32) := NULL;
    v_creates_cycle BOOLEAN := FALSE;
    v_audit_action VARCHAR(64);
    v_clean_reason TEXT;
    v_clean_notes TEXT;
    v_structured_reason TEXT;
BEGIN
    IF p_link_id IS NULL OR pg_catalog.btrim(p_link_id) = '' THEN
        RAISE EXCEPTION 'p_link_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_target_status IS NULL OR p_target_status NOT IN ('CONFIRMED', 'DISMISSED') THEN
        RAISE EXCEPTION 'Invalid target status: must be CONFIRMED or DISMISSED' USING ERRCODE = '22023';
    END IF;

    IF p_actor_id IS NULL OR pg_catalog.btrim(p_actor_id) = '' THEN
        RAISE EXCEPTION 'p_actor_id is required' USING ERRCODE = '22023';
    END IF;

    IF p_actor_role IS NULL OR p_actor_role NOT IN ('municipality', 'admin', 'service_role') THEN
        RAISE EXCEPTION 'Unauthorized: duplicate link review requires municipality, admin, or service_role credentials'
            USING ERRCODE = '42501';
    END IF;

    v_clean_reason := pg_catalog.btrim(COALESCE(p_reason, ''));
    IF pg_catalog.char_length(v_clean_reason) < 3 OR pg_catalog.char_length(v_clean_reason) > 500 THEN
        RAISE EXCEPTION 'A mandatory review reason between 3 and 500 characters is required'
            USING ERRCODE = '22023';
    END IF;

    IF p_audit_id_low IS NULL OR pg_catalog.btrim(p_audit_id_low) = ''
       OR p_audit_id_high IS NULL OR pg_catalog.btrim(p_audit_id_high) = ''
       OR p_audit_id_low = p_audit_id_high THEN
        RAISE EXCEPTION 'Distinct non-empty p_audit_id_low and p_audit_id_high are required'
            USING ERRCODE = '22023';
    END IF;

    IF p_target_status = 'CONFIRMED' AND (p_primary_incident_id IS NULL OR pg_catalog.btrim(p_primary_incident_id) = '') THEN
        RAISE EXCEPTION 'p_primary_incident_id is required when confirming a duplicate link'
            USING ERRCODE = '22023';
    END IF;

    -- Lock hierarchy step 1: serialize confirmation graph mutation checks
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('drainx:duplicate_confirm_graph'));

    -- Lock hierarchy step 2: lock target duplicate link row
    SELECT *
      INTO v_link
      FROM public.incident_duplicate_links
     WHERE link_id = p_link_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Duplicate link % not found', p_link_id USING ERRCODE = '02000';
    END IF;

    -- Lock hierarchy step 3: lock both referenced incidents in deterministic COLLATE "C" order
    SELECT * INTO v_inc_low FROM public.incidents WHERE id = v_link.incident_low_id FOR SHARE;
    SELECT * INTO v_inc_high FROM public.incidents WHERE id = v_link.incident_high_id FOR SHARE;

    IF v_inc_low.id IS NULL OR v_inc_high.id IS NULL THEN
        RAISE EXCEPTION 'One or both linked incidents no longer exist' USING ERRCODE = '02000';
    END IF;

    -- Optimistic concurrency verification
    IF p_expected_version IS NOT NULL AND v_link.review_version <> p_expected_version THEN
        RAISE EXCEPTION 'Version conflict on duplicate link %: expected %, found %',
            p_link_id, p_expected_version, v_link.review_version
            USING ERRCODE = '23514';
    END IF;

    v_is_override := (v_link.link_status <> 'SUSPECTED');
    IF v_is_override AND NOT COALESCE(p_override, FALSE) THEN
        RAISE EXCEPTION 'Duplicate link % is already %; explicit override=true is required',
            p_link_id, v_link.link_status
            USING ERRCODE = '23514';
    END IF;

    -- Reject redundant no-op overrides
    IF v_is_override THEN
        IF p_target_status = 'DISMISSED' AND v_link.link_status = 'DISMISSED' THEN
            RAISE EXCEPTION 'Redundant override: link % is already DISMISSED', p_link_id
                USING ERRCODE = '22023';
        END IF;
        IF p_target_status = 'CONFIRMED'
           AND v_link.link_status = 'CONFIRMED'
           AND v_link.primary_incident_id = p_primary_incident_id THEN
            RAISE EXCEPTION 'Redundant override: link % is already CONFIRMED with primary %',
                p_link_id, p_primary_incident_id
                USING ERRCODE = '22023';
        END IF;
    END IF;

    IF p_target_status = 'CONFIRMED' THEN
        IF p_primary_incident_id = v_link.incident_low_id THEN
            v_duplicate_id := v_link.incident_high_id;
            v_inc_primary := v_inc_low;
        ELSIF p_primary_incident_id = v_link.incident_high_id THEN
            v_duplicate_id := v_link.incident_low_id;
            v_inc_primary := v_inc_high;
        ELSE
            RAISE EXCEPTION 'Primary incident % does not belong to link % pair (%, %)',
                p_primary_incident_id, p_link_id, v_link.incident_low_id, v_link.incident_high_id
                USING ERRCODE = '22023';
        END IF;

        IF v_inc_primary.status = 'REJECTED' THEN
            RAISE EXCEPTION 'Cannot confirm REJECTED incident % as primary incident',
                p_primary_incident_id
                USING ERRCODE = '23514';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM public.incident_duplicate_links l
             WHERE l.duplicate_incident_id = v_duplicate_id
               AND l.link_id <> p_link_id
               AND l.link_status = 'CONFIRMED'
        ) THEN
            RAISE EXCEPTION 'Incident % is already confirmed as a duplicate of another primary incident',
                v_duplicate_id
                USING ERRCODE = '23505';
        END IF;

        -- Unlimited-depth recursive cycle check across all confirmed links
        WITH RECURSIVE dup_chain(current_id, path_ids) AS (
            SELECT p_primary_incident_id::TEXT, ARRAY[p_primary_incident_id::TEXT]
            UNION ALL
            SELECT l.primary_incident_id::TEXT, c.path_ids || l.primary_incident_id::TEXT
              FROM public.incident_duplicate_links l
              JOIN dup_chain c
                ON l.duplicate_incident_id::TEXT = c.current_id
             WHERE l.link_status = 'CONFIRMED'
               AND l.link_id <> p_link_id
               AND NOT (l.primary_incident_id::TEXT = ANY(c.path_ids))
        )
        SELECT EXISTS (
            SELECT 1
              FROM dup_chain
             WHERE current_id = v_duplicate_id::TEXT
        ) INTO v_creates_cycle;

        IF v_creates_cycle THEN
            RAISE EXCEPTION 'Confirming % as duplicate of % would create a circular dependency',
                v_duplicate_id, p_primary_incident_id
                USING ERRCODE = '23514';
        END IF;
    ELSE
        v_duplicate_id := NULL;
    END IF;

    v_clean_notes := NULLIF(pg_catalog.btrim(COALESCE(p_internal_notes, '')), '');

    -- Update link only (never mutate incident status or photos)
    UPDATE public.incident_duplicate_links
       SET link_status = p_target_status,
           primary_incident_id = CASE WHEN p_target_status = 'CONFIRMED' THEN p_primary_incident_id ELSE NULL END,
           duplicate_incident_id = CASE WHEN p_target_status = 'CONFIRMED' THEN v_duplicate_id ELSE NULL END,
           review_version = review_version + 1,
           reviewed_by = pg_catalog.left(pg_catalog.btrim(p_actor_id), 128),
           reviewed_role = p_actor_role,
           reviewed_at = v_now,
           review_reason = v_clean_reason,
           internal_notes = v_clean_notes,
           updated_at = v_now
     WHERE link_id = p_link_id
    RETURNING * INTO v_link;

    IF v_is_override THEN
        v_audit_action := CASE
            WHEN p_target_status = 'CONFIRMED' THEN 'DUPLICATE_OVERRIDE_CONFIRMED'
            ELSE 'DUPLICATE_OVERRIDE_DISMISSED'
        END;
    ELSE
        v_audit_action := CASE
            WHEN p_target_status = 'CONFIRMED' THEN 'DUPLICATE_CONFIRMED'
            ELSE 'DUPLICATE_DISMISSED'
        END;
    END IF;

    v_structured_reason := 'link=' || p_link_id
        || ';status=' || p_target_status
        || CASE
               WHEN p_target_status = 'CONFIRMED'
               THEN ';primary=' || p_primary_incident_id || ';duplicate=' || v_duplicate_id
               ELSE ''
           END
        || ';reason=' || v_clean_reason;

    -- Append immutable audit entries to BOTH linked incidents
    INSERT INTO public.incident_audits (
        audit_id, incident_id, actor_id, actor_role, action,
        previous_status, new_status,
        reason, internal_notes, timestamp
    ) VALUES (
        p_audit_id_low,
        v_link.incident_low_id,
        pg_catalog.left(pg_catalog.btrim(p_actor_id), 128),
        p_actor_role,
        v_audit_action,
        NULL,
        NULL,
        v_structured_reason,
        v_clean_notes,
        v_now
    );

    INSERT INTO public.incident_audits (
        audit_id, incident_id, actor_id, actor_role, action,
        previous_status, new_status,
        reason, internal_notes, timestamp
    ) VALUES (
        p_audit_id_high,
        v_link.incident_high_id,
        pg_catalog.left(pg_catalog.btrim(p_actor_id), 128),
        p_actor_role,
        v_audit_action,
        NULL,
        NULL,
        v_structured_reason,
        v_clean_notes,
        v_now
    );

    RETURN pg_catalog.to_jsonb(v_link);
END;
$function$;

REVOKE ALL ON FUNCTION public.review_incident_duplicate_link_rpc(
    VARCHAR(32), VARCHAR(24), VARCHAR(128), VARCHAR(64), TEXT, VARCHAR(32), VARCHAR(32), VARCHAR(32), TEXT, BOOLEAN, INT
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.review_incident_duplicate_link_rpc(
    VARCHAR(32), VARCHAR(24), VARCHAR(128), VARCHAR(64), TEXT, VARCHAR(32), VARCHAR(32), VARCHAR(32), TEXT, BOOLEAN, INT
) TO service_role;

-- ---------------------------------------------------------------------
-- 7. Schema & Privilege Assertion Block
-- ---------------------------------------------------------------------
DO $verify_schema$
DECLARE
    v_missing_cons INT;
    v_fk_count INT;
    v_bad_fk_count INT;
    v_rpc_req RECORD;
    v_proc_oid OID;
    v_overload_count INT;
    v_prosecdef BOOLEAN;
    v_proconfig TEXT[];
    v_role TEXT;
    v_tbl TEXT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'incidents' AND column_name = 'origin_operational_mode'
    ) THEN
        RAISE EXCEPTION 'Schema assertion failed: incidents.origin_operational_mode missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_indexes
         WHERE schemaname = 'public' AND tablename = 'incidents' AND indexname = 'idx_incidents_dup_time_window'
    ) THEN
        RAISE EXCEPTION 'Schema assertion failed: idx_incidents_dup_time_window missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'incident_duplicate_links' AND c.relrowsecurity = TRUE
    ) THEN
        RAISE EXCEPTION 'Schema assertion failed: incident_duplicate_links missing or RLS disabled';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relname = 'incident_duplicate_scan_jobs' AND c.relrowsecurity = TRUE
    ) THEN
        RAISE EXCEPTION 'Schema assertion failed: incident_duplicate_scan_jobs missing or RLS disabled';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_indexes
         WHERE schemaname = 'public' AND tablename = 'incident_duplicate_links' AND indexname = 'uq_dup_single_confirmed_primary'
    ) THEN
        RAISE EXCEPTION 'Schema assertion failed: uq_dup_single_confirmed_primary missing';
    END IF;

    SELECT pg_catalog.count(*)
      INTO v_missing_cons
      FROM (VALUES
          ('incidents', 'chk_incidents_origin_operational_mode'),
          ('incident_duplicate_links', 'uq_dup_canonical_pair'),
          ('incident_duplicate_links', 'chk_dup_canonical_pair_order'),
          ('incident_duplicate_links', 'chk_dup_review_state_consistency'),
          ('incident_duplicate_links', 'chk_dup_distance_meters'),
          ('incident_duplicate_scan_jobs', 'chk_dup_scan_status'),
          ('incident_duplicate_scan_jobs', 'chk_scan_job_lease_binding')
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
        RAISE EXCEPTION 'Schema assertion failed: % required CHECK/UNIQUE constraint(s) missing', v_missing_cons;
    END IF;

    SELECT pg_catalog.count(*),
           pg_catalog.count(*) FILTER (WHERE con.confdeltype <> 'r')
      INTO v_fk_count, v_bad_fk_count
      FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class rel ON con.conrelid = rel.oid
      JOIN pg_catalog.pg_namespace rel_ns ON rel.relnamespace = rel_ns.oid
      JOIN pg_catalog.pg_class frel ON con.confrelid = frel.oid
      JOIN pg_catalog.pg_namespace frel_ns ON frel.relnamespace = frel_ns.oid
     WHERE rel_ns.nspname = 'public'
       AND rel.relname IN ('incident_duplicate_links', 'incident_duplicate_scan_jobs')
       AND frel_ns.nspname = 'public'
       AND frel.relname = 'incidents'
       AND con.contype = 'f';

    IF v_fk_count <> 5 OR v_bad_fk_count > 0 THEN
        RAISE EXCEPTION 'Schema assertion failed: expected 5 ON DELETE RESTRICT foreign keys to incidents, found % (% non-RESTRICT)',
            v_fk_count, v_bad_fk_count;
    END IF;

    FOR v_rpc_req IN
        SELECT req.name, req.sig
          FROM (VALUES
              (
                  'citizen_incident_creation_rpc',
                  'public.citizen_incident_creation_rpc(character varying,character varying,text,double precision,double precision,character varying,character varying,character varying,text[],character varying,character varying)'
              ),
              (
                  'claim_duplicate_scan_jobs_rpc',
                  'public.claim_duplicate_scan_jobs_rpc(character varying,character varying,integer,integer)'
              ),
              (
                  'fetch_duplicate_candidates_rpc',
                  'public.fetch_duplicate_candidates_rpc(character varying,double precision,integer,text[],boolean,boolean,integer)'
              ),
              (
                  'record_duplicate_candidates_rpc',
                  'public.record_duplicate_candidates_rpc(character varying,character varying,jsonb,character varying)'
              ),
              (
                  'release_duplicate_scan_job_rpc',
                  'public.release_duplicate_scan_job_rpc(character varying,character varying,character varying,integer,boolean)'
              ),
              (
                  'reset_duplicate_scan_job_rpc',
                  'public.reset_duplicate_scan_job_rpc(character varying,character varying,character varying,text)'
              ),
              (
                  'review_incident_duplicate_link_rpc',
                  'public.review_incident_duplicate_link_rpc(character varying,character varying,character varying,character varying,text,character varying,character varying,character varying,text,boolean,integer)'
              )
          ) AS req(name, sig)
    LOOP
        v_proc_oid := pg_catalog.to_regprocedure(v_rpc_req.sig);
        IF v_proc_oid IS NULL THEN
            RAISE EXCEPTION 'Schema assertion failed: expected RPC signature missing: %', v_rpc_req.sig;
        END IF;

        SELECT pg_catalog.count(*)
          INTO v_overload_count
          FROM pg_catalog.pg_proc p
          JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.proname = v_rpc_req.name;

        IF v_overload_count <> 1 THEN
            RAISE EXCEPTION 'Schema assertion failed: expected 1 overload of %, found %',
                v_rpc_req.name, v_overload_count;
        END IF;

        SELECT p.prosecdef, p.proconfig
          INTO v_prosecdef, v_proconfig
          FROM pg_catalog.pg_proc p
         WHERE p.oid = v_proc_oid;

        IF NOT COALESCE(v_prosecdef, FALSE) THEN
            RAISE EXCEPTION 'Schema assertion failed: % must be SECURITY DEFINER', v_rpc_req.name;
        END IF;

        IF v_proconfig IS NULL OR NOT EXISTS (
            SELECT 1
              FROM pg_catalog.unnest(v_proconfig) AS cfg
             WHERE pg_catalog.replace(cfg, ' ', '') = 'search_path=pg_catalog,public,pg_temp'
        ) THEN
            RAISE EXCEPTION 'Schema assertion failed: % search_path not hardened to pg_catalog, public, pg_temp',
                v_rpc_req.name;
        END IF;

        IF pg_catalog.has_function_privilege('public', v_proc_oid, 'EXECUTE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: PUBLIC has EXECUTE on %', v_rpc_req.name;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'anon')
           AND pg_catalog.has_function_privilege('anon', v_proc_oid, 'EXECUTE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: anon has EXECUTE on %', v_rpc_req.name;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'authenticated')
           AND pg_catalog.has_function_privilege('authenticated', v_proc_oid, 'EXECUTE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: authenticated has EXECUTE on %', v_rpc_req.name;
        END IF;

        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'service_role')
           AND NOT pg_catalog.has_function_privilege('service_role', v_proc_oid, 'EXECUTE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: service_role lacks EXECUTE on %', v_rpc_req.name;
        END IF;
    END LOOP;

    FOREACH v_tbl IN ARRAY ARRAY['public.incident_duplicate_links', 'public.incident_duplicate_scan_jobs']
    LOOP
        IF pg_catalog.has_table_privilege('public', v_tbl, 'SELECT')
           OR pg_catalog.has_table_privilege('public', v_tbl, 'INSERT')
           OR pg_catalog.has_table_privilege('public', v_tbl, 'UPDATE')
           OR pg_catalog.has_table_privilege('public', v_tbl, 'DELETE')
           OR pg_catalog.has_table_privilege('public', v_tbl, 'TRUNCATE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: PUBLIC has table access on %', v_tbl;
        END IF;

        FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated']
        LOOP
            IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
                IF pg_catalog.has_table_privilege(v_role, v_tbl, 'SELECT')
                   OR pg_catalog.has_table_privilege(v_role, v_tbl, 'INSERT')
                   OR pg_catalog.has_table_privilege(v_role, v_tbl, 'UPDATE')
                   OR pg_catalog.has_table_privilege(v_role, v_tbl, 'DELETE')
                   OR pg_catalog.has_table_privilege(v_role, v_tbl, 'TRUNCATE') THEN
                    RAISE EXCEPTION 'Privilege assertion failed: % has table access on %', v_role, v_tbl;
                END IF;
            END IF;
        END LOOP;
    END LOOP;

    IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'service_role') THEN
        IF NOT pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'SELECT') THEN
            RAISE EXCEPTION 'Privilege assertion failed: service_role lacks SELECT on incident_duplicate_links';
        END IF;

        IF pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'INSERT')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'UPDATE')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'DELETE')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'TRUNCATE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: service_role has write access on incident_duplicate_links';
        END IF;

        IF pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'SELECT')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'INSERT')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'UPDATE')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'DELETE')
           OR pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'TRUNCATE') THEN
            RAISE EXCEPTION 'Privilege assertion failed: service_role has direct table access on incident_duplicate_scan_jobs';
        END IF;
    END IF;
END $verify_schema$;

NOTIFY pgrst, 'reload schema';

COMMIT;
