BEGIN;

-- =====================================================================
-- DRAIN-X Milestone 3 Production Rate Limiting & Abuse Protection
-- Canonical Migration File:
--   database/migrations/006_rate_limiting.sql
--
-- Security & Operational Architecture:
--   1. Table: public.api_rate_limits
--      - Primary key: rate_limit_key VARCHAR(64) (64-char lowercase hex HMAC-SHA256)
--      - Explicit CHECK constraints for valid keys, actions, window order, and counts.
--      - Avoids storing raw JWTs, IP addresses, tokens, or PII.
--      - Database time (pg_catalog.clock_timestamp()) guarantees tamper-proof window calculations.
--   2. Atomic Upsert & Concurrency Control:
--      - check_and_increment_rate_limit_rpc() uses single atomic INSERT ... ON CONFLICT DO UPDATE.
--      - Evaluates database clock_timestamp() after lock acquisition via subquery.
--      - Safe bounded probabilistic cleanup using ORDER BY window_end ASC + FOR UPDATE SKIP LOCKED
--        with an outer expiration recheck so newly reset active counters are never deleted.
--   3. Privilege Boundaries (Least Privilege matching Migration 005):
--      - RLS enabled on table.
--      - Direct table access REVOKED from PUBLIC, anon, authenticated, and service_role.
--      - RPC execution REVOKED from PUBLIC, anon, and authenticated; granted strictly to service_role.
-- =====================================================================

CREATE TABLE IF NOT EXISTS public.api_rate_limits (
    rate_limit_key VARCHAR(64) PRIMARY KEY,
    action VARCHAR(32) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_end TIMESTAMPTZ NOT NULL,
    request_count INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT chk_api_rate_limits_key_hex CHECK (rate_limit_key ~ '^[a-f0-9]{64}$'),
    CONSTRAINT chk_api_rate_limits_action_valid CHECK (action IN ('incident_create', 'photo_upload', 'photo_retrieve')),
    CONSTRAINT chk_api_rate_limits_window_order CHECK (window_end > window_start),
    CONSTRAINT chk_api_rate_limits_count_positive CHECK (request_count >= 1)
);

CREATE INDEX IF NOT EXISTS idx_api_rate_limits_window_end
    ON public.api_rate_limits (window_end);

ALTER TABLE public.api_rate_limits ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.api_rate_limits FROM PUBLIC, anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.check_and_increment_rate_limit_rpc(
    p_key_hash VARCHAR(64),
    p_action VARCHAR(32),
    p_limit INT,
    p_window_sec INT
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $function$
DECLARE
    v_window_interval INTERVAL;
    v_window_start TIMESTAMPTZ;
    v_window_end TIMESTAMPTZ;
    v_raw_count INT;
    v_now TIMESTAMPTZ;
    v_allowed BOOLEAN;
    v_current_count INT;
    v_remaining INT;
    v_reset_after INT;
    v_retry_after INT;
BEGIN
    IF p_key_hash IS NULL OR p_key_hash !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'Invalid rate limit key hash: must be 64 lowercase hex characters.'
            USING ERRCODE = '22023';
    END IF;
    IF p_action IS NULL OR p_action NOT IN ('incident_create', 'photo_upload', 'photo_retrieve') THEN
        RAISE EXCEPTION 'Invalid rate limit action.'
            USING ERRCODE = '22023';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100000 THEN
        RAISE EXCEPTION 'Invalid rate limit max requests: must be between 1 and 100000.'
            USING ERRCODE = '22023';
    END IF;
    IF p_window_sec IS NULL OR p_window_sec < 1 OR p_window_sec > 2592000 THEN
        RAISE EXCEPTION 'Invalid rate limit window seconds: must be between 1 and 2592000.'
            USING ERRCODE = '22023';
    END IF;

    v_window_interval := pg_catalog.make_interval(secs => p_window_sec);
    v_now := pg_catalog.clock_timestamp();

    INSERT INTO public.api_rate_limits (
        rate_limit_key, action, window_start, window_end, request_count, updated_at
    ) VALUES (
        p_key_hash, p_action, v_now, v_now + v_window_interval, 1, v_now
    )
    ON CONFLICT (rate_limit_key) DO UPDATE
    SET action = EXCLUDED.action,
        (window_start, window_end, request_count, updated_at) = (
            SELECT
                CASE
                    WHEN t.ts >= public.api_rate_limits.window_end THEN t.ts
                    ELSE public.api_rate_limits.window_start
                END,
                CASE
                    WHEN t.ts >= public.api_rate_limits.window_end THEN t.ts + v_window_interval
                    ELSE public.api_rate_limits.window_end
                END,
                CASE
                    WHEN t.ts >= public.api_rate_limits.window_end THEN 1
                    WHEN public.api_rate_limits.request_count < p_limit THEN public.api_rate_limits.request_count + 1
                    ELSE p_limit + 1
                END,
                t.ts
            FROM (VALUES (pg_catalog.clock_timestamp())) AS t(ts)
        )
    RETURNING window_start, window_end, request_count, updated_at
    INTO v_window_start, v_window_end, v_raw_count, v_now;

    IF v_raw_count <= p_limit THEN
        v_allowed := TRUE;
        v_current_count := v_raw_count;
        v_remaining := p_limit - v_current_count;
        v_reset_after := GREATEST(1, LEAST(p_window_sec, CEIL(EXTRACT(EPOCH FROM (v_window_end - v_now)))::INT));
        v_retry_after := 0;
    ELSE
        v_allowed := FALSE;
        v_current_count := p_limit;
        v_remaining := 0;
        v_reset_after := GREATEST(1, LEAST(p_window_sec, CEIL(EXTRACT(EPOCH FROM (v_window_end - v_now)))::INT));
        v_retry_after := v_reset_after;
    END IF;

    -- Bounded piggybacked cleanup: delete up to 50 expired records older than 1 hour.
    -- Uses ORDER BY window_end ASC + FOR UPDATE SKIP LOCKED + outer expiration recheck.
    IF pg_catalog.random() < 0.05 THEN
        DELETE FROM public.api_rate_limits
        WHERE rate_limit_key IN (
            SELECT rate_limit_key
            FROM public.api_rate_limits
            WHERE window_end < (v_now - INTERVAL '1 hour')
            ORDER BY window_end ASC
            LIMIT 50
            FOR UPDATE SKIP LOCKED
        )
        AND window_end < (v_now - INTERVAL '1 hour');
    END IF;

    RETURN jsonb_build_object(
        'allowed', v_allowed,
        'current_count', v_current_count,
        'limit', p_limit,
        'remaining', v_remaining,
        'reset_after_sec', v_reset_after,
        'retry_after_sec', v_retry_after
    );
END;
$function$;

REVOKE ALL ON FUNCTION public.check_and_increment_rate_limit_rpc(VARCHAR(64), VARCHAR(32), INT, INT)
FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.check_and_increment_rate_limit_rpc(VARCHAR(64), VARCHAR(32), INT, INT)
TO service_role;

COMMIT;
