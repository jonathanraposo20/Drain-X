BEGIN;

REVOKE EXECUTE ON FUNCTION public.municipal_incident_transaction_rpc(
    varchar, varchar, varchar, varchar, varchar, varchar, varchar,
    text, text, text, varchar, varchar, varchar, varchar, text, varchar
) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.municipal_incident_transaction_rpc(
    varchar, varchar, varchar, varchar, varchar, varchar, varchar,
    text, text, text, varchar, varchar, varchar, varchar, text, varchar
) TO service_role;

COMMIT;
