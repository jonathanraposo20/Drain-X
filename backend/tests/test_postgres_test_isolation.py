import pytest

from tests import test_duplicate_detection_postgres_live as dup_pg
from tests import test_migration_008_postgres_live as m008_pg


def test_database_url_fallback_is_never_used(monkeypatch):
    monkeypatch.delenv("DRAINX_TEST_POSTGRES_DSN", raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://postgres:secret@db.xhdtceqcnsheoskmuwsv.supabase.co:5432/postgres",
    )
    assert dup_pg.resolve_test_postgres_dsn() is None
    assert m008_pg.validate_disposable_postgres_dsn(None) is None


@pytest.mark.parametrize(
    "prod_dsn",
    [
        "postgresql://postgres:pass@db.xhdtceqcnsheoskmuwsv.supabase.co:5432/postgres",
        "postgresql://postgres.xhdtceqcnsheoskmuwsv:pass@aws-0-ap-south-1.pooler.supabase.com:6543/postgres",
        "postgresql://postgres:pass@some-other-project.supabase.co:5432/postgres",
        "host=db.example.supabase.co port=5432 dbname=postgres user=postgres",
        "postgresql://postgres:pass@localhost:5432/xhdtceqcnsheoskmuwsv",
    ],
)
def test_production_supabase_hosts_fail_closed(monkeypatch, prod_dsn):
    monkeypatch.setenv("DRAINX_TEST_POSTGRES_DSN", prod_dsn)
    with pytest.raises(RuntimeError):
        dup_pg.resolve_test_postgres_dsn()
    with pytest.raises(RuntimeError):
        m008_pg.validate_disposable_postgres_dsn(prod_dsn)


def test_open_pg_connection_fails_closed_on_supabase_host(monkeypatch):
    monkeypatch.setattr(
        dup_pg,
        "POSTGRES_DSN",
        "postgresql://postgres:pass@db.xhdtceqcnsheoskmuwsv.supabase.co:5432/postgres",
    )
    with pytest.raises(RuntimeError, match="Supabase|production"):
        dup_pg._open_pg_connection()

    monkeypatch.setattr(
        m008_pg,
        "TEST_POSTGRES_DSN",
        "postgresql://postgres:pass@aws-0-ap-south-1.pooler.supabase.com:5432/postgres",
    )
    with pytest.raises(RuntimeError, match="Supabase|production"):
        m008_pg._open_conn()


def test_disposable_local_dsn_is_accepted(monkeypatch):
    local_dsn = "postgresql://postgres:postgres@127.0.0.1:55432/drainx_test"
    monkeypatch.setenv("DRAINX_TEST_POSTGRES_DSN", local_dsn)
    assert dup_pg.resolve_test_postgres_dsn() == local_dsn
    assert m008_pg.validate_disposable_postgres_dsn(local_dsn) == local_dsn
