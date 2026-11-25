"""Shared safety guard for live PostgreSQL integration-test DSNs.

Live integration tests are permitted to connect only to loopback PostgreSQL.
Use a separately reviewed mechanism if a remote disposable test database is ever
required; never broaden this allowlist just to make CI pass.
"""
import ipaddress
import os
import re
import urllib.parse


def _extract_host(dsn: str) -> str:
    parsed = urllib.parse.urlparse(dsn)
    if parsed.scheme:
        if parsed.scheme not in ("postgres", "postgresql"):
            raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: expected a PostgreSQL DSN.")
        host = parsed.hostname or ""
    else:
        match = re.search(
            r"(?:^|\s)host\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))",
            dsn,
            re.IGNORECASE,
        )
        host = next((part for part in match.groups() if part is not None), "") if match else ""
    host = host.strip().lower().rstrip(".")
    if not host or "," in host:
        raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: unable to determine one target host.")
    return host


def validate_disposable_postgres_dsn(dsn: str | None) -> str | None:
    """Accept only localhost or an IP address explicitly classified as loopback."""
    if not dsn or not dsn.strip():
        return None
    cleaned = dsn.strip()
    host = _extract_host(cleaned)
    # Supabase project references are 20 lowercase alphanumeric characters.
    # Reject them anywhere in the DSN, even when a misleading host is loopback.
    if re.search(r"(?<![a-z0-9])[a-z0-9]{20}(?![a-z0-9])", cleaned.lower()):
        raise RuntimeError(
            "Refusing PostgreSQL test DSN containing a production-style project identifier."
        )
    if host == "localhost":
        return cleaned
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeError(
            "Refusing live PostgreSQL tests against a non-loopback host. "
            "Use a disposable local PostgreSQL instance via DRAINX_TEST_POSTGRES_DSN."
        ) from exc
    if not address.is_loopback:
        raise RuntimeError(
            "Refusing live PostgreSQL tests against a non-loopback host. "
            "Use a disposable local PostgreSQL instance via DRAINX_TEST_POSTGRES_DSN."
        )
    return cleaned


def resolve_test_postgres_dsn() -> str | None:
    """Read only DRAINX_TEST_POSTGRES_DSN; never fall back to DATABASE_URL."""
    return validate_disposable_postgres_dsn(os.getenv("DRAINX_TEST_POSTGRES_DSN"))
