"""Shared safety guard for live PostgreSQL integration-test DSNs.

Live integration tests are permitted to connect only to loopback PostgreSQL.
Use a separately reviewed mechanism if a remote disposable test database is ever
required; never broaden this allowlist just to make CI pass.
"""
import ipaddress
import os
import re
import urllib.parse


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_loopback_host(host: str) -> bool:
    normalized = _normalize_host(host)
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _extract_hosts(dsn: str) -> list[str]:
    parsed = urllib.parse.urlparse(dsn)
    if parsed.scheme:
        if parsed.scheme not in ("postgres", "postgresql"):
            raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: expected a PostgreSQL DSN.")
        try:
            authority_host = parsed.hostname or ""
        except ValueError as exc:
            raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: malformed connection URI.") from exc

        # libpq URI query parameters can override the authority host. Validate both
        # values and reject multi-host forms instead of trusting only parsed.hostname.
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        query_hosts = query.get("host", [])
        query_hostaddrs = query.get("hostaddr", [])
        if len(query_hosts) > 1 or len(query_hostaddrs) > 1:
            raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: multiple connection host overrides are not allowed.")
        hosts = [authority_host] if authority_host else []
        if query_hosts:
            hosts.append(query_hosts[0])
        # libpq hostaddr bypasses DNS resolution and determines the actual socket
        # destination even when host=localhost is supplied.
        if query_hostaddrs:
            hosts.append(query_hostaddrs[0])
    else:
        # Reject repeated host parameters and comma-separated host lists. The
        # keyword form accepts quoted values, including whitespace in hostnames.
        def _keyword_values(name: str) -> list[str]:
            pattern = rf"(?:^|\s){name}\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))"
            found = list(re.finditer(pattern, dsn, re.IGNORECASE))
            return [next((part for part in match.groups() if part is not None), "") for match in found]

        keyword_hosts = _keyword_values("host")
        keyword_hostaddrs = _keyword_values("hostaddr")
        if len(keyword_hosts) != 1 or len(keyword_hostaddrs) > 1:
            raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: exactly one target host is required.")
        hosts = keyword_hosts + keyword_hostaddrs

    normalized_hosts = [_normalize_host(host) for host in hosts]
    if not normalized_hosts or any(not host or "," in host for host in normalized_hosts):
        raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: unable to determine one target host.")
    return normalized_hosts


def validate_disposable_postgres_dsn(dsn: str | None) -> str | None:
    """Accept only localhost or IP loopback targets; reject every remote or ambiguous target."""
    if not dsn or not dsn.strip():
        return None
    cleaned = dsn.strip()
    hosts = _extract_hosts(cleaned)

    # Supabase project references are 20 lowercase alphanumeric characters.
    # Reject them anywhere in the DSN, even when a misleading host is loopback.
    if re.search(r"(?<![a-z0-9])[a-z0-9]{20}(?![a-z0-9])", cleaned.lower()):
        raise RuntimeError(
            "Refusing PostgreSQL test DSN containing a production-style project identifier."
        )

    if any(not _is_loopback_host(host) for host in hosts):
        raise RuntimeError(
            "Refusing live PostgreSQL tests against a non-loopback host. "
            "Use a disposable local PostgreSQL instance via DRAINX_TEST_POSTGRES_DSN."
        )
    return cleaned


def resolve_test_postgres_dsn() -> str | None:
    """Read only DRAINX_TEST_POSTGRES_DSN; never fall back to DATABASE_URL."""
    return validate_disposable_postgres_dsn(os.getenv("DRAINX_TEST_POSTGRES_DSN"))
