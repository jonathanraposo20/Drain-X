"""
DRAIN-X Persistence Circuit Breaker.

Batch 2C.3: Circuit breaker and reconnection management for transient
Supabase / PostgREST persistence failures.

States:
- CLOSED: Normal operation; persistence calls proceed.
- OPEN: Tripped due to transient errors; persistence calls fast-fail.
- HALF_OPEN: Backoff expired; exactly one probe attempt permitted.

Timing & Backoff:
- Initial backoff: 1.0 second.
- Exponential increase: backoff_multiplier = 2.0.
- Maximum backoff: 30.0 seconds.
- Jitter: bounded random variation to avoid thundering-herd synchronization.

Thread Safety:
- All state transitions and probe acquisitions are protected by a threading.RLock.
- Exactly one caller can enter HALF_OPEN at a time; concurrent callers fast-fail.
"""

from enum import Enum
import logging
import random
import threading
import time
from typing import Any, Optional
import httpx

from app.core.config import settings
from app.services.persistence_repository import (
    StorageError,
    StorageNotConfiguredError,
    DirectiveAuditConflictError,
)

logger = logging.getLogger("drainx.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenError(StorageError):
    """Raised when persistence calls fast-fail because the circuit breaker is OPEN or HALF_OPEN."""

    def __init__(
        self,
        message: str = "Persistence circuit breaker is OPEN; fast-failing.",
        remaining_backoff: float = 0.0,
    ):
        super().__init__(message)
        self.remaining_backoff = remaining_backoff


def is_transient_error(exc: Exception) -> bool:
    """
    Determines whether an exception represents a transient failure that should
    trigger or maintain the circuit breaker.

    Transient:
    - Network connectivity failures, socket errors, connection resets.
    - Timeouts (connect, read, write, pool).
    - Server-side 5xx HTTP errors (500 Internal Server Error, 502 Bad Gateway,
      503 Service Unavailable, 504 Gateway Timeout).
    - Database server connection / admin shutdown errors (sqlstate 08xxx, 57P01, 40001).

    Permanent (MUST NOT trip or advance circuit breaker):
    - Missing configuration (StorageNotConfiguredError).
    - Security / authentication / role errors (StorageSecurityError, 401, 403).
    - Client / payload / schema validation errors (ValueError, TypeError, 400, 422).
    - Immutability conflicts (DirectiveAuditConflictError, 409).
    """
    if exc is None:
        return False

    # 1. Explicit permanent domain exceptions
    if isinstance(exc, (StorageNotConfiguredError, DirectiveAuditConflictError)):
        return False

    if exc.__class__.__name__ == "StorageSecurityError":
        return False

    if isinstance(exc, (ValueError, TypeError, KeyError, AssertionError)):
        return False

    # 2. Check inner cause / context recursively
    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    if cause is not None and cause is not exc:
        if isinstance(cause, (StorageNotConfiguredError, DirectiveAuditConflictError)):
            return False
        if cause.__class__.__name__ == "StorageSecurityError":
            return False
        if isinstance(cause, (ValueError, TypeError, KeyError, AssertionError)):
            return False

    # 3. Direct httpx network / timeout errors
    if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError)):
        return True

    # 4. Standard Python socket / connection / timeout errors
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True

    # 5. httpx HTTPStatusError
    if isinstance(exc, httpx.HTTPStatusError):
        code = getattr(exc.response, "status_code", 0) if exc.response is not None else 0
        if code >= 500:
            return True
        if 400 <= code < 500:
            return False

    # Check cause for network / timeout / HTTP status
    if cause is not None:
        if isinstance(cause, (httpx.TimeoutException, httpx.NetworkError, ConnectionError, TimeoutError)):
            return True
        if isinstance(cause, httpx.HTTPStatusError):
            code = getattr(cause.response, "status_code", 0) if cause.response is not None else 0
            if code >= 500:
                return True
            if 400 <= code < 500:
                return False

    # 6. StorageError message and sqlstate inspection
    if isinstance(exc, StorageError):
        msg = str(exc).lower()

        # Permanent status / text markers
        permanent_tokens = [
            "400", "401", "403", "404", "409", "422",
            "unauthorized", "forbidden", "permission",
            "misconfigured", "credentials",
            "invalid payload", "invalid argument", "invalid schema",
            "invalid request", "invalid data", "invalid column", "invalid field",
            "conflict", "diverges", "malformed",
        ]
        for token in permanent_tokens:
            if f"http {token}" in msg or f"status {token}" in msg or token in msg:
                return False

        # Transient status / text markers
        transient_tokens = [
            "http 5", "500", "502", "503", "504",
            "timeout", "timed out", "connection", "connect",
            "network", "unavailable", "server error", "gateway",
            "reset by peer", "broken pipe", "closed prematurely",
        ]
        for token in transient_tokens:
            if token in msg:
                return True

        # Check PostgreSQL SQLSTATE
        sqlstate = getattr(exc, "sqlstate", None)
        if sqlstate:
            if sqlstate.startswith("08") or sqlstate in ("57P01", "40001", "40P01"):
                return True
            return False

    return False


class PersistenceCircuitBreaker:
    """
    Thread-safe circuit breaker with exponential backoff and jitter
    for persistence operations.
    """

    def __init__(
        self,
        initial_backoff: Optional[float] = None,
        max_backoff: Optional[float] = None,
        backoff_multiplier: Optional[float] = None,
        jitter_ratio: Optional[float] = None,
    ):
        self._lock = threading.RLock()
        self.initial_backoff = (
            initial_backoff
            if initial_backoff is not None
            else getattr(settings, "PERSISTENCE_CIRCUIT_BREAKER_INITIAL_BACKOFF_SEC", 1.0)
        )
        self.max_backoff = (
            max_backoff
            if max_backoff is not None
            else getattr(settings, "PERSISTENCE_CIRCUIT_BREAKER_MAX_BACKOFF_SEC", 30.0)
        )
        self.backoff_multiplier = (
            backoff_multiplier
            if backoff_multiplier is not None
            else getattr(settings, "PERSISTENCE_CIRCUIT_BREAKER_BACKOFF_MULTIPLIER", 2.0)
        )
        self.jitter_ratio = (
            jitter_ratio
            if jitter_ratio is not None
            else getattr(settings, "PERSISTENCE_CIRCUIT_BREAKER_JITTER_RATIO", 0.1)
        )

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._last_failure_time: Optional[float] = None
        self._next_attempt_time: float = 0.0
        self._half_open_in_flight: bool = False
        self._current_backoff: float = 0.0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            # Check if an OPEN state has expired and is eligible for probe
            if self._state == CircuitState.OPEN and time.monotonic() >= self._next_attempt_time:
                return CircuitState.HALF_OPEN
            return self._state

    @property
    def failure_count(self) -> int:
        with self._lock:
            return self._failure_count

    @property
    def current_backoff(self) -> float:
        with self._lock:
            return self._current_backoff

    def calculate_backoff(self, failure_count: int, apply_jitter: bool = True) -> float:
        """
        Calculates exponential backoff for failure_count bounded by max_backoff.
        Optionally applies jitter bounded within [raw * (1 - jitter), min(max_backoff, raw * (1 + jitter))].
        """
        if failure_count <= 0:
            return 0.0
        raw = min(
            self.initial_backoff * (self.backoff_multiplier ** max(0, failure_count - 1)),
            self.max_backoff,
        )
        if not apply_jitter or self.jitter_ratio <= 0.0:
            return raw
        low = raw * (1.0 - self.jitter_ratio)
        high = min(self.max_backoff, raw * (1.0 + self.jitter_ratio))
        # Ensure low does not exceed high
        low = min(low, high)
        return random.uniform(low, high)

    def acquire_execution_permission(self) -> bool:
        """
        Requests permission to execute a persistence call.
        - In CLOSED state: returns True.
        - In OPEN state:
            - If backoff has expired: transitions to HALF_OPEN, grants permission to
              EXACTLY ONE caller, and returns True.
            - If backoff has not expired: returns False (fast-fail).
        - In HALF_OPEN state:
            - A probe is already in-flight; returns False (fast-fail).
        """
        with self._lock:
            now = time.monotonic()
            if self._state == CircuitState.CLOSED:
                return True
            elif self._state == CircuitState.OPEN:
                if now >= self._next_attempt_time:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_in_flight = True
                    logger.info("Circuit breaker transitioning OPEN -> HALF_OPEN (probing persistence).")
                    return True
                return False
            elif self._state == CircuitState.HALF_OPEN:
                if not self._half_open_in_flight:
                    self._half_open_in_flight = True
                    return True
                # Exactly one probe allowed at a time
                return False
            return False

    def release_execution_permission(self) -> None:
        """
        Releases an acquired probe permission without recording success or failure.
        Used when an acquired probe cannot be exercised (e.g. empty outbox, pre-flight check,
        or task cancellation).
        """
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_in_flight = False

    def record_success(self) -> None:
        """
        Records a successful persistence call.
        Resets circuit state to CLOSED, failure count to 0, and clears backoff.
        """
        with self._lock:
            prev_state = self._state
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_in_flight = False
            self._current_backoff = 0.0
            self._next_attempt_time = 0.0
            if prev_state != CircuitState.CLOSED:
                logger.info("Persistence circuit breaker recovered: state reset to CLOSED.")

    def record_failure(self, exc: Exception) -> bool:
        """
        Records a failed persistence call.
        - If the error is transient: increments failure count, calculates exponential
          backoff with jitter, transitions state to OPEN, and returns True.
        - If the error is permanent: does NOT increment failure count, does not trip
          breaker, and returns False.
        """
        with self._lock:
            if not is_transient_error(exc):
                # Permanent error: do NOT trip breaker
                if self._state == CircuitState.HALF_OPEN:
                    self._half_open_in_flight = False
                    self._state = CircuitState.OPEN
                logger.debug(
                    "Circuit breaker ignored non-transient error (%s): %s",
                    exc.__class__.__name__,
                    exc,
                )
                return False

            self._failure_count += 1
            now = time.monotonic()
            self._last_failure_time = now
            backoff = self.calculate_backoff(self._failure_count, apply_jitter=True)
            self._current_backoff = backoff
            self._next_attempt_time = now + backoff
            prev_state = self._state
            self._state = CircuitState.OPEN
            self._half_open_in_flight = False
            logger.warning(
                "Persistence circuit breaker tripped to OPEN (failures=%d, backoff=%.2fs, error=%s): %s",
                self._failure_count,
                backoff,
                exc.__class__.__name__,
                exc,
            )
            return True

    def get_remaining_backoff(self) -> float:
        """Returns seconds remaining before a recovery probe is allowed."""
        with self._lock:
            if self._state != CircuitState.OPEN:
                return 0.0
            rem = self._next_attempt_time - time.monotonic()
            return max(0.0, rem)

    def reset(self) -> None:
        """Resets the circuit breaker completely (for testing or manual intervention)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = None
            self._next_attempt_time = 0.0
            self._half_open_in_flight = False
            self._current_backoff = 0.0


# Shared singleton instance
persistence_circuit_breaker = PersistenceCircuitBreaker()
