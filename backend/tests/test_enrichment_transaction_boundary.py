"""
SafeSOC — Enrichment Transaction Boundary Tests (Phase 4.7)
One invariant, asserted directly rather than inferred from code shape:

    NO DATABASE TRANSACTION IS OPEN WHILE AN EXTERNAL PROVIDER CALL
    IS IN FLIGHT.

Each test installs a fake provider that records `db.in_transaction()`
at the exact moment it is invoked. That is the observation that
matters — a mock asserting "the provider was called" would have passed
happily against the broken version, which held a Postgres backend
`idle in transaction` for the whole 13-23s of provider latency under
load.

These run against a real database where one is reachable (the Docker
suite) and skip otherwise, because the defect was a real
connection-lifecycle problem and a fake session cannot demonstrate its
absence.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select, text

from app.clients.abuseipdb import AbuseIPDBError
from app.clients.virustotal import VirusTotalError
from app.core.enums import TIProvider
from app.db.postgresql import worker_session_factory
from app.models.ti_cache import TICache
from app.schemas.log import TIResult
from app.services import enrichment


def _postgres_available() -> bool:
    async def _check() -> bool:
        try:
            async with worker_session_factory() as db:
                await db.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    try:
        return asyncio.run(_check())
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(), reason="no reachable PostgreSQL (integration test)"
)


def _indicator() -> str:
    """A unique documentation-range IP per test, so tests never share cache rows."""
    return f"203.0.113.{uuid.uuid4().int % 200 + 20}"


async def _clear(db, indicator: str) -> None:
    await db.execute(delete(TICache).where(TICache.indicator == indicator))
    await db.commit()


async def _seed_cache(db, indicator: str, provider: TIProvider, *, expired: bool, is_malicious: bool = False) -> None:
    expires_at = datetime.now(timezone.utc) + (timedelta(days=-1) if expired else timedelta(days=1))
    db.add(TICache(
        indicator=indicator, provider=provider,
        result=TIResult(source_ip=indicator, is_malicious=is_malicious, vt_total=7).model_dump(mode="json"),
        is_malicious=is_malicious, expires_at=expires_at,
    ))
    await db.commit()


class _ProviderProbe:
    """Records whether a transaction was open when the provider was called."""

    def __init__(self, db, result=None, error=None):
        self.db = db
        self.result = result
        self.error = error
        self.calls = 0
        self.in_transaction_during_call = None

    async def __call__(self, *args, **kwargs):
        self.calls += 1
        self.in_transaction_during_call = self.db.in_transaction()
        if self.error is not None:
            raise self.error
        return self.result


# ── Test 1 — cache hit ──────────────────────────────────────────────

@requires_postgres
def test_cache_hit_returns_cached_result_without_calling_the_provider(monkeypatch):
    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            await _seed_cache(db, indicator, TIProvider.VIRUSTOTAL, expired=False, is_malicious=True)
            await _seed_cache(db, indicator, TIProvider.ABUSEIPDB, expired=False)

            vt_probe = _ProviderProbe(db, result=TIResult())
            abuse_probe = _ProviderProbe(db, result=TIResult())
            monkeypatch.setattr(enrichment.virustotal, "lookup_ip", vt_probe)
            monkeypatch.setattr(enrichment.abuseipdb, "lookup_ip", abuse_probe)

            result = await enrichment.enrich_indicator(db, indicator)
            await _clear(db, indicator)
            return result, vt_probe.calls, abuse_probe.calls

    result, vt_calls, abuse_calls = asyncio.run(scenario())

    assert vt_calls == 0 and abuse_calls == 0, "a fresh cache entry must not reach the provider"
    assert result.is_malicious is True, "the cached verdict must be what comes back"


# ── Test 2 — cache miss: the boundary itself ────────────────────────

@requires_postgres
def test_no_transaction_is_open_while_the_provider_is_called():
    """The load-bearing test for this phase."""
    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            vt_probe = _ProviderProbe(db, result=TIResult(source_ip=indicator, vt_malicious=3, vt_total=90, is_malicious=True))
            abuse_probe = _ProviderProbe(db, result=TIResult(source_ip=indicator))
            enrichment.virustotal.lookup_ip = vt_probe
            enrichment.abuseipdb.lookup_ip = abuse_probe
            try:
                result = await enrichment.enrich_indicator(db, indicator)
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)

            persisted = (await db.execute(
                select(TICache).where(TICache.indicator == indicator, TICache.provider == TIProvider.VIRUSTOTAL)
            )).scalar_one_or_none()
            was_persisted = persisted is not None
            await _clear(db, indicator)
            return vt_probe, abuse_probe, result, was_persisted

    vt_probe, abuse_probe, result, was_persisted = asyncio.run(scenario())

    assert vt_probe.calls == 1, "a cache miss must reach the provider"
    assert vt_probe.in_transaction_during_call is False, "a transaction was open during the VirusTotal call"
    assert abuse_probe.in_transaction_during_call is False, "a transaction was open during the AbuseIPDB call"
    assert result.is_malicious is True
    assert was_persisted, "the provider result must be written to the cache"


# ── Tests 3, 4, 5 — failure, 401, timeout ───────────────────────────

@requires_postgres
@pytest.mark.parametrize(
    "error",
    [
        VirusTotalError("VirusTotal request failed: connection reset"),
        VirusTotalError("VirusTotal request failed: 401 Client Error: Unauthorized"),
        VirusTotalError("VirusTotal request failed: HTTPSConnectionPool read timed out"),
    ],
    ids=["provider_failure", "provider_401", "provider_timeout"],
)
def test_a_failing_provider_leaves_no_transaction_open_and_still_falls_back(error):
    """
    Every failure shape takes the same path: the transaction is already
    closed before the call, so nothing is left open however the provider
    fails — and the stale-cache fallback still works.
    """
    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            # An EXPIRED row: forces the provider call, and is what the
            # fallback should return when that call fails.
            await _seed_cache(db, indicator, TIProvider.VIRUSTOTAL, expired=True, is_malicious=True)

            vt_probe = _ProviderProbe(db, error=error)
            abuse_probe = _ProviderProbe(db, result=TIResult(source_ip=indicator))
            enrichment.virustotal.lookup_ip = vt_probe
            enrichment.abuseipdb.lookup_ip = abuse_probe
            try:
                result = await enrichment.enrich_indicator(db, indicator)
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)

            still_open = db.in_transaction()
            usable = (await db.execute(text("SELECT 1"))).scalar()
            await _clear(db, indicator)
            return vt_probe, result, still_open, usable

    vt_probe, result, still_open, usable = asyncio.run(scenario())

    assert vt_probe.calls == 1
    assert vt_probe.in_transaction_during_call is False, "a transaction was open during the failing provider call"
    assert result.is_malicious is True, "the stale cached verdict must still be used as fallback"
    assert usable == 1, "the caller's session must remain usable after a provider failure"
    assert still_open in (True, False)  # recorded for completeness; the invariant is about the call itself


@requires_postgres
def test_a_provider_failure_with_no_cache_at_all_returns_no_verdict():
    """Unchanged existing behaviour: nothing cached and the provider down means no opinion, not an exception."""
    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            vt_probe = _ProviderProbe(db, error=VirusTotalError("down"))
            abuse_probe = _ProviderProbe(db, error=AbuseIPDBError("down"))
            enrichment.virustotal.lookup_ip = vt_probe
            enrichment.abuseipdb.lookup_ip = abuse_probe
            try:
                result = await enrichment.enrich_indicator(db, indicator)
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)
            await _clear(db, indicator)
            return vt_probe, abuse_probe, result

    vt_probe, abuse_probe, result = asyncio.run(scenario())

    assert vt_probe.in_transaction_during_call is False
    assert abuse_probe.in_transaction_during_call is False
    assert result.is_malicious is False
    assert result.vt_total is None or result.vt_total == 0


# ── Test 6 — concurrent cache misses ────────────────────────────────

@requires_postgres
def test_concurrent_cache_misses_never_hold_a_transaction_across_the_provider():
    """
    Two enrichments in flight at once, each on its own session. This does
    NOT assert a single provider call: the existing architecture has no
    cache-miss deduplication (no advisory lock, no SELECT ... FOR UPDATE),
    so duplicate lookups are pre-existing behaviour and out of scope here.
    What must hold is that neither one pins a connection across its call.
    """
    indicator_a, indicator_b = _indicator(), _indicator()
    observations = []
    # One shared dispatcher, keyed by indicator: patching the module
    # attribute per-coroutine would have them overwrite each other and
    # observe the wrong session.
    sessions: dict[str, object] = {}

    async def dispatch(ip: str) -> TIResult:
        observations.append((ip, sessions[ip].in_transaction()))
        return TIResult(source_ip=ip, vt_total=1)

    async def one(indicator):
        async with worker_session_factory() as db:
            sessions[indicator] = db
            await _clear(db, indicator)
            await enrichment.enrich_indicator(db, indicator)
            await _clear(db, indicator)

    async def scenario():
        enrichment.virustotal.lookup_ip = dispatch
        enrichment.abuseipdb.lookup_ip = dispatch
        try:
            await asyncio.gather(one(indicator_a), one(indicator_b))
        finally:
            import importlib
            importlib.reload(enrichment.virustotal)
            importlib.reload(enrichment.abuseipdb)

    asyncio.run(scenario())
    observations = [in_txn for _, in_txn in observations]

    assert observations, "no provider calls were observed"
    assert all(seen is False for seen in observations), f"a transaction was open during a concurrent call: {observations}"


# ── Test 8 — session ownership ──────────────────────────────────────

@requires_postgres
def test_enrichment_does_not_close_the_callers_session():
    """
    Enrichment receives a caller-owned session. It may end the
    transaction (it has always committed on the cache-miss path — see
    _get_or_fetch's docstring), but it must never close the session or
    leave it unusable for the caller's remaining work.
    """
    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            enrichment.virustotal.lookup_ip = _ProviderProbe(db, result=TIResult(source_ip=indicator))
            enrichment.abuseipdb.lookup_ip = _ProviderProbe(db, result=TIResult(source_ip=indicator))
            try:
                await enrichment.enrich_indicator(db, indicator)
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)

            after = (await db.execute(text("SELECT 42"))).scalar()
            is_active = db.is_active
            await _clear(db, indicator)
            return after, is_active

    after, is_active = asyncio.run(scenario())

    assert after == 42, "the caller's session must still execute queries after enrichment"
    assert is_active, "the caller's session must still be active"


def test_a_non_ip_indicator_never_reaches_a_provider_or_the_database():
    """Unchanged behaviour, and it needs no database at all — so it runs everywhere."""

    async def scenario():
        class _ExplodingSession:
            async def execute(self, *args, **kwargs):
                raise AssertionError("a non-IP indicator must not touch the database")

            def in_transaction(self):
                return False

        return await enrichment.enrich_indicator(_ExplodingSession(), "not-an-ip.example.com")

    result = asyncio.run(scenario())

    assert result.is_malicious is False
    assert result.source_ip is None


# ── Test 7 — SOAR's automatic enrich_indicator action ───────────────

@requires_postgres
def test_the_soar_enrich_action_holds_no_transaction_across_the_provider():
    """
    SOAR's ENRICH_INDICATOR runs this same enrichment inside a session
    shared with the action's own state transitions, so a transaction
    held here would pin a connection for every automatic enrichment the
    platform performs. Exercises the real handler, not enrichment
    directly.
    """
    from app.services.soar_execution import _execute_enrich_indicator

    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            probe = _ProviderProbe(db, result=TIResult(source_ip=indicator, vt_malicious=2, vt_total=80, is_malicious=True))
            abuse = _ProviderProbe(db, result=TIResult(source_ip=indicator))
            enrichment.virustotal.lookup_ip = probe
            enrichment.abuseipdb.lookup_ip = abuse
            try:
                result = await _execute_enrich_indicator(
                    db, uuid.uuid4(), uuid.uuid4(), {"indicator": indicator}
                )
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)
            await _clear(db, indicator)
            return probe, result

    probe, result = asyncio.run(scenario())

    assert probe.in_transaction_during_call is False, "SOAR enrichment held a transaction across the provider call"
    assert result["success"] is True, "the action must still report success"
    assert result["is_malicious"] is True, "the provider verdict must reach the action result"
    assert result["indicator"] == indicator


@requires_postgres
def test_the_soar_enrich_action_still_succeeds_when_the_provider_is_down():
    """Existing semantics: a provider outage is not an action failure — it yields a verdict-free success."""
    from app.services.soar_execution import _execute_enrich_indicator

    indicator = _indicator()

    async def scenario():
        async with worker_session_factory() as db:
            await _clear(db, indicator)
            probe = _ProviderProbe(db, error=VirusTotalError("401 Client Error: Unauthorized"))
            enrichment.virustotal.lookup_ip = probe
            enrichment.abuseipdb.lookup_ip = _ProviderProbe(db, error=AbuseIPDBError("401 Client Error: Unauthorized"))
            try:
                result = await _execute_enrich_indicator(db, uuid.uuid4(), uuid.uuid4(), {"indicator": indicator})
            finally:
                import importlib
                importlib.reload(enrichment.virustotal)
                importlib.reload(enrichment.abuseipdb)
            await _clear(db, indicator)
            return probe, result

    probe, result = asyncio.run(scenario())

    assert probe.in_transaction_during_call is False
    assert result["success"] is True
    assert result["is_malicious"] is False


def test_the_soar_enrich_action_rejects_a_missing_indicator():
    """Validation is unchanged by the refactor — no indicator, no lookup, no database access."""
    from app.services.soar_execution import _execute_enrich_indicator

    class _ExplodingSession:
        async def execute(self, *args, **kwargs):
            raise AssertionError("validation must short-circuit before any database access")

    result = asyncio.run(_execute_enrich_indicator(_ExplodingSession(), uuid.uuid4(), uuid.uuid4(), {}))

    assert result["success"] is False
