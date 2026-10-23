"""
SafeSOC — Investigate Chat Grounding Tests
The chat's tools honour the filters the resolver extracts, return the
counts and context an answer needs, and the prompt tells the model what
was searched and what the fields mean. Each case here is a confidently
wrong live answer this fixes:

- "anything suspicious today?"  -> only failed logins were searched
- "was the attack successful?"  -> successes were never searched
- "who's brute forcing us?"     -> the TARGETED account named as attacker
- "any active attack chains?"   -> incidents carried no category/hosts

Tool tests stub search_alerts / list_incidents; search_alerts' own query
shape is tested against a fake client, and its new features (IP on
either side, bounded window, severity sort, counts) also against a real
OpenSearch when one is reachable (throwaway index, random tenants).
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.clients import ollama
from app.core.enums import CorrelationPattern, Intent, IncidentStatus, QueryResolution, UserRole
from app.db import opensearch
from app.db.opensearch import search_alerts
from app.db.postgresql import get_db
from app.main import app
from app.mcp.tools import TOOLS, AlertListOutput
from app.models.incident import Incident
from app.routers.v1.investigate import _build_prompt
from app.services import investigation
from app.services.investigation import commit_context, resolve_query
from tests.test_investigate_resolution import CONVERSATION, KNOWN, NOW
from tests.test_investigation import _FakeRedisClient

TENANT = uuid.uuid4()


def _search_mock(result=None, by_action=None):
    """A search_alerts stub. by_action maps an action filter to its result."""
    default = result or {"total": 0, "alerts": [], "counts": {}}

    async def fake(**kwargs):
        if by_action is not None and kwargs.get("action") in by_action:
            return by_action[kwargs["action"]]
        return default

    return AsyncMock(side_effect=fake)


def _incident(status=IncidentStatus.OPEN, category=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, alert_ids=("a1", "a2")):
    now = datetime.now(timezone.utc)
    return Incident(
        id=uuid.uuid4(), tenant_id=TENANT, status=status, category=category, confidence=0.64,
        alert_ids=list(alert_ids), tags=[], created_at=now, updated_at=now,
    )


@pytest.fixture(autouse=True)
def _no_incidents(monkeypatch):
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=([], 0)))


# ── 1. Filters reach search_alerts, tenant-scoped ────────────────────

@pytest.mark.asyncio
async def test_auth_failures_passes_user_and_window_and_counts_origin_targets_hosts(monkeypatch):
    search = _search_mock({"total": 6, "alerts": [], "counts": {
        "source_ip": {"203.0.113.25": 6}, "user": {"jane.smith": 6, "unknown": 2}, "host_id": {"WIN10-FIN-07": 6},
    }})
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)
    window = {"start": "2026-10-21T00:00:00Z", "end": "2026-10-22T00:00:00Z", "timerange_hours": 48}

    result = await TOOLS[Intent.AUTH_FAILURES].call(None, TENANT, {"host_id": "WIN10-FIN-07", "user": "jane.smith", **window})

    kwargs = search.call_args.kwargs
    assert kwargs["tenant_id"] == str(TENANT)
    assert (kwargs["action"], kwargs["host_id"], kwargs["user"]) == ("failed_login", "WIN10-FIN-07", "jane.smith")
    assert (kwargs["start"], kwargs["end"]) == (window["start"], window["end"])
    assert set(kwargs["aggregate_by"]) == {"source_ip", "user", "host_id", "severity"}
    assert result.counts["Source IPs (where the activity came from)"] == {"203.0.113.25": 6}
    assert result.counts["Accounts targeted or used"] == {"jane.smith": 6}  # "unknown" placeholder dropped
    assert result.scope == (
        "Searched failed logins for jane.smith on WIN10-FIN-07 between 21 Oct 2026 00:00 UTC "
        "and 22 Oct 2026 00:00 UTC."
    )


@pytest.mark.asyncio
async def test_top_alerts_passes_every_filter_sorts_by_severity_and_counts(monkeypatch):
    search = _search_mock({"total": 3, "alerts": [], "counts": {"severity": {"critical": 1}, "log_type": {"privilege": 1}}})
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)
    params = {"severity": "critical", "host_id": "UBUNTU-WEB-01", "log_type": "privilege", "action": "privilege_change",
              "user": "bob.admin", "start": "2026-10-22T00:00:00Z"}

    result = await TOOLS[Intent.TOP_ALERTS].call(None, TENANT, params)

    kwargs = search.call_args.kwargs
    assert kwargs["tenant_id"] == str(TENANT)
    for key, value in params.items():
        assert kwargs[key] == value
    assert kwargs["sort_by_severity"] is True
    assert set(kwargs["aggregate_by"]) == {"severity", "log_type", "host_id", "user"}
    assert result.counts == {"Severity": {"critical": 1}, "Log types": {"privilege": 1}}


@pytest.mark.asyncio
async def test_ip_activity_matches_source_or_destination_and_counts(monkeypatch):
    search = _search_mock()
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)

    await TOOLS[Intent.IP_ACTIVITY].call(None, TENANT, {"ip": "203.0.113.25"})

    kwargs = search.call_args.kwargs
    assert (kwargs["tenant_id"], kwargs["ip"]) == (str(TENANT), "203.0.113.25")
    assert set(kwargs["aggregate_by"]) == {"host_id", "user", "action", "severity"}


@pytest.mark.asyncio
async def test_user_activity_covers_every_alert_type_with_counts(monkeypatch):
    search = _search_mock()
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)

    await TOOLS[Intent.USER_ACTIVITY].call(None, TENANT, {"user": "jane.smith"})

    kwargs = search.call_args.kwargs
    assert (kwargs["tenant_id"], kwargs["user"]) == (str(TENANT), "jane.smith")
    assert "action" not in kwargs
    assert set(kwargs["aggregate_by"]) == {"action", "host_id", "severity", "source_ip"}


@pytest.mark.asyncio
async def test_risky_endpoints_limit_is_optional_and_capped(monkeypatch):
    from app.mcp.tools import RiskyEndpointsInput

    assert RiskyEndpointsInput().limit is None  # not asked: the tool shows its default 10
    with pytest.raises(Exception):
        RiskyEndpointsInput(limit=500)


# ── 2. search_alerts query shape ─────────────────────────────────────

class _Capture:
    def __init__(self, aggregations=None):
        self.body = None
        self.aggregations = aggregations or {}

    def search(self, index, body):
        self.body = body
        return {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": self.aggregations}


@pytest.mark.asyncio
async def test_search_alerts_ip_matches_source_or_destination(monkeypatch):
    client = _Capture()
    monkeypatch.setattr(opensearch, "get_client", lambda: client)

    await search_alerts(tenant_id="t", ip="203.0.113.25")

    must = client.body["query"]["bool"]["must"]
    assert {"term": {"tenant_id": "t"}} in must
    assert {"bool": {"should": [{"term": {"source_ip": "203.0.113.25"}}, {"term": {"destination_ip": "203.0.113.25"}}],
                     "minimum_should_match": 1}} in must


@pytest.mark.asyncio
async def test_search_alerts_yesterday_is_a_bounded_window(monkeypatch):
    client = _Capture()
    monkeypatch.setattr(opensearch, "get_client", lambda: client)

    await search_alerts(tenant_id="t", timerange_hours=48, start="2026-10-21T00:00:00Z", end="2026-10-22T00:00:00Z")

    assert client.body["query"]["bool"]["filter"] == [
        {"range": {"timestamp": {"gte": "2026-10-21T00:00:00Z", "lt": "2026-10-22T00:00:00Z"}}}
    ]


@pytest.mark.asyncio
async def test_search_alerts_severity_sort_and_counts(monkeypatch):
    client = _Capture({"by_severity": {"buckets": [{"key": "critical", "doc_count": 2}]}})
    monkeypatch.setattr(opensearch, "get_client", lambda: client)

    result = await search_alerts(tenant_id="t", sort_by_severity=True, aggregate_by=["severity", "not_a_field"])

    assert "_script" in client.body["sort"][0]
    assert client.body["sort"][1] == {"timestamp": {"order": "desc"}}
    assert set(client.body["aggs"]) == {"by_severity"}  # unknown fields are never aggregated
    assert result["counts"] == {"severity": {"critical": 2}}


@pytest.mark.asyncio
async def test_search_alerts_supports_a_counts_only_query(monkeypatch):
    """Regression (found running the overview against live data): size=0 divided by zero computing pages."""
    client = _Capture({"by_log_type": {"buckets": [{"key": "privilege", "doc_count": 1}]}})
    monkeypatch.setattr(opensearch, "get_client", lambda: client)

    result = await search_alerts(tenant_id="t", size=0, aggregate_by=["log_type"])

    assert result["pages"] == 0
    assert result["counts"] == {"log_type": {"privilege": 1}}


@pytest.mark.asyncio
async def test_resolved_yesterday_reaches_the_tool_as_a_bounded_window(monkeypatch):
    fake = _FakeRedisClient()
    monkeypatch.setattr(investigation, "get_client", lambda: fake)
    await commit_context("t", "s", Intent.AUTH_FAILURES, {"host_id": "WIN10-FIN-07"})
    search = _search_mock()
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)

    resolution = await resolve_query("t", "s", "what about yesterday?", KNOWN, now=NOW)
    await TOOLS[resolution.intent].call(None, TENANT, resolution.params)

    kwargs = search.call_args.kwargs
    assert (kwargs["start"], kwargs["end"]) == ("2026-10-21T00:00:00Z", "2026-10-22T00:00:00Z")
    assert kwargs["host_id"] == "WIN10-FIN-07"


# ── 3. Endpoint snapshot: every alert type, success after failures ───

def _alert(action, minute, ip="203.0.113.25", user="jane.smith", host="UBUNTU-WEB-01"):
    ts = (datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)).isoformat()
    return {"alert_id": f"{action}-{minute}", "action": action, "timestamp": ts, "source_ip": ip, "user": user, "host_id": host}


@pytest.mark.asyncio
async def test_snapshot_reports_a_login_success_after_failures(monkeypatch):
    failures = [_alert("failed_login", m) for m in range(5)]
    success = [_alert("login_success", 7)]
    search = _search_mock(
        {"total": 6, "alerts": failures + success, "counts": {"action": {"failed_login": 5, "login_success": 1}}},
        by_action={"failed_login": {"total": 5, "alerts": failures}, "login_success": {"total": 1, "alerts": success}},
    )
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, TENANT, {"host_id": "UBUNTU-WEB-01"})

    host_wide = [c.kwargs for c in search.call_args_list if "action" not in c.kwargs]
    assert host_wide and host_wide[0]["host_id"] == "UBUNTU-WEB-01"  # every alert type, not only failures
    assert all(c.kwargs["tenant_id"] == str(TENANT) for c in search.call_args_list)
    assert result.successful_login_after_failures is True
    assert result.same_source_success_after_failures is True
    assert result.logins_after_failures == [{
        "source_ip": "203.0.113.25", "user": "jane.smith", "success_at": success[0]["timestamp"],
        "failed_attempts_before": 5, "failed_attempts_from_same_source": 5,
    }]
    assert result.counts["Activity types"] == {"failed_login": 5, "login_success": 1}


@pytest.mark.asyncio
async def test_snapshot_ignores_a_success_before_any_failure(monkeypatch):
    failures = [_alert("failed_login", m) for m in range(3)]
    early = _alert("login_success", -5)
    monkeypatch.setattr("app.mcp.tools.search_alerts", _search_mock(
        by_action={"failed_login": {"total": 3, "alerts": failures}, "login_success": {"total": 1, "alerts": [early]}},
    ))
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, TENANT, {"host_id": "UBUNTU-WEB-01"})

    assert result.successful_login_after_failures is False
    assert result.logins_after_failures == []


@pytest.mark.asyncio
async def test_snapshot_reports_a_host_level_success_even_from_a_rotated_ip(monkeypatch):
    """
    Brute force often rotates source IPs (the demo data does too), so the
    host-level sequence is the headline — like the correlation engine's
    successful_compromise pattern — and same-source is a separate flag.
    """
    failures = [_alert("failed_login", m, ip=f"198.51.100.{m}") for m in range(6)]
    success = _alert("login_success", 7, ip="203.0.113.99")
    monkeypatch.setattr("app.mcp.tools.search_alerts", _search_mock(
        by_action={"failed_login": {"total": 6, "alerts": failures}, "login_success": {"total": 1, "alerts": [success]}},
    ))
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, TENANT, {"host_id": "UBUNTU-WEB-01"})

    assert result.successful_login_after_failures is True
    assert result.same_source_success_after_failures is False
    assert result.logins_after_failures[0]["failed_attempts_before"] == 6


@pytest.mark.asyncio
async def test_snapshot_lists_only_this_hosts_active_incidents(monkeypatch, _mock_incident_summary_lookup):
    on_host = _incident(alert_ids=("a1",))
    elsewhere = _incident(alert_ids=("b1",))
    closed = _incident(status=IncidentStatus.RESOLVED, alert_ids=("a2",))
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=([on_host, elsewhere, closed], 3)))
    _mock_incident_summary_lookup.return_value = [
        {"alert_id": "a1", "host_id": "UBUNTU-WEB-01", "severity": "high"},
        {"alert_id": "a2", "host_id": "UBUNTU-WEB-01", "severity": "low"},
        {"alert_id": "b1", "host_id": "WIN10-FIN-07", "severity": "medium"},
    ]
    monkeypatch.setattr("app.mcp.tools.search_alerts", _search_mock())
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, TENANT, {"host_id": "UBUNTU-WEB-01"})

    assert [i["id"] for i in result.open_incidents] == [str(on_host.id)]
    assert result.open_incidents[0]["category_label"] == "Credential brute force"
    assert result.open_incidents[0]["severity"] == "high"


# ── 4. Attack chains carry what the answer needs ─────────────────────

@pytest.mark.asyncio
async def test_attack_chain_items_include_category_hosts_severity_confidence_mitre(monkeypatch, _mock_incident_summary_lookup):
    incidents = [_incident(), _incident(category=CorrelationPattern.SUCCESSFUL_COMPROMISE, alert_ids=("c1",))]
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=(incidents, 2)))
    _mock_incident_summary_lookup.return_value = [
        {"alert_id": "a1", "host_id": "WIN10-FIN-07", "severity": "medium", "mitre_technique": "T1110"},
        {"alert_id": "a2", "host_id": "WIN10-FIN-07", "severity": "high"},
        {"alert_id": "c1", "host_id": "UBUNTU-WEB-01", "severity": "critical"},
    ]

    result = await TOOLS[Intent.ATTACK_CHAIN_STATUS].call(None, TENANT, {})

    first = result.incidents[0]
    assert first["category"] == "credential_brute_force"
    assert first["category_label"] == "Credential brute force"
    assert first["hosts"] == ["WIN10-FIN-07"]
    assert first["severity"] == "high"
    assert first["confidence"] == 0.64
    assert "T1110" in first["mitre_techniques"]
    assert first["status"] == "open" and first["alert_count"] == 2
    assert result.incidents[1]["category_label"] == "Successful compromise"
    assert result.active_count == 2
    assert _mock_incident_summary_lookup.await_count == 1  # one batched lookup for every incident


# ── 5. Overview ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_overview_returns_critical_alerts_counts_and_active_incidents(monkeypatch, _mock_incident_summary_lookup):
    critical = {"alert_id": "p1", "severity": "critical", "action": "privilege_change", "host_id": "PRIV-TEST-01"}

    async def fake_search(**kwargs):
        if kwargs.get("severities"):
            return {"total": 1, "alerts": [critical], "counts": {}}
        fields = kwargs.get("aggregate_by") or []
        counts = {
            "severity": {"medium": 20, "critical": 1}, "log_type": {"authentication": 18, "privilege": 1},
            "host_id": {"WIN10-FIN-07": 12}, "user": {"jane.smith": 9, "unknown": 4},
        }
        return {"total": 21, "alerts": [], "counts": {f: counts[f] for f in fields}}

    search = AsyncMock(side_effect=fake_search)
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=(
        [_incident(), _incident(status=IncidentStatus.FALSE_POSITIVE)], 2,
    )))

    result = await TOOLS[Intent.OVERVIEW].call(None, TENANT, {"timerange_hours": 24, "start": "2026-10-22T00:00:00Z"})

    assert result.critical_high_alerts == [critical]
    assert result.critical_high_total == 1
    assert result.total_alerts == 21
    assert result.counts["Severity"] == {"medium": 20, "critical": 1}
    assert result.counts["Accounts targeted or used"] == {"jane.smith": 9}
    assert result.active_incident_count == 1
    severity_call = next(c.kwargs for c in search.call_args_list if c.kwargs.get("severities"))
    assert severity_call["severities"] == ["critical", "high"] and severity_call["sort_by_severity"] is True
    assert all(c.kwargs["tenant_id"] == str(TENANT) and c.kwargs["start"] == "2026-10-22T00:00:00Z"
               for c in search.call_args_list)


@pytest.mark.asyncio
async def test_success_questions_route_to_snapshot_with_a_host_else_overview(monkeypatch):
    fake = _FakeRedisClient()
    monkeypatch.setattr(investigation, "get_client", lambda: fake)

    no_context = await resolve_query("t", "s1", "did they get in?", KNOWN, now=NOW)
    assert (no_context.kind, no_context.intent) == (QueryResolution.TOOL, Intent.OVERVIEW)

    await commit_context("t", "s2", Intent.AUTH_FAILURES, {"host_id": "UBUNTU-WEB-01", "timerange_hours": 6})
    followed = await resolve_query("t", "s2", "did they get in?", KNOWN, now=NOW)
    assert followed.intent == Intent.ENDPOINT_SNAPSHOT
    assert followed.params == {"host_id": "UBUNTU-WEB-01", "timerange_hours": 24}


# ── 6. Prompt: glossary, scope line, readable counts ─────────────────

def test_prompt_has_the_glossary_scope_line_and_readable_counts():
    result = AlertListOutput(
        scope="Searched failed logins on WIN10-FIN-07 in the last 24 hours.",
        total=6,
        counts={"Source IPs (where the activity came from)": {"203.0.113.25": 6}, "Accounts targeted or used": {"jane.smith": 6}},
        alerts=[],
    )

    prompt = _build_prompt("who's been trying to brute force us", result, [])

    assert "account (user) = the account targeted or used; source IP = where the activity came from" in prompt
    assert "never call a targeted account the attacker" in prompt
    assert "Every incident is a detected attack chain" in prompt
    assert "Open or investigating incidents are active attack chains" in prompt
    assert "Start by stating what was searched" in prompt
    assert "Searched failed logins on WIN10-FIN-07 in the last 24 hours." in prompt
    assert "Source IPs (where the activity came from): 203.0.113.25 (6)" in prompt
    data_section = prompt.split("<<<UNTRUSTED_DATA_START>>>")[-1]
    for leaked_key in ("counts:", "scope:", '"counts"', '"scope"'):  # no raw key names
        assert leaked_key not in data_section.lower()


# ── 7. The C1 conversation end-to-end through the router ─────────────

def test_the_conversation_routes_each_turn_to_the_right_tool(client, make_auth_headers, monkeypatch):
    fake = _FakeRedisClient()
    monkeypatch.setattr(investigation, "get_client", lambda: fake)

    async def override_get_db():
        yield "fake-db-session"

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.routers.v1.investigate.get_known_entities", AsyncMock(return_value=KNOWN))
    monkeypatch.setattr("app.routers.v1.investigate.record_event", AsyncMock())
    monkeypatch.setattr(ollama, "generate", Mock(return_value="Searched the requested scope."))
    tools = {intent: Mock(call=AsyncMock(return_value=AlertListOutput(total=0, alerts=[]))) for intent in TOOLS}
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", tools)
    headers = make_auth_headers(tenant_id=TENANT, role=UserRole.ANALYST)

    session_id, failures = None, []
    try:
        for number, (query, kind, intent, expected, absent) in enumerate(CONVERSATION, start=1):
            for tool in tools.values():
                tool.call.reset_mock()
            body = {"query": query, **({"session_id": session_id} if session_id else {})}
            response = client.post("/api/v1/investigate", json=body, headers=headers).json()
            session_id = response["session_id"]
            called = [i for i, tool in tools.items() if tool.call.await_count]

            if kind != QueryResolution.TOOL:
                if called:
                    failures.append(f"#{number} {query!r}: called {called} for a {kind.value} turn")
                continue
            if called != [intent]:
                failures.append(f"#{number} {query!r}: routed to {called}, expected {intent}")
                continue
            db, tenant_id, params = tools[intent].call.call_args.args
            if tenant_id != TENANT:
                failures.append(f"#{number}: tenant {tenant_id} != {TENANT}")
            for key, value in expected.items():
                # start/end depend on today's date here (no fixed clock in the router); check presence.
                ok = key in params if key in ("start", "end") else params.get(key) == value
                if not ok:
                    failures.append(f"#{number} {query!r}: {key}={params.get(key)!r}, expected {value!r}")
            for key in absent:
                if key in params:
                    failures.append(f"#{number} {query!r}: {key} should be absent")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert not failures, "\n".join(failures)


# ── 8. Live OpenSearch: the new search features really work ──────────

def _opensearch_available() -> bool:
    try:
        return opensearch.get_client().ping()
    except Exception:
        return False


requires_opensearch = pytest.mark.skipif(not _opensearch_available(), reason="no reachable OpenSearch (integration test)")


@pytest.fixture(scope="module")
def live_index():
    from app.db.mappings.alert_mapping import ALERT_MAPPING

    client = opensearch.get_client()
    index = f"safesoc-alerts-groundtest-{uuid.uuid4().hex[:12]}"
    tenant = f"groundtest-{uuid.uuid4()}"
    other = f"groundtest-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)
    yesterday_noon = (now - timedelta(days=1)).replace(hour=12, minute=0, second=0, microsecond=0)

    def doc(alert_id, tenant_id=tenant, **fields):
        base = {"alert_id": alert_id, "tenant_id": tenant_id, "source": "synthetic", "log_type": "authentication",
                "severity": "low", "timestamp": (now - timedelta(minutes=5)).isoformat(), "host_id": "WIN10-FIN-07",
                "user": "jane.smith", "action": "failed_login", "description": "d"}
        base.update(fields)
        return base

    docs = [
        doc("src", source_ip="203.0.113.25", severity="medium"),
        doc("dst", destination_ip="203.0.113.25", severity="high", action="network_connection", log_type="network"),
        doc("crit", severity="critical", action="privilege_change", log_type="privilege"),
        doc("yday", severity="low", timestamp=yesterday_noon.isoformat()),
        doc("other", tenant_id=other, source_ip="203.0.113.25", severity="critical"),
    ]
    client.indices.create(index=index, body=ALERT_MAPPING)
    try:
        body = []
        for d in docs:
            body += [{"index": {"_index": index, "_id": d["alert_id"] + d["tenant_id"]}}, d]
        client.bulk(body=body, refresh=True)
        yield tenant, yesterday_noon
    finally:
        client.indices.delete(index=index, ignore=[404])


@requires_opensearch
def test_live_ip_matches_either_side_within_the_tenant(live_index):
    tenant, _ = live_index
    result = asyncio.run(search_alerts(tenant_id=tenant, ip="203.0.113.25", timerange_hours=1))

    assert {a["alert_id"] for a in result["alerts"]} == {"src", "dst"}


@requires_opensearch
def test_live_severity_sort_and_counts(live_index):
    tenant, _ = live_index
    result = asyncio.run(search_alerts(
        tenant_id=tenant, timerange_hours=1, sort_by_severity=True, aggregate_by=["severity", "log_type"],
    ))

    assert [a["alert_id"] for a in result["alerts"]] == ["crit", "dst", "src"]
    assert result["counts"]["severity"] == {"critical": 1, "high": 1, "medium": 1}
    assert result["counts"]["log_type"]["authentication"] == 1


@requires_opensearch
def test_live_bounded_window_selects_only_that_day(live_index):
    tenant, yesterday_noon = live_index
    day_start = yesterday_noon.replace(hour=0)
    result = asyncio.run(search_alerts(
        tenant_id=tenant, timerange_hours=48,
        start=day_start.isoformat(), end=(day_start + timedelta(days=1)).isoformat(),
    ))

    assert [a["alert_id"] for a in result["alerts"]] == ["yday"]
