"""
SafeSOC — Alert Free-Text Search Tests
GET /api/v1/alerts?q= (db/opensearch.py: build_alert_search_clause,
search_alerts). Two layers:

- Query-shape tests against a fake client — always run, including CI.
- Live tests against a real OpenSearch, skipped when none is reachable.
  They prove what the shape tests can't: that case-insensitive wildcard,
  `match` and IP/CIDR terms really find each field, and that hostile
  input doesn't make OpenSearch reject the query. They write to a
  uniquely named `safesoc-alerts-searchtest-*` index under a random
  tenant_id (invisible to every real tenant) and delete it afterwards.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.db import opensearch
from app.db.opensearch import SEARCH_IP_FIELDS, SEARCH_KEYWORD_FIELDS, build_alert_search_clause, search_alerts

HOSTILE_QUERIES = [
    '"', "'", "\\", "*", "?", "a*b?", "(", ")", "[", "]", "{", "}", ":", "/", "!", "~", "^",
    "host_id:*", "user:admin OR 1:1", '") OR ("', "AND", "OR NOT", "-", "+", "&&", "||", "<script>",
    "%", "éè", "\U0001f600", "a" * 300,
]


class _CapturingClient:
    def __init__(self):
        self.body = None

    def search(self, index, body):
        self.body = body
        return {"hits": {"total": {"value": 0}, "hits": []}}


@pytest.fixture
def fake_client(monkeypatch):
    client = _CapturingClient()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: client)
    return client


def _clauses_by_field(clause: dict) -> dict[str, dict]:
    by_field = {}
    for should in clause["bool"]["should"]:
        (kind, spec), = should.items()
        (field, value), = spec.items()
        by_field[field] = {kind: value}
    return by_field


# ── Query shape ──────────────────────────────────────────────────────

def test_blank_q_adds_no_clause():
    assert build_alert_search_clause("   ") is None


@pytest.mark.parametrize("field", SEARCH_KEYWORD_FIELDS)
def test_q_is_a_case_insensitive_substring_match_on_each_keyword_field(field):
    by_field = _clauses_by_field(build_alert_search_clause("Fin-07"))

    assert by_field[field] == {"wildcard": {"value": "*Fin-07*", "case_insensitive": True}}


def test_q_matches_the_analyzed_description_text():
    by_field = _clauses_by_field(build_alert_search_clause("failed login"))

    assert by_field["description"] == {"match": {"query": "failed login", "operator": "and"}}


def test_one_matching_field_is_enough():
    assert build_alert_search_clause("x")["bool"]["minimum_should_match"] == 1


@pytest.mark.parametrize("q, expected", [
    ("203.0.113.18", "203.0.113.18"),
    ("198.51.100", "198.51.100.0/24"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("2001:db8::1", "2001:db8::1"),
])
def test_ip_shaped_q_also_queries_both_ip_fields(q, expected):
    by_field = _clauses_by_field(build_alert_search_clause(q))

    for field in SEARCH_IP_FIELDS:
        assert by_field[field] == {"term": expected}


@pytest.mark.parametrize("q", ["WIN10", "10", "admin", "1.2.3.4.5"])
def test_non_ip_q_never_queries_ip_fields(q):
    """An ip-typed field rejects a non-IP term, which would fail the whole search."""
    by_field = _clauses_by_field(build_alert_search_clause(q))

    for field in SEARCH_IP_FIELDS:
        assert field not in by_field


def test_wildcard_metacharacters_in_q_are_escaped():
    by_field = _clauses_by_field(build_alert_search_clause("a*b?c\\d"))

    assert by_field["host_id"]["wildcard"]["value"] == "*a\\*b\\?c\\\\d*"


@pytest.mark.parametrize("q", HOSTILE_QUERIES)
def test_hostile_q_never_uses_query_string_syntax(q):
    clause = build_alert_search_clause(q)
    serialized = json.dumps(clause)

    assert "query_string" not in serialized
    assert "simple_query_string" not in serialized


def test_q_is_capped_in_length():
    clause = build_alert_search_clause("a" * 1000)
    pattern = _clauses_by_field(clause)["host_id"]["wildcard"]["value"]

    assert len(pattern) == opensearch.SEARCH_QUERY_MAX_LENGTH + 2


@pytest.mark.asyncio
async def test_q_is_anded_with_tenant_and_the_other_filters(fake_client):
    await search_alerts(
        tenant_id="tenant-a", severity="high", log_type="authentication", source="wazuh", host_id="WIN10-FIN-07",
        timerange_hours=48, q="admin",
    )

    bool_query = fake_client.body["query"]["bool"]
    must = bool_query["must"]
    assert {"term": {"tenant_id": "tenant-a"}} in must
    assert {"term": {"severity": "high"}} in must
    assert {"term": {"log_type": "authentication"}} in must
    assert {"term": {"source": "wazuh"}} in must
    assert {"term": {"host_id": "WIN10-FIN-07"}} in must
    assert build_alert_search_clause("admin") in must
    assert bool_query["filter"] == [{"range": {"timestamp": {"gte": "now-48h", "lte": "now"}}}]
    assert fake_client.body["track_total_hits"] is True


@pytest.mark.asyncio
async def test_alert_id_include_and_exclude_filters(fake_client):
    await search_alerts(tenant_id="t", alert_ids_include=["a1"], alert_ids_exclude=["a2"])

    bool_query = fake_client.body["query"]["bool"]
    assert {"terms": {"alert_id": ["a1"]}} in bool_query["must"]
    assert bool_query["must_not"] == [{"terms": {"alert_id": ["a2"]}}]


@pytest.mark.asyncio
async def test_an_empty_include_list_matches_nothing_without_querying(fake_client):
    result = await search_alerts(tenant_id="t", alert_ids_include=[])

    assert result["total"] == 0
    assert result["alerts"] == []
    assert fake_client.body is None


# ── Live OpenSearch ──────────────────────────────────────────────────

def _opensearch_available() -> bool:
    try:
        return opensearch.get_client().ping()
    except Exception:
        return False


requires_opensearch = pytest.mark.skipif(
    not _opensearch_available(), reason="no reachable OpenSearch (integration test)"
)


@pytest.fixture(scope="module")
def live_index():
    """A throwaway alerts index holding two tenants' documents; deleted afterwards."""
    from app.db.mappings.alert_mapping import ALERT_MAPPING

    client = opensearch.get_client()
    index = f"safesoc-alerts-searchtest-{uuid.uuid4().hex[:12]}"
    tenant_a, tenant_b = f"searchtest-{uuid.uuid4()}", f"searchtest-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    def doc(tenant, alert_id, **fields):
        base = {
            "alert_id": alert_id, "tenant_id": tenant, "source": "synthetic", "log_type": "authentication",
            "severity": "low", "timestamp": (now - timedelta(minutes=5)).isoformat(), "host_id": "LINUX-DB-02",
            "user": "svc_backup", "action": "file_read", "description": "routine activity",
        }
        base.update(fields)
        return base

    docs = [
        doc(tenant_a, "host", host_id="WIN10-FIN-07"),
        doc(tenant_a, "user", user="j.mendez"),
        doc(tenant_a, "action", action="failed_login", severity="high"),
        doc(tenant_a, "description", description="Suspicious PowerShell download cradle"),
        doc(tenant_a, "source_ip", source_ip="203.0.113.18"),
        doc(tenant_a, "destination_ip", destination_ip="198.51.100.77"),
        doc(tenant_a, "rule_id", rule_id="WZ-5710"),
        doc(tenant_a, "mitre", mitre_technique="T1110.003"),
        doc(tenant_b, "other-tenant", host_id="WIN10-FIN-07"),
    ]
    client.indices.create(index=index, body=ALERT_MAPPING)
    try:
        body = []
        for d in docs:
            body += [{"index": {"_index": index, "_id": d["alert_id"] + d["tenant_id"]}}, d]
        client.bulk(body=body, refresh=True)
        yield tenant_a, tenant_b
    finally:
        client.indices.delete(index=index, ignore=[404])


async def _ids(tenant, **kwargs) -> set[str]:
    result = await search_alerts(tenant_id=tenant, timerange_hours=1, **kwargs)
    return {alert["alert_id"] for alert in result["alerts"]}


@requires_opensearch
@pytest.mark.asyncio
@pytest.mark.parametrize("q, expected_id", [
    ("win10-fin", "host"),
    ("MENDEZ", "user"),
    ("Failed_Lo", "action"),
    ("powershell", "description"),
    ("203.0.113.18", "source_ip"),
    ("198.51.100", "destination_ip"),
    ("wz-5710", "rule_id"),
    ("t1110", "mitre"),
])
async def test_live_q_finds_each_field_case_insensitively(live_index, q, expected_id):
    tenant_a, _ = live_index

    assert await _ids(tenant_a, q=q) == {expected_id}


@requires_opensearch
@pytest.mark.asyncio
async def test_live_q_combines_with_other_filters_and_counts_only_matches(live_index):
    tenant_a, _ = live_index

    assert await _ids(tenant_a, q="failed", severity="high") == {"action"}
    assert await _ids(tenant_a, q="failed", severity="low") == set()
    result = await search_alerts(tenant_id=tenant_a, timerange_hours=1, q="WIN10", size=1)
    assert result["total"] == 1


@requires_opensearch
@pytest.mark.asyncio
async def test_live_q_never_crosses_tenants(live_index):
    tenant_a, tenant_b = live_index

    assert await _ids(tenant_a, q="WIN10-FIN-07") == {"host"}
    assert await _ids(tenant_b, q="WIN10-FIN-07") == {"other-tenant"}
    assert await _ids(tenant_b, q="mendez") == set()


@requires_opensearch
@pytest.mark.asyncio
@pytest.mark.parametrize("q", HOSTILE_QUERIES)
async def test_live_hostile_q_does_not_error(live_index, q):
    tenant_a, _ = live_index

    result = await search_alerts(tenant_id=tenant_a, timerange_hours=1, q=q)

    assert result["total"] == len(result["alerts"])  # answered normally, nothing raised
