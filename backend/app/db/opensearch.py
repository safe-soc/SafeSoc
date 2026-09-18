"""
SafeSOC — OpenSearch Client
Connection management, index setup, bulk writes, and search queries.
"""

from datetime import datetime
from typing import Optional

from opensearchpy import OpenSearch, exceptions

from app.core.config import settings
from app.core.enums import LogSource
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Index pattern with monthly rotation
INDEX_PATTERN = "safesoc-alerts-{YYYY}.{MM}"


def _build_index_name(timestamp: Optional[datetime] = None) -> str:
    """Generate monthly index name: safesoc-alerts-2026.05"""
    ts = timestamp or datetime.utcnow()
    return f"safesoc-alerts-{ts.year}.{ts.month:02d}"


def get_client() -> OpenSearch:
    """Create and return an OpenSearch client instance."""
    return OpenSearch(
        hosts=[{"host": settings.OPENSEARCH_HOST, "port": settings.OPENSEARCH_PORT}],
        http_auth=(settings.OPENSEARCH_USER, settings.OPENSEARCH_PASSWORD),
        use_ssl=settings.OPENSEARCH_USE_SSL,
        verify_certs=settings.OPENSEARCH_VERIFY_CERTS,
        ssl_show_warn=False,
    )


async def check_connection() -> bool:
    """Check if OpenSearch is reachable. Returns True if healthy."""
    try:
        client = get_client()
        return client.ping()
    except Exception:
        return False


async def ensure_index_exists(client: OpenSearch, index_name: str) -> None:
    """Create index with mapping if it doesn't already exist."""
    from app.db.mappings.alert_mapping import ALERT_MAPPING

    if not client.indices.exists(index=index_name):
        client.indices.create(index=index_name, body=ALERT_MAPPING)
        logger.info("Created index", index=index_name)


async def ensure_ilm_policy() -> None:
    """
    Create the safesoc-alerts-* retention (ISM) policy if it doesn't already
    exist. Idempotent: safe to call on every startup. New indices matching
    the policy's ism_template pick it up automatically; indices created
    before this policy existed are not retroactively affected.
    """
    from app.db.mappings.ilm_policy import ILM_POLICY, ILM_POLICY_ID

    client = get_client()
    try:
        client.index_management.get_policy(policy=ILM_POLICY_ID)
        logger.info("ILM policy already exists", policy_id=ILM_POLICY_ID)
    except exceptions.NotFoundError:
        client.index_management.put_policy(policy=ILM_POLICY_ID, body=ILM_POLICY)
        logger.info("Created ILM policy", policy_id=ILM_POLICY_ID)


async def bulk_index_logs(logs: list[dict]) -> int:
    """
    Write a batch of normalized logs to OpenSearch.
    Returns the number of successfully indexed documents.
    """
    if not logs:
        return 0

    client = get_client()
    success_count = 0
    failed_count = 0

    # Group logs by their monthly index
    batches: dict[str, list[dict]] = {}
    for log in logs:
        ts = log.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        index_name = _build_index_name(ts)
        batches.setdefault(index_name, []).append(log)

    # Bulk write per index
    for index_name, batch in batches.items():
        await ensure_index_exists(client, index_name)

        body = []
        for doc in batch:
            body.append({"index": {"_index": index_name, "_id": doc.get("alert_id")}})
            body.append(doc)

        try:
            response = client.bulk(body=body, refresh=True)
            if response.get("errors"):
                for item in response["items"]:
                    if "error" in item.get("index", {}):
                        failed_count += 1
                        logger.error(
                            "Bulk index error",
                            error=item["index"]["error"],
                            doc_id=item["index"].get("_id"),
                        )
                    else:
                        success_count += 1
            else:
                success_count += len(batch)

        except exceptions.OpenSearchException as e:
            logger.error("Bulk index failed", error=str(e))
            failed_count += len(batch)

    logger.info("Bulk index complete", success=success_count, failed=failed_count)
    return success_count


async def get_alert_by_id(alert_id: str) -> Optional[dict]:
    """
    Fetch a single alert document by its alert_id, searching across all
    monthly indices (the caller doesn't need to know which one it's in).
    Returns None if no such document exists.
    """
    client = get_client()
    response = client.search(
        index="safesoc-alerts-*",
        body={"query": {"term": {"alert_id": alert_id}}, "size": 1},
    )
    hits = response["hits"]["hits"]
    return hits[0]["_source"] if hits else None


async def get_alerts_by_ids(alert_ids: list[str]) -> list[dict]:
    """
    Batch-fetch alert documents by id, searching across all monthly
    indices in one round trip (SS-099/SS-100) — the multi-alert
    equivalent of get_alert_by_id above, used wherever a caller already
    has a list of alert_ids (e.g. Incident.alert_ids) and wants their
    full documents. An id with no matching document is silently
    omitted rather than raising: callers (incident timeline/evidence
    extraction) treat a missing alert as best-effort, same as
    get_alert_by_id's None return for a single lookup.
    """
    if not alert_ids:
        return []
    client = get_client()
    response = client.search(
        index="safesoc-alerts-*",
        body={"query": {"terms": {"alert_id": alert_ids}}, "size": len(alert_ids)},
    )
    return [hit["_source"] for hit in response["hits"]["hits"]]


async def update_alert_ti_fields(
    alert_id: str,
    timestamp: datetime,
    ti_result: dict,
    ti_enriched: bool,
    risk_score: int,
) -> bool:
    """
    Update an already-indexed alert's ti_result/ti_enriched/risk_score
    fields in place (update-by-id). `timestamp` locates the alert's
    monthly index the same way bulk_index_logs does when it was written.
    Returns True on success, False on failure (never raises).
    """
    client = get_client()
    index_name = _build_index_name(timestamp)
    try:
        client.update(
            index=index_name,
            id=alert_id,
            body={"doc": {"ti_result": ti_result, "ti_enriched": ti_enriched, "risk_score": risk_score}},
        )
        return True
    except exceptions.OpenSearchException as e:
        logger.error("TI enrichment update failed", alert_id=alert_id, error=str(e))
        return False


async def update_alert_anomaly_score(alert_id: str, timestamp: datetime, anomaly_score: float) -> bool:
    """
    Update an already-indexed alert's anomaly_score field in place
    (update-by-id), same pattern as update_alert_ti_fields above
    (SS-102). A separate function rather than extending
    update_alert_ti_fields — anomaly scoring is a distinct concern
    (behavioral, not threat-intel) that happens to update the same
    document. Returns True on success, False on failure (never raises).
    """
    client = get_client()
    index_name = _build_index_name(timestamp)
    try:
        client.update(
            index=index_name,
            id=alert_id,
            body={"doc": {"anomaly_score": anomaly_score}},
        )
        return True
    except exceptions.OpenSearchException as e:
        logger.error("Anomaly score update failed", alert_id=alert_id, error=str(e))
        return False


async def search_alerts(
    tenant_id: str,
    severity: Optional[str] = None,
    log_type: Optional[str] = None,
    source: Optional[str] = None,
    host_id: Optional[str] = None,
    action: Optional[str] = None,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
    timerange_hours: int = 24,
    page: int = 1,
    size: int = 50,
) -> dict:
    """
    Search alerts with mandatory tenant_id filter.
    Returns paginated results with total count.
    """
    client = get_client()

    must_filters = [{"term": {"tenant_id": tenant_id}}]

    if severity:
        must_filters.append({"term": {"severity": severity}})
    if log_type:
        must_filters.append({"term": {"log_type": log_type}})
    if source:
        must_filters.append({"term": {"source": source}})
    if host_id:
        must_filters.append({"term": {"host_id": host_id}})
    if action:
        must_filters.append({"term": {"action": action}})
    if user:
        must_filters.append({"term": {"user": user}})
    if source_ip:
        must_filters.append({"term": {"source_ip": source_ip}})

    range_filter = {
        "range": {
            "timestamp": {
                "gte": f"now-{timerange_hours}h",
                "lte": "now",
            }
        }
    }

    query = {
        "query": {
            "bool": {
                "must": must_filters,
                "filter": [range_filter],
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size,
        "track_total_hits": True,
    }

    # Search across all monthly indices
    response = client.search(index="safesoc-alerts-*", body=query)

    total = response["hits"]["total"]["value"]
    hits = [hit["_source"] for hit in response["hits"]["hits"]]

    return {
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
        "alerts": hits,
    }


async def get_alert_severity_summary(tenant_id: str, timerange_hours: int = 24, host_id: Optional[str] = None) -> dict:
    """
    Aggregate severity counts for the SAME tenant+time-window population
    search_alerts() would page through — total count plus a per-severity
    breakdown — via a size:0 terms aggregation rather than fetching
    documents, so the result doesn't depend on (and isn't capped by) any
    page-size limit. Used by dashboard severity distribution (the naive
    approach of counting a single fetched page client-side silently
    undercounts once total alerts exceed that page size), and, with
    host_id set, by the endpoint detail page's own severity breakdown —
    same reasoning, scoped to one host instead of the whole tenant.

    Every indexed alert has passed NormalizedLog validation (severity is
    a required Severity enum field — app/schemas/log.py), so a malformed
    or missing severity is rejected at ingestion, never indexed. Bucket
    keys are therefore always one of low/medium/high/critical in
    practice; buckets are still returned as-is (not coerced to a fixed
    set of 4) so an unexpected value is surfaced rather than silently
    folded into another severity.
    """
    client = get_client()

    must_filters = [{"term": {"tenant_id": tenant_id}}]
    if host_id:
        must_filters.append({"term": {"host_id": host_id}})

    query = {
        "query": {
            "bool": {
                "must": must_filters,
                "filter": [{"range": {"timestamp": {"gte": f"now-{timerange_hours}h", "lte": "now"}}}],
            }
        },
        "size": 0,
        "track_total_hits": True,
        "aggs": {
            "by_severity": {"terms": {"field": "severity", "size": 10}},
        },
    }

    response = client.search(index="safesoc-alerts-*", body=query)

    total = response["hits"]["total"]["value"]
    by_severity = {
        bucket["key"]: bucket["doc_count"] for bucket in response["aggregations"]["by_severity"]["buckets"]
    }

    return {
        "total": total,
        "timerange_hours": timerange_hours,
        "by_severity": by_severity,
    }


async def get_known_endpoints(timerange_hours: int = 24) -> list[dict]:
    """
    Discover every distinct (tenant_id, host_id) pair with at least one
    alert in the lookback window, across all tenants — "known endpoints"
    for the scheduled risk recalculation task (SS-033) to re-score.
    Uses a nested terms aggregation since this is a distinct-pairs
    discovery query, not a per-tenant document search like search_alerts.
    """
    client = get_client()

    query = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": f"now-{timerange_hours}h", "lte": "now"}}},
        "aggs": {
            "by_tenant": {
                "terms": {"field": "tenant_id", "size": 10000},
                "aggs": {
                    "by_host": {"terms": {"field": "host_id", "size": 10000}},
                },
            },
        },
    }

    response = client.search(index="safesoc-alerts-*", body=query)

    endpoints = []
    for tenant_bucket in response["aggregations"]["by_tenant"]["buckets"]:
        tenant_id = tenant_bucket["key"]
        for host_bucket in tenant_bucket["by_host"]["buckets"]:
            endpoints.append({"tenant_id": tenant_id, "host_id": host_bucket["key"]})

    return endpoints


async def get_cloud_summary(tenant_id: str, timerange_hours: int = 24) -> dict:
    """
    Aggregate stats for cloud-sourced (CloudLens) alerts: total count,
    breakdowns by severity and category (stored as `action`), and the
    number of distinct affected resources (`host_id`). A genuinely
    different *shape* of view than search_alerts' paginated raw list —
    aggregates, not a page of documents — which is what makes this
    worth a dedicated endpoint rather than duplicating GET /api/v1/alerts
    (SS-040).
    """
    client = get_client()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"tenant_id": tenant_id}},
                    {"term": {"source": LogSource.CLOUDLENS.value}},
                ],
                "filter": [{"range": {"timestamp": {"gte": f"now-{timerange_hours}h", "lte": "now"}}}],
            }
        },
        "size": 0,
        "track_total_hits": True,
        "aggs": {
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_category": {"terms": {"field": "action", "size": 20}},
            "distinct_affected_resources": {"cardinality": {"field": "host_id"}},
        },
    }

    response = client.search(index="safesoc-alerts-*", body=query)

    total = response["hits"]["total"]["value"]
    aggs = response["aggregations"]

    return {
        "total": total,
        "by_severity": {bucket["key"]: bucket["doc_count"] for bucket in aggs["by_severity"]["buckets"]},
        "by_category": {bucket["key"]: bucket["doc_count"] for bucket in aggs["by_category"]["buckets"]},
        "distinct_affected_resources": aggs["distinct_affected_resources"]["value"],
    }