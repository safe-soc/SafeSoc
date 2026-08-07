"""
SafeSOC — Reporting Service
Renders the weekly digest described in SRS §3.3 (executive summary,
alert trends, incidents, top-risk endpoints, TI findings, cloud
posture, recommendations) to PDF, saved under
settings.REPORT_OUTPUT_DIR/{tenant_id}/ (SS-052).

Reuses existing services rather than duplicating query logic: alert
data comes from db.opensearch.search_alerts/get_cloud_summary,
incidents from services.incidents.list_incidents, and endpoint risk
from services.risk_scoring.list_endpoints — the same data every other
part of the app already reads through.

Data gathering and HTML rendering are pure/testable without WeasyPrint
itself: the actual PDF-writing step is isolated behind _write_pdf() (a
lazy import), so this module — and anything that imports it, like the
scheduling task (SS-053) and the listing/download router (SS-054) —
stays importable even in an environment missing WeasyPrint's native
text-shaping library (Pango), which this module doesn't otherwise need.
"""

import html
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import IncidentStatus, RiskLevel
from app.db.opensearch import get_cloud_summary, search_alerts
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.services.incidents import list_incidents
from app.services.risk_scoring import list_endpoints

TOP_RISK_ENDPOINT_LIMIT = 10
# A report summarizes a period, not a full forensic export — this caps
# how many raw alerts are pulled to compute the severity breakdown.
# alerts_total (below) still reflects the true period total even if it
# exceeds this.
REPORT_ALERT_FETCH_LIMIT = 1000


@dataclass(frozen=True)
class ReportData:
    tenant_name: str
    period_start: datetime
    period_end: datetime
    alerts_total: int
    alerts_by_severity: dict[str, int]
    incidents: list[Incident]
    top_risk_endpoints: list[Endpoint]
    ti_malicious_count: int
    cloud_summary: dict
    recommendations: list[str]


async def _get_tenant_name(db: AsyncSession, tenant_id: uuid.UUID) -> str:
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()
    return tenant.name if tenant is not None else str(tenant_id)


def _build_recommendations(
    alerts_by_severity: dict[str, int],
    incidents: list[Incident],
    top_risk_endpoints: list[Endpoint],
    ti_malicious_count: int,
    cloud_summary: dict,
) -> list[str]:
    """
    Deterministic, rule-based recommendations from this period's data —
    not an LLM call, matching the precedent set by SS-044's
    intent classification (keeps this testable without a live LLM).
    """
    recommendations = []

    critical_count = alerts_by_severity.get("critical", 0)
    if critical_count:
        recommendations.append(
            f"{critical_count} critical-severity alert(s) were recorded this period — review and triage immediately."
        )

    high_count = alerts_by_severity.get("high", 0)
    if high_count:
        recommendations.append(f"{high_count} high-severity alert(s) were recorded — prioritize investigation.")

    open_incidents = [i for i in incidents if i.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)]
    if open_incidents:
        recommendations.append(
            f"{len(open_incidents)} incident(s) remain open or under investigation — "
            "assign an analyst if one isn't already working it."
        )

    if top_risk_endpoints and top_risk_endpoints[0].risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        recommendations.append(
            f"Endpoint '{top_risk_endpoints[0].host_id}' has the highest risk score this period "
            f"({top_risk_endpoints[0].risk_score}, {top_risk_endpoints[0].risk_level.value}) — investigate first."
        )

    if ti_malicious_count:
        recommendations.append(
            f"{ti_malicious_count} alert(s) matched a known-malicious threat intelligence indicator — "
            "review the associated hosts for signs of compromise."
        )

    if cloud_summary.get("total", 0):
        recommendations.append(
            f"{cloud_summary['total']} cloud security finding(s) were recorded — review CloudLens for remediation."
        )

    if not recommendations:
        recommendations.append("No significant security events were recorded this period. Continue routine monitoring.")

    return recommendations


async def gather_report_data(db: AsyncSession, tenant_id: uuid.UUID, days: int) -> ReportData:
    """Collect everything a report needs for the trailing `days`-day period ending now."""
    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=days)

    tenant_name = await _get_tenant_name(db, tenant_id)

    alerts_result = await search_alerts(
        tenant_id=str(tenant_id), timerange_hours=days * 24, size=REPORT_ALERT_FETCH_LIMIT
    )
    alerts = alerts_result["alerts"]

    alerts_by_severity: dict[str, int] = {}
    ti_malicious_count = 0
    for alert in alerts:
        severity = alert.get("severity", "unknown")
        alerts_by_severity[severity] = alerts_by_severity.get(severity, 0) + 1
        ti_result = alert.get("ti_result")
        if ti_result and ti_result.get("is_malicious"):
            ti_malicious_count += 1

    all_incidents, _total = await list_incidents(db, tenant_id, size=500)
    incidents = [incident for incident in all_incidents if incident.created_at >= period_start]

    endpoints = await list_endpoints(db, tenant_id)
    top_risk_endpoints = endpoints[:TOP_RISK_ENDPOINT_LIMIT]

    cloud_summary = await get_cloud_summary(str(tenant_id), timerange_hours=days * 24)

    recommendations = _build_recommendations(
        alerts_by_severity, incidents, top_risk_endpoints, ti_malicious_count, cloud_summary
    )

    return ReportData(
        tenant_name=tenant_name,
        period_start=period_start,
        period_end=period_end,
        alerts_total=alerts_result["total"],
        alerts_by_severity=alerts_by_severity,
        incidents=incidents,
        top_risk_endpoints=top_risk_endpoints,
        ti_malicious_count=ti_malicious_count,
        cloud_summary=cloud_summary,
        recommendations=recommendations,
    )


def _esc(value: object) -> str:
    return html.escape(str(value))


def _severity_table(alerts_by_severity: dict[str, int]) -> str:
    if not alerts_by_severity:
        return "<p>No alerts were recorded during this period.</p>"
    rows = "".join(
        f"<tr><td>{_esc(severity.title())}</td><td>{count}</td></tr>"
        for severity, count in sorted(alerts_by_severity.items(), key=lambda kv: -kv[1])
    )
    return f"<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>"


def _incident_table(incidents: list[Incident]) -> str:
    if not incidents:
        return "<p>No incidents were opened during this period.</p>"
    rows = "".join(
        f"<tr><td>{_esc(str(incident.id)[:8])}</td>"
        f"<td>{_esc(incident.status.value.replace('_', ' ').title())}</td>"
        f"<td>{len(incident.alert_ids)}</td>"
        f"<td>{incident.created_at:%Y-%m-%d %H:%M}</td></tr>"
        for incident in incidents
    )
    return f"<table><thead><tr><th>Incident</th><th>Status</th><th>Alerts</th><th>Opened</th></tr></thead><tbody>{rows}</tbody></table>"


def _endpoint_table(endpoints: list[Endpoint]) -> str:
    if not endpoints:
        return "<p>No endpoints have been scored yet.</p>"
    rows = "".join(
        f"<tr><td>{_esc(endpoint.host_id)}</td><td>{endpoint.risk_score}</td>"
        f"<td>{_esc(endpoint.risk_level.value.title())}</td></tr>"
        for endpoint in endpoints
    )
    return f"<table><thead><tr><th>Host</th><th>Risk Score</th><th>Risk Level</th></tr></thead><tbody>{rows}</tbody></table>"


def render_report_html(data: ReportData) -> str:
    """
    Build the report's HTML content — plain string building, no
    templating-engine dependency added just for this. Every data
    section has an explicit empty-state message rather than an empty
    table, so a tenant with zero alerts/incidents still renders
    sensible content (AC).
    """
    recommendation_items = "".join(f"<li>{_esc(r)}</li>" for r in data.recommendations)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SafeSOC Security Report</title>
<style>
  body {{ font-family: sans-serif; color: #1a1a1a; margin: 2em; }}
  h1 {{ font-size: 1.6em; margin-bottom: 0.1em; }}
  h2 {{ font-size: 1.2em; margin-top: 1.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 0.5em; }}
  th, td {{ border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; font-size: 0.9em; }}
  th {{ background: #f0f0f0; }}
</style>
</head>
<body>
  <h1>SafeSOC Security Report — {_esc(data.tenant_name)}</h1>
  <p>Period: {data.period_start:%Y-%m-%d} to {data.period_end:%Y-%m-%d}</p>

  <h2>Executive Summary</h2>
  <p>{data.alerts_total} alert(s), {len(data.incidents)} incident(s), and {data.cloud_summary.get('total', 0)}
  cloud finding(s) were recorded during this period.</p>

  <h2>Alert Trends</h2>
  {_severity_table(data.alerts_by_severity)}

  <h2>Incidents</h2>
  {_incident_table(data.incidents)}

  <h2>Top-Risk Endpoints</h2>
  {_endpoint_table(data.top_risk_endpoints)}

  <h2>Threat Intelligence Findings</h2>
  <p>{data.ti_malicious_count} alert(s) matched a known-malicious threat intelligence indicator.</p>

  <h2>Cloud Posture</h2>
  <p>{data.cloud_summary.get('total', 0)} cloud finding(s) across
  {data.cloud_summary.get('distinct_affected_resources', 0)} affected resource(s).</p>

  <h2>Recommendations</h2>
  <ul>{recommendation_items}</ul>
</body>
</html>"""


def _write_pdf(html_content: str, output_path: Path) -> None:
    # Lazy import — see module docstring: keeps this module (and its
    # callers) importable without WeasyPrint's native Pango dependency
    # present, which only actually matters at the point a PDF is rendered.
    from weasyprint import HTML

    output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_content).write_pdf(str(output_path))


def _report_filename(generated_at: datetime) -> str:
    return f"{generated_at:%Y%m%dT%H%M%SZ}.pdf"


async def generate_report(db: AsyncSession, tenant_id: uuid.UUID, days: int = 7, *, output_dir: Optional[Path] = None) -> Path:
    """
    Generate and save a PDF security report for tenant_id covering the
    trailing `days`-day period (default: weekly, matching
    REPORT_SCHEDULE_DAY/HOUR). Saved under
    settings.REPORT_OUTPUT_DIR/{tenant_id}/ unless output_dir overrides
    the tenant-scoped parent directory (used by tests).
    """
    data = await gather_report_data(db, tenant_id, days)
    html_content = render_report_html(data)

    generated_at = datetime.now(timezone.utc)
    base_dir = output_dir if output_dir is not None else Path(settings.REPORT_OUTPUT_DIR)
    report_path = base_dir / str(tenant_id) / _report_filename(generated_at)

    _write_pdf(html_content, report_path)
    return report_path


@dataclass(frozen=True)
class ReportInfo:
    filename: str
    generated_at: datetime
    size_bytes: int


def _tenant_report_dir(tenant_id: uuid.UUID) -> Path:
    return Path(settings.REPORT_OUTPUT_DIR) / str(tenant_id)


def list_reports(tenant_id: uuid.UUID) -> list[ReportInfo]:
    """List a tenant's generated reports (SS-054), newest first. Empty if the tenant has none yet — not an error."""
    report_dir = _tenant_report_dir(tenant_id)
    if not report_dir.is_dir():
        return []

    reports = []
    for path in report_dir.glob("*.pdf"):
        try:
            generated_at = datetime.strptime(path.stem, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            continue  # not one of our own generated filenames — skip rather than error
        reports.append(ReportInfo(filename=path.name, generated_at=generated_at, size_bytes=path.stat().st_size))

    return sorted(reports, key=lambda r: r.generated_at, reverse=True)


def get_report_path(tenant_id: uuid.UUID, filename: str) -> Optional[Path]:
    """
    Resolve `filename` to a report file scoped to tenant_id (SS-054).
    None if it doesn't exist under this tenant's own report directory
    — including a filename that exists under a *different* tenant's
    directory, or a path-traversal attempt, so cross-tenant access
    isn't just hard to guess, it's structurally unreachable regardless
    of what filename is supplied (AC).
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        return None

    candidate = _tenant_report_dir(tenant_id) / filename
    if not candidate.is_file():
        return None
    return candidate
