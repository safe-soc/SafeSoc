"""
SafeSOC — Investigation Report HTML/PDF Renderer
Turns an InvestigationReportData (services/investigation_report.py) into
a print-ready HTML document, styled for WeasyPrint's Paged Media support
(CSS @page rules: running headers/footers, page-number counters, a
distinct unnumbered cover page). Kept in its own module, separate from
data gathering, matching the "report data -> renderer -> PDF" staging
the whole feature is built around — nothing in here queries the
database or calls another service; it only formats what it's given.

Visual language: SafeSOC's own dark-cover-page + light-content-page
convention (a printed multi-page PDF with a dark background throughout
would be unreadable/wasteful to print) — cyan-blue accent (#0ea5e9),
near-black cover (#0b1220), white content pages, the same 4-tier
severity palette already used everywhere else in the app
(components/LevelBadge.tsx: low slate / medium yellow / high orange /
critical red). No branding, layout, or wording copied from any
third-party report product — this is a native SafeSOC document.
"""

import html
from datetime import datetime
from typing import Optional

from app.services.investigation_report import (
    AlertRow,
    AttackChainData,
    BehaviorFinding,
    EndpointAnalysis,
    InvestigationReportData,
    MitreRow,
    NetworkRow,
    Recommendation,
    SeverityCounts,
    TimelineEvent,
    UserActivity,
    VulnerabilityRow,
)

_SEVERITY_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#94a3b8"}
_NODE_COLORS = {"host": "#3b82f6", "ip": "#f97316", "user": "#a855f7", "cloud_resource": "#22c55e"}


def _esc(value: object) -> str:
    if value is None:
        return "—"
    return html.escape(str(value))


def _fmt_dt(value: Optional[datetime]) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_date(value: Optional[datetime]) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d")


def _severity_badge(severity: Optional[str]) -> str:
    severity = (severity or "low").lower()
    color = _SEVERITY_COLORS.get(severity, "#94a3b8")
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}66">{_esc(severity.title())}</span>'


def _empty_state(message: str) -> str:
    return f'<p class="empty-state">{_esc(message)}</p>'


def _finish_sentence(text: str) -> str:
    # The underlying LLM call caps output tokens for latency (see
    # services/incident_narrative.py) and can end mid-sentence as a
    # result -- mark that visually with an ellipsis rather than
    # printing a sentence that just stops, without altering the
    # narrative's actual wording.
    stripped = text.rstrip()
    if stripped and stripped[-1] not in ".!?…\"'":
        return stripped + "…"
    return stripped


# ── Severity / volume charts (plain HTML/CSS bars — reliable in print, no JS/canvas) ──

def _severity_bar_chart(counts: SeverityCounts) -> str:
    if counts.total == 0:
        return _empty_state("No alerts in scope.")
    rows = []
    for label in ("critical", "high", "medium", "low"):
        count = getattr(counts, label)
        pct = round((count / counts.total) * 100) if counts.total else 0
        color = _SEVERITY_COLORS[label]
        rows.append(f"""
        <div class="bar-row">
          <span class="bar-label">{_esc(label.title())}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>
          <span class="bar-value">{count} ({pct}%)</span>
        </div>""")
    return f'<div class="bar-chart">{"".join(rows)}</div>'


def _daily_volume_chart(daily) -> str:
    if not daily:
        return _empty_state("No time-series data available in scope.")
    max_count = max(d.count for d in daily) or 1
    bars = "".join(
        f'<div class="vol-bar" title="{_esc(d.date)}: {d.count}">'
        f'<span class="vol-bar-count">{d.count}</span>'
        f'<div class="vol-bar-track"><div class="vol-bar-fill" style="height:{max(round((d.count / max_count) * 100), 3)}%"></div></div>'
        f'<span class="vol-bar-label">{_esc(d.date[5:])}</span></div>'
        for d in daily
    )
    return f'<div class="vol-chart">{bars}</div>'


# ── Attack chain SVG diagram ──

def _attack_chain_svg(chain: AttackChainData) -> str:
    width, height = 700, 420
    parts = [f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}px" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f8fafc" stroke="#e2e8f0"/>')

    nodes_by_id = {n.id: n for n in chain.nodes}

    for edge in chain.grouped_edges:
        pos_a = chain.node_positions.get(edge.source_id)
        pos_b = chain.node_positions.get(edge.target_id)
        if pos_a is None or pos_b is None:
            continue
        stroke = "#a855f7" if edge.mitre_techniques else "#94a3b8"
        stroke_width = 2 if edge.mitre_techniques else 1.2
        parts.append(f'<line x1="{pos_a[0]:.1f}" y1="{pos_a[1]:.1f}" x2="{pos_b[0]:.1f}" y2="{pos_b[1]:.1f}" stroke="{stroke}" stroke-width="{stroke_width}"/>')
        if edge.count > 1:
            mx, my = (pos_a[0] + pos_b[0]) / 2, (pos_a[1] + pos_b[1]) / 2
            parts.append(f'<circle cx="{mx:.1f}" cy="{my:.1f}" r="9" fill="#ffffff" stroke="#94a3b8"/>')
            parts.append(f'<text x="{mx:.1f}" y="{my + 3:.1f}" font-size="9" text-anchor="middle" fill="#334155">{edge.count}</text>')

    for node in chain.nodes:
        pos = chain.node_positions.get(node.id)
        if pos is None:
            continue
        x, y = pos
        color = _NODE_COLORS.get(node.type, "#64748b")
        if node.type == "ip":
            parts.append(f'<rect x="{x-11:.1f}" y="{y-11:.1f}" width="22" height="22" fill="{color}" stroke="#ffffff" stroke-width="1.5" transform="rotate(45 {x:.1f} {y:.1f})"/>')
        elif node.type == "cloud_resource":
            parts.append(f'<rect x="{x-14:.1f}" y="{y-14:.1f}" width="28" height="28" rx="4" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
        else:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="14" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')
        label = node.label if len(node.label) <= 20 else node.label[:18] + "…"
        parts.append(f'<text x="{x:.1f}" y="{y + 28:.1f}" font-size="10" text-anchor="middle" fill="#1e293b">{_esc(label)}</text>')

    parts.append("</svg>")
    return "".join(parts)


def _attack_chain_legend() -> str:
    items = "".join(
        f'<span class="legend-item"><span class="legend-dot" style="background:{color}"></span>{_esc(label)}</span>'
        for label, color in (("Host", _NODE_COLORS["host"]), ("IP Address", _NODE_COLORS["ip"]),
                              ("User", _NODE_COLORS["user"]), ("Cloud Resource", _NODE_COLORS["cloud_resource"]))
    )
    return f'<div class="legend">{items}</div>'


# ── Tables ──

def _table(
    headers: list[str], rows: list[list[str]], empty_message: str,
    col_widths: Optional[list[int]] = None, table_class: str = "",
) -> str:
    if not rows:
        return _empty_state(empty_message)
    # table-layout:fixed (see _CSS) sizes columns from the FIRST row's
    # widths and holds them for the whole table -- without an explicit
    # colgroup, a wide table (e.g. 9-column alert evidence) would
    # otherwise get equal-width columns and run off the printable page
    # width once fixed layout is in play, so callers with lopsided
    # column content (a long Description next to a short Severity)
    # pass col_widths (percentages summing to ~100) to avoid that.
    colgroup = ""
    if col_widths:
        colgroup = "<colgroup>" + "".join(f'<col style="width:{w}%">' for w in col_widths) + "</colgroup>"
        head = "".join(f'<th style="width:{w}%">{_esc(h)}</th>' for h, w in zip(headers, col_widths))
    else:
        head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    class_attr = f' class="{table_class}"' if table_class else ""
    return f'<table{class_attr}>{colgroup}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


# ══════════════════════════════════════════════════════════════════════
# Section renderers
# ══════════════════════════════════════════════════════════════════════


def _render_cover(data: InvestigationReportData) -> str:
    scope_label = "Incident" if data.metadata.scope_type == "incident" else "Endpoint"
    risk_line = ""
    if data.metadata.risk_score is not None or data.metadata.risk_level is not None:
        color = _SEVERITY_COLORS.get((data.metadata.risk_level or "low").lower(), "#94a3b8")
        score_html = f'<span class="cover-risk-score">{data.metadata.risk_score}</span>' if data.metadata.risk_score is not None else ""
        risk_line = (
            '<div class="cover-risk">'
            f"{score_html}"
            f'<span class="cover-risk-level" style="color:{color}">{_esc((data.metadata.risk_level or "unknown").title())} Risk</span>'
            "</div>"
        )
    classification = ""
    if data.metadata.is_synthetic:
        classification = '<div class="cover-classification">SYNTHETIC DEMONSTRATION DATA</div>'
    return (
        '<section class="cover-page">'
        '<div class="cover-brand">SafeSOC</div>'
        '<div class="cover-title">Security Investigation Report</div>'
        f'<div class="cover-scope">{_esc(scope_label)}: {_esc(data.metadata.scope_name)}</div>'
        f"{risk_line}"
        f"{classification}"
        '<div class="cover-footer">'
        f"<div>Report generated {_fmt_dt(data.metadata.generated_at)}</div>"
        f'<div>Report ID: {_esc(data.metadata.report_id[:8])}</div>'
        "</div>"
        "</section>"
    )


def _render_executive_summary(data: InvestigationReportData) -> str:
    s = data.summary
    findings = "".join(f"<li>{_esc(f.text)}</li>" for f in s.key_findings)
    if s.narrative_is_fallback:
        narrative_note = (
            '<p class="ai-note">Deterministic summary — the AI summarizer was unavailable or no active '
            "investigation session was captured for this report.</p>"
        )
    else:
        narrative_note = '<p class="ai-note">AI-generated summary, grounded in the evidence gathered for this report.</p>'
    stats = [
        ("Overall Verdict", s.verdict),
        ("Investigation Status", (s.investigation_status or "—").title() if s.investigation_status else "—"),
        ("First Observed", _fmt_dt(s.first_observed)),
        ("Last Observed", _fmt_dt(s.last_observed)),
        ("Affected Endpoints", str(s.affected_endpoints)),
        ("Affected Users", str(s.affected_users)),
        ("Alert Count", str(s.alert_count)),
        ("Incident Count", str(s.incident_count)),
        ("Critical/High Alerts", str(s.critical_high_alert_count)),
    ]
    stat_rows = "".join(
        f'<div class="stat-box"><div class="stat-label">{_esc(k)}</div><div class="stat-value">{_esc(v)}</div></div>'
        for k, v in stats
    )
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Executive Summary</h1>'
        f'<div class="stat-grid">{stat_rows}</div>'
        f"{narrative_note}"
        f'<p class="narrative">{_esc(_finish_sentence(s.narrative))}</p>'
        '<h2 class="section-title">Key Findings</h2>'
        f'<ul class="findings-list">{findings}</ul>'
        "</section>"
    )


def _render_overview(data: InvestigationReportData) -> str:
    if data.metadata.scope_type == "incident":
        rows = [
            ("Incident ID", _esc(data.appendix.incident_ids[0] if data.appendix.incident_ids else "—")),
            ("Status", _esc((data.summary.investigation_status or "—").title())),
            ("Severity", _severity_badge(data.summary.severity)),
            ("Alert Count", str(data.summary.alert_count)),
            ("Affected Hosts", str(len(data.endpoints))),
            ("Affected Users", str(len(data.users))),
            ("MITRE Techniques", ", ".join(data.appendix.mitre_technique_ids) or "None observed"),
        ]
        title = "Incident Overview"
    else:
        e = data.endpoints[0] if data.endpoints else None
        rows = [
            ("Hostname", _esc(data.metadata.scope_name)),
            ("Risk Score", str(data.metadata.risk_score) if data.metadata.risk_score is not None else "Not yet scored"),
            ("Risk Level", _severity_badge(data.metadata.risk_level) if data.metadata.risk_level else "—"),
            ("Alert Count (30d)", str(data.summary.alert_count)),
            ("Critical Alerts", str(e.severity.critical if e else 0)),
            ("High Alerts", str(e.severity.high if e else 0)),
            ("Associated Incidents", str(len(data.appendix.incident_ids))),
            ("Users Observed", str(len(data.users))),
        ]
        title = "Endpoint Overview"
    table_rows = "".join(f"<tr><th>{_esc(k)}</th><td>{v}</td></tr>" for k, v in rows)
    return (
        '<section class="content-section">'
        f'<h1 class="page-title">{title}</h1>'
        f'<table class="kv-table">{table_rows}</table>'
        "</section>"
    )


def _render_activity_summary(data: InvestigationReportData) -> str:
    hosts = ", ".join(e.host_id for e in data.endpoints[:10]) + ("…" if len(data.endpoints) > 10 else "")
    users = ", ".join(u.user for u in data.users[:10]) + ("…" if len(data.users) > 10 else "")
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Security Activity Summary</h1>'
        '<h2 class="section-title">Severity Distribution</h2>'
        f"{_severity_bar_chart(data.statistics.severity)}"
        '<h2 class="section-title">Alert Volume Over Time</h2>'
        f"{_daily_volume_chart(data.statistics.alerts_over_time)}"
        '<h2 class="section-title">Affected Assets</h2>'
        '<table class="kv-table">'
        f'<tr><th>Affected Hosts ({len(data.endpoints)})</th><td>{_esc(hosts) if hosts else "—"}</td></tr>'
        f'<tr><th>Affected Users ({len(data.users)})</th><td>{_esc(users) if users else "—"}</td></tr>'
        "</table>"
        "</section>"
    )


def _render_timeline(events: list) -> str:
    if not events:
        body = _empty_state("No chronological evidence is available in scope.")
    else:
        rows = []
        for e in events[:80]:
            severity_html = _severity_badge(e.severity) if e.severity else ""
            meta_parts = []
            if e.host:
                meta_parts.append(f"Host: {_esc(e.host)}")
            if e.user:
                meta_parts.append(f"User: {_esc(e.user)}")
            if e.reference:
                meta_parts.append(f"Ref: {_esc(e.reference)}")
            rows.append(
                '<div class="timeline-row">'
                f'<div class="timeline-time">{_fmt_dt(e.timestamp)}</div>'
                '<div class="timeline-marker"></div>'
                '<div class="timeline-body">'
                f'<div class="timeline-event-type">{_esc(e.event_type)} {severity_html}</div>'
                f'<div class="timeline-desc">{_esc(e.description)}</div>'
                f'<div class="timeline-meta">{"  ".join(meta_parts)}</div>'
                "</div></div>"
            )
        body = f'<div class="timeline">{"".join(rows)}</div>'
        if len(events) > 80:
            body += f'<p class="table-note">{len(events)} total timeline events; the 80 most recent are shown above.</p>'
    return f'<section class="content-section"><h1 class="page-title">Investigation Timeline</h1>{body}</section>'


def _render_attack_chain(chain) -> str:
    if chain is None or not chain.nodes:
        empty = _empty_state(
            "No relationship graph could be derived from the available evidence — either no incident is "
            "associated with this scope, or it has no linked alerts yet."
        )
        return f'<section class="content-section"><h1 class="page-title">Attack Chain</h1>{empty}</section>'

    progression = " → ".join(chain.progression[:8]) if chain.progression else "No ordered progression could be derived from the available edges."
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Attack Chain</h1>'
        f"{_attack_chain_legend()}"
        f'<div class="attack-chain-diagram">{_attack_chain_svg(chain)}</div>'
        '<h2 class="section-title">Observed Attack Progression</h2>'
        f'<p class="progression">{_esc(progression)}</p>'
        f'<p class="table-note">{len(chain.nodes)} node(s), {len(chain.grouped_edges)} distinct relationship(s) '
        f"from {len(chain.edges)} linked alert(s). Parallel relationships between the same pair of entities are "
        "grouped, matching the live application's own graph view.</p>"
        "</section>"
    )


def _render_behavior(findings: list) -> str:
    if not findings:
        empty = _empty_state("No suspicious behavior categories were matched against the available evidence.")
        return f'<section class="content-section"><h1 class="page-title">Behavior / Security Findings</h1>{empty}</section>'
    cards = []
    for f in findings:
        cards.append(
            '<div class="finding-card">'
            f'<div class="finding-header">{_severity_badge(f.severity)} <span class="finding-category">{_esc(f.category)}</span></div>'
            f'<p class="finding-desc">{_esc(f.description)}</p>'
            '<table class="finding-meta-table">'
            f"<tr><th>Affected Asset</th><td>{_esc(f.affected_asset)}</td></tr>"
            f'<tr><th>Affected User</th><td>{_esc(f.affected_user) if f.affected_user else "—"}</td></tr>'
            f"<tr><th>Evidence Count</th><td>{f.evidence_count}</td></tr>"
            f"<tr><th>Timestamp Range</th><td>{_fmt_dt(f.first_seen)} – {_fmt_dt(f.last_seen)}</td></tr>"
            "</table></div>"
        )
    return f'<section class="content-section"><h1 class="page-title">Behavior / Security Findings</h1>{"".join(cards)}</section>'


def _render_alerts(rows: list, total: int) -> str:
    if not rows:
        empty = _empty_state("No alerts are present in this scope.")
        return f'<section class="content-section"><h1 class="page-title">Alert Evidence</h1>{empty}</section>'
    if total > len(rows):
        note = (
            f"{total:,} alert(s) matched this investigation. The {len(rows)} highest-relevance alerts are "
            "displayed below (sorted by severity, then recency) — this table is a representative subset, "
            "not the complete dataset."
        )
    else:
        note = f"{total:,} alert(s) matched this investigation. All matching alerts are shown below."
    table_rows = [
        [
            _fmt_dt(r.timestamp), f'<span class="mono">{_esc(r.alert_id[:8])}</span>', _severity_badge(r.severity),
            _esc(r.log_type), f'<span class="mono">{_esc(r.host_id)}</span>', _esc(r.user),
            _esc(r.description[:90] + ("…" if len(r.description) > 90 else "")),
            _esc(r.mitre_technique) if r.mitre_technique else "—", _esc(r.status),
        ]
        for r in rows
    ]
    table = _table(
        ["Timestamp", "Alert ID", "Sev.", "Type", "Host", "User", "Description", "MITRE", "Status"],
        table_rows, "", col_widths=[11, 8, 8, 8, 12, 7, 31, 6, 9], table_class="alert-table",
    )
    return (
        '<section class="content-section landscape">'
        '<h1 class="page-title">Alert Evidence</h1>'
        f'<p class="table-note">{_esc(note)}</p>'
        f"{table}"
        "</section>"
    )


def _render_endpoints(endpoints: list) -> str:
    if not endpoints:
        empty = _empty_state("No endpoints are present in this scope.")
        return f'<section class="content-section"><h1 class="page-title">Endpoint Analysis</h1>{empty}</section>'
    cards = []
    for e in endpoints:
        level_badge = _severity_badge(e.risk_level) if e.risk_level else '<span class="badge">Not yet scored</span>'
        factors_html = (
            '<ul class="findings-list">' + "".join(f"<li>{_esc(f)}</li>" for f in e.risk_factors) + "</ul>"
            if e.risk_factors else _empty_state("No elevated risk factors were found in the available evidence.")
        )
        cards.append(
            '<div class="endpoint-card">'
            '<div class="endpoint-header">'
            f'<span class="mono endpoint-name">{_esc(e.host_id)}</span> {level_badge} '
            f'<span class="endpoint-score">{e.risk_score if e.risk_score is not None else "—"}</span>'
            "</div>"
            '<table class="finding-meta-table">'
            f"<tr><th>Critical</th><td>{e.severity.critical}</td><th>High</th><td>{e.severity.high}</td></tr>"
            f"<tr><th>Medium</th><td>{e.severity.medium}</td><th>Low</th><td>{e.severity.low}</td></tr>"
            f"<tr><th>After-hours events</th><td>{e.after_hours_count}</td><th>Associated incidents</th><td>{len(e.associated_incident_ids)}</td></tr>"
            "</table>"
            '<p class="why-risky-label">Why is this endpoint risky?</p>'
            f"{factors_html}"
            "</div>"
        )
    return f'<section class="content-section"><h1 class="page-title">Endpoint Analysis</h1>{"".join(cards)}</section>'


def _render_users(users: list) -> str:
    if not users:
        empty = _empty_state("No user activity is present in this scope.")
        return f'<section class="content-section"><h1 class="page-title">Users and Identity Activity</h1>{empty}</section>'
    rows = [
        [_esc(u.user), str(u.host_count), str(u.alert_count), str(u.failed_logins), str(u.successful_logins),
         str(u.after_hours_count), str(len(u.associated_incident_ids))]
        for u in users
    ]
    table = _table(["Username", "Hosts", "Alerts", "Failed Logins", "Successful Logins", "After-hours", "Incidents"], rows, "")
    suspicious = [u for u in users if u.failed_logins >= 3 or u.after_hours_count >= 3]
    suspicious_note = ""
    if suspicious:
        names = ", ".join(u.user for u in suspicious[:10])
        suspicious_note = (
            f'<p class="table-note">Suspicious identity activity: {_esc(names)} — elevated failed-login or '
            "after-hours activity relative to other users in scope.</p>"
        )
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Users and Identity Activity</h1>'
        f"{table}{suspicious_note}"
        "</section>"
    )


def _render_software(data) -> str:
    if not data.has_any_software:
        empty = _empty_state("No software inventory data available for the endpoint(s) in this scope.")
        return f'<section class="content-section"><h1 class="page-title">Software &amp; Vulnerabilities</h1>{empty}</section>'

    disclaimers = []
    if data.has_any_synthetic_vuln:
        disclaimers.append('Synthetic demonstration vulnerability data — findings marked "DEMO" are placeholders, not real CVE database records.')
    if data.has_any_real_vuln:
        disclaimers.append(
            'Findings marked "CVE" are real, publicly-documented vulnerabilities attached to intentionally '
            "outdated software versions for demonstration — not vulnerabilities discovered on a real production system."
        )
    disclaimer_html = "".join(f'<p class="ai-note">{_esc(d)}</p>' for d in disclaimers)

    by_severity: dict = {"critical": [], "high": [], "medium": [], "low": [], None: []}
    for row in data.rows:
        by_severity.setdefault(row.severity, []).append(row)

    sections = []
    for sev in ("critical", "high", "medium", "low"):
        group = by_severity.get(sev, [])
        if not group:
            continue
        rows = [
            [_esc(r.software), _esc(r.version), f'<span class="mono">{_esc(r.host_id)}</span>',
             f'<span class="mono">{_esc(r.vulnerability_id)}</span>', _esc(r.title or ""),
             "DEMO" if r.is_synthetic else "CVE"]
            for r in group
        ]
        table = _table(["Software", "Version", "Endpoint", "Vulnerability", "Description", "Status"], rows, "")
        sections.append(f'<h2 class="section-title">{sev.title()} ({len(group)})</h2>{table}')

    clean = by_severity.get(None, [])
    if clean:
        rows = [[_esc(r.software), _esc(r.version), f'<span class="mono">{_esc(r.host_id)}</span>', "None known"] for r in clean]
        table = _table(["Software", "Version", "Endpoint", "Vulnerability"], rows, "")
        sections.append(f'<h2 class="section-title">No Known Vulnerabilities</h2>{table}')

    return (
        '<section class="content-section">'
        '<h1 class="page-title">Software &amp; Vulnerabilities</h1>'
        f"{disclaimer_html}{''.join(sections)}"
        "</section>"
    )


def _render_mitre(rows: list) -> str:
    if not rows:
        empty = _empty_state("No MITRE ATT&CK techniques are associated with the available evidence.")
        return f'<section class="content-section"><h1 class="page-title">MITRE ATT&amp;CK Mapping</h1>{empty}</section>'
    table_rows = [
        [f'<span class="mono">{_esc(r.technique_id)}</span>', _esc(r.tactic), _esc(r.evidence_description),
         f'<span class="mono">{_esc(r.affected_host)}</span>', f'<span class="mono">{_esc(r.related_alert)}</span>']
        for r in rows
    ]
    table = _table(["Technique ID", "Tactic", "Observed Evidence", "Affected Host", "Related Alert"], table_rows, "")
    return (
        '<section class="content-section">'
        '<h1 class="page-title">MITRE ATT&amp;CK Mapping</h1>'
        '<p class="table-note">Only techniques actually present on evidence in scope are listed — none are inferred.</p>'
        f"{table}"
        "</section>"
    )


def _render_network(rows: list) -> str:
    if not rows:
        empty = _empty_state("No network destination telemetry (source/destination IP) is available in this scope.")
        return f'<section class="content-section"><h1 class="page-title">Network / Communication Activity</h1>{empty}</section>'
    table_rows = []
    for r in rows:
        if r.classification == "Malicious":
            bg, fg = "#ef444422", "#ef4444"
        elif r.classification == "Clean":
            bg, fg = "#22c55e22", "#22c55e"
        else:
            bg, fg = "#94a3b822", "#64748b"
        table_rows.append([
            f'<span class="mono">{_esc(r.source_host)}</span>', f'<span class="mono">{_esc(r.destination_ip)}</span>',
            str(r.port) if r.port else "—", _esc(r.protocol) if r.protocol else "—", str(r.event_count),
            f'<span class="badge" style="background:{bg};color:{fg}">{_esc(r.classification)}</span>',
        ])
    table = _table(["Source Host", "Destination IP", "Port", "Protocol", "Event Count", "Classification"], table_rows, "")
    return f'<section class="content-section"><h1 class="page-title">Network / Communication Activity</h1>{table}</section>'


def _render_investigation(findings) -> str:
    if findings.qa:
        qa_html = []
        for q in findings.qa:
            fallback_note = (
                '<p class="ai-note">Deterministic summary (AI summarizer unavailable at the time this question was asked).</p>'
                if q.is_fallback else ""
            )
            qa_html.append(
                '<div class="qa-block">'
                f'<p class="qa-question">Q: {_esc(q.question)}</p>'
                f'<p class="qa-answer">{_esc(q.answer)}</p>'
                f"{fallback_note}"
                "</div>"
            )
        body = (
            '<p class="table-note">The following questions were asked of the SafeSOC Investigation Assistant '
            "during this analyst's session, and are included verbatim with their evidence-grounded answers.</p>"
            + "".join(qa_html)
        )
    elif findings.has_data:
        if findings.narrative_is_fallback:
            note = (
                '<p class="ai-note">Deterministic summary — the AI summarizer was unavailable or no active '
                "investigation session was captured for this report.</p>"
            )
        else:
            note = '<p class="ai-note">AI-generated summary, grounded in the evidence gathered for this report.</p>'
        body = f'{note}<p class="narrative">{_esc(_finish_sentence(findings.narrative))}</p>'
    else:
        body = _empty_state("Evidence insufficient to determine this.")
    return f'<section class="content-section"><h1 class="page-title">Investigation / AI Analyst Findings</h1>{body}</section>'


def _render_recommendation_group(title: str, items: list) -> str:
    rows = []
    for r in items:
        rows.append(
            '<div class="reco-item">'
            f'<div class="reco-observed"><span class="reco-label">OBSERVED</span> {_esc(r.observed)}</div>'
            f'<div class="reco-recommended"><span class="reco-label reco-label-action">RECOMMENDED</span> {_esc(r.recommended)}</div>'
            "</div>"
        )
    return f'<h2 class="section-title">{_esc(title)}</h2>{"".join(rows)}'


def _render_recommendations(rec) -> str:
    long_term = "".join(f"<li>{_esc(item)}</li>" for item in rec.long_term)
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Response / Recommendations</h1>'
        f'{_render_recommendation_group("Immediate Actions", rec.immediate)}'
        f'{_render_recommendation_group("Investigation Actions", rec.investigation)}'
        f'{_render_recommendation_group("Containment Recommendations", rec.containment)}'
        '<h2 class="section-title">Long-Term Improvements</h2>'
        f'<ul class="findings-list">{long_term}</ul>'
        "</section>"
    )


def _render_appendix(data: InvestigationReportData) -> str:
    a = data.appendix
    user_ids_display = ", ".join(a.user_ids[:20]) + ("…" if len(a.user_ids) > 20 else "")
    rows = [
        ("Incident ID(s)", ", ".join(a.incident_ids) or "None"),
        ("Endpoint ID(s)", ", ".join(a.endpoint_ids) or "None"),
        ("User ID(s)", user_ids_display or "None"),
        ("MITRE Technique(s)", ", ".join(a.mitre_technique_ids) or "None"),
        ("Evidence Alert Count", str(a.evidence_alert_count)),
        ("Report Generated", _fmt_dt(data.metadata.generated_at)),
        ("Data Source", "SafeSOC — synthetic demonstration telemetry" if data.metadata.is_synthetic else "SafeSOC — live telemetry"),
    ]
    table_rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in rows)
    synthetic_note = ""
    if data.metadata.is_synthetic:
        synthetic_note = (
            '<p class="ai-note">This environment contains synthetic demonstration telemetry and does not '
            "represent a real organization's security events.</p>"
        )
    return (
        '<section class="content-section">'
        '<h1 class="page-title">Appendix / Evidence Summary</h1>'
        f'<table class="kv-table">{table_rows}</table>'
        '<p class="narrative">This report contains findings generated from the telemetry available to '
        "SafeSOC at the time of analysis.</p>"
        f"{synthetic_note}"
        "</section>"
    )


_CSS = """
@page {
  size: A4;
  margin: 22mm 16mm 20mm 16mm;
  @top-center {
    content: "SafeSOC — Security Investigation Report";
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #64748b;
  }
  @bottom-center {
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #64748b;
  }
}
@page :first {
  margin: 0;
  @top-center { content: none; }
  @bottom-center { content: none; }
}
@page evidence-landscape {
  size: A4 landscape;
  margin: 16mm 16mm 18mm 16mm;
  @top-center {
    content: "SafeSOC — Security Investigation Report";
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #64748b;
  }
  @bottom-center {
    content: "Page " counter(page) " of " counter(pages);
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 8pt;
    color: #64748b;
  }
}
* { box-sizing: border-box; }
body {
  font-family: 'Segoe UI', Arial, sans-serif;
  color: #1e293b;
  font-size: 9.5pt;
  line-height: 1.5;
  margin: 0;
}
.mono { font-family: 'Consolas', 'Courier New', monospace; font-size: 0.92em; }

/* ── Cover page ─────────────────────────────────────────── */
.cover-page {
  page: cover;
  break-after: page;
  background: #0b1220;
  color: #f1f5f9;
  height: 297mm;
  width: 210mm;
  padding: 60mm 24mm 0 24mm;
  display: flex;
  flex-direction: column;
}
.cover-brand {
  color: #0ea5e9;
  font-size: 16pt;
  font-weight: 700;
  letter-spacing: 0.12em;
  margin-bottom: 6mm;
}
.cover-title {
  font-size: 26pt;
  font-weight: 300;
  color: #f8fafc;
  margin-bottom: 10mm;
  border-bottom: 1px solid #1e293b;
  padding-bottom: 8mm;
}
.cover-scope { font-size: 13pt; color: #cbd5e1; margin-bottom: 8mm; }
.cover-risk { margin-bottom: 8mm; }
.cover-risk-score {
  font-size: 34pt;
  font-weight: 700;
  color: #f8fafc;
  margin-right: 4mm;
}
.cover-risk-level { font-size: 12pt; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
.cover-classification {
  display: inline-block;
  margin-top: 4mm;
  padding: 2mm 5mm;
  border: 1px solid #ef4444;
  color: #ef4444;
  font-size: 9pt;
  font-weight: 700;
  letter-spacing: 0.08em;
  width: fit-content;
}
.cover-footer {
  margin-top: auto;
  padding-top: 10mm;
  border-top: 1px solid #1e293b;
  font-size: 8.5pt;
  color: #64748b;
  display: flex;
  justify-content: space-between;
}

/* ── Section layout ─────────────────────────────────────── */
.content-section { break-before: page; }
.content-section:first-of-type { break-before: avoid; }
.content-section.landscape { page: evidence-landscape; }
.page-title {
  font-size: 16pt;
  font-weight: 600;
  color: #0b1220;
  border-bottom: 2px solid #0ea5e9;
  padding-bottom: 3mm;
  margin: 0 0 6mm 0;
}
.section-title {
  font-size: 11.5pt;
  font-weight: 600;
  color: #0f172a;
  margin: 7mm 0 3mm 0;
}

/* ── Tables ──────────────────────────────────────────────── */
table { width: 100%; table-layout: fixed; border-collapse: collapse; margin-bottom: 4mm; font-size: 8.8pt; }
th, td {
  border: 1px solid #e2e8f0;
  padding: 1.6mm 2.4mm;
  text-align: left;
  vertical-align: top;
  overflow-wrap: break-word;
  overflow: hidden;
}
th { background: #f1f5f9; color: #334155; font-weight: 600; }
table.kv-table th { width: 38%; background: #f8fafc; color: #475569; }
table.alert-table th { white-space: nowrap; font-size: 7.6pt; padding: 1.6mm 1.6mm; }
.table-note { font-size: 8.3pt; color: #64748b; font-style: italic; margin: -1mm 0 3mm 0; }

/* ── Badges ──────────────────────────────────────────────── */
.badge {
  display: inline-block;
  max-width: 100%;
  overflow-wrap: break-word;
  padding: 0.5mm 2.2mm;
  border-radius: 2mm;
  font-size: 7.8pt;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

/* ── Notes / narrative ───────────────────────────────────── */
.ai-note {
  font-size: 8.3pt;
  color: #0369a1;
  background: #f0f9ff;
  border-left: 2px solid #0ea5e9;
  padding: 2mm 3mm;
  margin: 0 0 3mm 0;
}
.narrative { font-size: 9.5pt; color: #1e293b; margin: 0 0 4mm 0; }
.empty-state {
  color: #94a3b8;
  font-style: italic;
  padding: 4mm 0;
  border: 1px dashed #cbd5e1;
  text-align: center;
  border-radius: 1mm;
  margin-bottom: 3mm;
}
.findings-list { margin: 0 0 3mm 0; padding-left: 5mm; }
.findings-list li { margin-bottom: 1.2mm; }

/* ── Executive summary stat grid ─────────────────────────── */
.stat-grid { display: flex; flex-wrap: wrap; gap: 2mm; margin-bottom: 4mm; }
.stat-box {
  flex: 1 0 28%;
  border: 1px solid #e2e8f0;
  border-top: 2px solid #0ea5e9;
  padding: 2.2mm 3mm;
}
.stat-label { font-size: 7.5pt; color: #64748b; text-transform: uppercase; letter-spacing: 0.03em; }
.stat-value { font-size: 11pt; font-weight: 600; color: #0f172a; margin-top: 0.6mm; }

/* ── Bar charts ──────────────────────────────────────────── */
.bar-chart { margin-bottom: 4mm; }
.bar-row { display: flex; align-items: center; gap: 2mm; margin-bottom: 1.6mm; }
.bar-label { width: 16mm; font-size: 8.3pt; color: #475569; text-transform: capitalize; }
.bar-track { flex: 1; background: #f1f5f9; height: 4mm; border-radius: 0.5mm; overflow: hidden; }
.bar-fill { height: 100%; }
.bar-value { width: 10mm; text-align: right; font-size: 8.3pt; color: #334155; }

.vol-chart { display: flex; align-items: stretch; gap: 1mm; height: 34mm; margin-bottom: 2mm; border-bottom: 1px solid #e2e8f0; padding-bottom: 1mm; }
.vol-bar { flex: 1; display: flex; flex-direction: column; align-items: center; max-width: 14mm; }
.vol-bar-count { font-size: 7pt; font-weight: 600; color: #334155; margin-bottom: 0.8mm; }
.vol-bar-track { flex: 1; width: 65%; display: flex; align-items: flex-end; }
.vol-bar-fill { width: 100%; background: #0ea5e9; min-height: 0.5mm; }
.vol-bar-label { font-size: 6.5pt; color: #94a3b8; margin-top: 1mm; white-space: nowrap; }

/* ── Timeline ────────────────────────────────────────────── */
.timeline { border-left: 2px solid #e2e8f0; margin-left: 2mm; padding-left: 4mm; }
.timeline-row { position: relative; margin-bottom: 4mm; break-inside: avoid; }
.timeline-marker {
  position: absolute;
  left: -6.6mm;
  top: 0.8mm;
  width: 2.4mm;
  height: 2.4mm;
  border-radius: 50%;
  background: #0ea5e9;
}
.timeline-time { font-size: 7.8pt; color: #64748b; font-family: 'Consolas', monospace; }
.timeline-event-type { font-weight: 600; color: #0f172a; font-size: 9.2pt; }
.timeline-desc { font-size: 8.8pt; color: #334155; margin-top: 0.4mm; }
.timeline-meta { font-size: 7.8pt; color: #64748b; margin-top: 0.4mm; }

/* ── Attack chain ────────────────────────────────────────── */
.attack-chain-diagram { text-align: center; margin-bottom: 3mm; border: 1px solid #e2e8f0; padding: 3mm; }
.attack-chain-diagram svg { max-width: 100%; height: auto; }
.legend { display: flex; gap: 5mm; margin-bottom: 3mm; font-size: 8pt; color: #475569; }
.legend-item { display: flex; align-items: center; gap: 1.5mm; }
.legend-dot { width: 2.6mm; height: 2.6mm; border-radius: 50%; display: inline-block; }
.progression {
  font-size: 9pt;
  color: #0f172a;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  padding: 2.5mm 3.5mm;
  margin-bottom: 2mm;
}

/* ── Finding cards ───────────────────────────────────────── */
.finding-card { border: 1px solid #e2e8f0; border-left: 3px solid #0ea5e9; padding: 3mm; margin-bottom: 3mm; break-inside: avoid; }
.finding-header { margin-bottom: 1.5mm; }
.finding-category { font-weight: 600; color: #0f172a; margin-left: 1.5mm; }
.finding-desc { font-size: 8.8pt; color: #334155; margin: 0 0 2mm 0; }
.finding-meta-table { margin-bottom: 0; }
.finding-meta-table th { width: 32%; }

/* ── Endpoint cards ──────────────────────────────────────── */
.endpoint-card { border: 1px solid #e2e8f0; padding: 3mm; margin-bottom: 3mm; break-inside: avoid; }
.endpoint-header { display: flex; align-items: center; gap: 2.5mm; margin-bottom: 2mm; }
.endpoint-name { font-size: 10pt; font-weight: 600; color: #0f172a; }
.endpoint-score { margin-left: auto; font-size: 13pt; font-weight: 700; color: #0f172a; }
.why-risky-label { font-size: 8.8pt; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.03em; margin: 2mm 0 1.5mm 0; }

/* ── Investigation Q&A ───────────────────────────────────── */
.qa-block { border: 1px solid #e2e8f0; padding: 3mm; margin-bottom: 3mm; break-inside: avoid; }
.qa-question { font-weight: 600; color: #0f172a; margin: 0 0 1.5mm 0; font-size: 9pt; }
.qa-answer { font-size: 8.8pt; color: #334155; margin: 0; }

/* ── Recommendations ─────────────────────────────────────── */
.reco-item { border: 1px solid #e2e8f0; padding: 2.5mm 3mm; margin-bottom: 2.5mm; break-inside: avoid; }
.reco-observed, .reco-recommended { font-size: 8.8pt; margin: 0.6mm 0; }
.reco-observed { color: #475569; }
.reco-recommended { color: #0f172a; }
.reco-label {
  display: inline-block;
  font-size: 7pt;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: #64748b;
  background: #f1f5f9;
  padding: 0.3mm 1.6mm;
  border-radius: 1mm;
  margin-right: 1.5mm;
}
.reco-label-action { color: #ffffff; background: #0ea5e9; }
"""


def render_investigation_report_html(data: InvestigationReportData) -> str:
    sections = [
        _render_cover(data),
        _render_executive_summary(data),
        _render_overview(data),
        _render_activity_summary(data),
        _render_timeline(data.timeline),
        _render_attack_chain(data.attack_chain),
        _render_behavior(data.behavior_findings),
        _render_alerts(data.alerts, data.alerts_total),
        _render_endpoints(data.endpoints),
        _render_users(data.users),
        _render_software(data.software),
        _render_mitre(data.mitre),
        _render_network(data.network),
        _render_investigation(data.investigation),
        _render_recommendations(data.recommendations),
        _render_appendix(data),
    ]
    scope_label = _esc(data.metadata.scope_name)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>SafeSOC Security Investigation Report — {scope_label}</title>"
        f"<style>{_CSS}</style>"
        "</head><body>"
        f"{''.join(sections)}"
        "</body></html>"
    )
