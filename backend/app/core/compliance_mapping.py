"""
SafeSOC — Indian Regulatory Compliance Mapping
Static lookup of the regulatory requirements the Compliance Center
assesses evidence against — data, not inline strings scattered through
services/compliance.py — following core/mitre_mapping.py's own
established pattern for a fixed, rarely-changing reference table.

Deliberately NOT a database table (Phase 1 architecture decision,
approved before implementation): this is legal-text mapping that is
the same for every tenant and changes only when a law/direction
itself changes, not application state. A migration would be the wrong
tool for that. The tenant-specific, frequently-changing part —
whether/how much SafeSOC evidence exists for a given requirement right
now — is computed live by services/compliance.py from existing
evidence sources and is never stored here or anywhere else.

Every requirement below traces to a specific authoritative source
researched before implementation (see docs/compliance.md for the full
citation list and sourcing caveats). Nothing here is invented: where
no directly-applicable SafeSOC evidence or DPIIT technical control
exists, the requirement says so explicitly (evidence_type="none",
NOT_ASSESSABLE) rather than fabricating one.

IMPORTANT — this module describes what the LAW requires, in plain
language. It never says whether an organization complies with it.
That determination is always organizational/legal, never SafeSOC's to
make — see services/compliance.py's own module docstring and
docs/compliance.md.
"""

from dataclasses import dataclass

from app.core.enums import ComplianceFramework


@dataclass(frozen=True)
class ComplianceRequirement:
    id: str
    framework: ComplianceFramework
    title: str
    reference: str
    authoritative_source: str
    requirement_summary: str
    what_safesoc_can_observe: str
    what_safesoc_cannot_verify: str
    # A short tag identifying which live-evidence computation in
    # services/compliance.py applies (e.g. "access_control",
    # "log_monitoring") — not a DB/UI concern, just a dispatch key.
    evidence_type: str


FRAMEWORK_TITLES: dict[ComplianceFramework, str] = {
    ComplianceFramework.DPDP_ACT_2023: "Digital Personal Data Protection Act, 2023",
    ComplianceFramework.CERT_IN_DIRECTIONS_2022: "CERT-In Directions dated 28.04.2022",
    ComplianceFramework.DPIIT: "DPIIT / Other Applicable Requirements",
}

COMPLIANCE_REQUIREMENTS: list[ComplianceRequirement] = [
    # ── Digital Personal Data Protection Act, 2023 (+ DPDP Rules, 2025) ──
    ComplianceRequirement(
        id="DPDP-R1",
        framework=ComplianceFramework.DPDP_ACT_2023,
        title="Access control on personal data",
        reference="Section 8(5); DPDP Rules, 2025 — Rule 6(a)",
        authoritative_source=(
            "Digital Personal Data Protection Act, 2023, Section 8 "
            "(https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf); "
            "DPDP Rules, 2025, Rule 6"
        ),
        requirement_summary=(
            "A Data Fiduciary must take reasonable security safeguards to prevent a personal data "
            "breach, including — per Rule 6(a) — controlling access to computer resources that "
            "process personal data."
        ),
        what_safesoc_can_observe=(
            "Whether SafeSOC itself enforces role-based access control and authenticated access to "
            "the security data it holds."
        ),
        what_safesoc_cannot_verify=(
            "This only demonstrates SafeSOC's own access control over SafeSOC application data. It "
            "does not establish access control across the customer's wider IT/data environment "
            "(file shares, email, third-party SaaS, databases outside SafeSOC, etc.) — those remain "
            "an organizational responsibility outside SafeSOC's visibility."
        ),
        evidence_type="access_control",
    ),
    ComplianceRequirement(
        id="DPDP-R2",
        framework=ComplianceFramework.DPDP_ACT_2023,
        title="Logging and monitoring for detection, investigation, and remediation",
        reference="Section 8(5); DPDP Rules, 2025 — Rule 6(c)",
        authoritative_source=(
            "Digital Personal Data Protection Act, 2023, Section 8(5); "
            "DPDP Rules, 2025, Rule 6(c) (https://www.dpdpa.com/dpdparules/rule6.html)"
        ),
        requirement_summary=(
            "Reasonable security safeguards must include maintaining logs and visibility of access "
            "to computer resources that process personal data, to enable detection, investigation, "
            "and remediation of unauthorised access."
        ),
        what_safesoc_can_observe=(
            "Volume and recency of SafeSOC's own audit trail, detected alerts, opened incidents, and "
            "investigation activity (sessions, confirmed findings, completed actions) for this tenant."
        ),
        what_safesoc_cannot_verify=(
            "SafeSOC can only see logging/monitoring activity that flows through SafeSOC itself. Any "
            "detection, investigation, or remediation activity conducted entirely outside SafeSOC is "
            "invisible to this assessment."
        ),
        evidence_type="log_monitoring",
    ),
    ComplianceRequirement(
        id="DPDP-R3",
        framework=ComplianceFramework.DPDP_ACT_2023,
        title="Encryption, tokenisation, and backups",
        reference="DPDP Rules, 2025 — Rule 6(b), (d)",
        authoritative_source="DPDP Rules, 2025, Rule 6(b) and 6(d) (https://www.dpdpa.com/dpdparules/rule6.html)",
        requirement_summary=(
            "Reasonable security safeguards must include measures such as encrypting, obfuscating, "
            "masking, or tokenising personal data, and maintaining backups to ensure continued "
            "processing in the event of a compromise."
        ),
        what_safesoc_can_observe="Nothing — SafeSOC has no visibility into encryption configuration or backup operations.",
        what_safesoc_cannot_verify=(
            "Encryption/tokenisation and backup practices are infrastructure- and deployment-level "
            "controls (disk/TLS encryption, database configuration, backup jobs) entirely outside "
            "SafeSOC's application telemetry. SafeSOC does not attempt to infer their presence or "
            "adequacy from application logs — doing so would not be a sound inference. Requires "
            "organizational/infrastructure verification."
        ),
        evidence_type="none",
    ),
    ComplianceRequirement(
        id="DPDP-R4",
        framework=ComplianceFramework.DPDP_ACT_2023,
        title="Data Processor contractual safeguards",
        reference="DPDP Rules, 2025 — Rule 6(e)",
        authoritative_source="DPDP Rules, 2025, Rule 6(e) (https://www.dpdpa.com/dpdparules/rule6.html)",
        requirement_summary=(
            "A Data Fiduciary must ensure, including through contractual arrangements, that any Data "
            "Processor engaged on its behalf implements equivalent reasonable security safeguards."
        ),
        what_safesoc_can_observe="Nothing — this is a contractual relationship, not a technical control.",
        what_safesoc_cannot_verify=(
            "Whether Data Processor contracts exist and contain adequate security clauses is an "
            "organizational/legal matter with no technical telemetry signature at all. Requires "
            "organizational/legal verification."
        ),
        evidence_type="none",
    ),
    ComplianceRequirement(
        id="DPDP-R5",
        framework=ComplianceFramework.DPDP_ACT_2023,
        title="Personal data breach notification",
        reference="Section 8(6)",
        authoritative_source="Digital Personal Data Protection Act, 2023, Section 8(6) (https://indiankanoon.org/doc/186118625/)",
        requirement_summary=(
            "In the event of a personal data breach, the Data Fiduciary must give the Data Protection "
            "Board of India and each affected Data Principal intimation of the breach, in the form and "
            "manner prescribed."
        ),
        what_safesoc_can_observe=(
            "That a security incident was detected and tracked through its lifecycle (open → "
            "investigating → resolved), which can inform a breach-notification decision."
        ),
        what_safesoc_cannot_verify=(
            "SafeSOC does NOT submit notifications to the Data Protection Board or to affected Data "
            "Principals, and cannot verify whether any such notification occurred, was timely, or was "
            "adequate. That determination and action are entirely organizational/legal."
        ),
        evidence_type="breach_notification",
    ),
    # ── CERT-In Directions dated 28.04.2022 (Section 70B, IT Act, 2000) ──
    ComplianceRequirement(
        id="CERTIN-R1",
        framework=ComplianceFramework.CERT_IN_DIRECTIONS_2022,
        title="Mandatory reporting of specified cyber incidents within 6 hours",
        reference="Direction, para 2; Annexure I",
        authoritative_source=(
            "CERT-In Directions No. 20(3)/2022-CERT-In dated 28.04.2022, issued under Section 70B(6) "
            "of the Information Technology Act, 2000 "
            "(https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf); corroborated via "
            "secondary legal summaries — see docs/compliance.md for sourcing caveats."
        ),
        requirement_summary=(
            "Specified categories of cyber security incidents (Annexure I — e.g. data breaches, data "
            "leaks, ransomware, unauthorised access, phishing) must be reported to CERT-In within 6 "
            "hours of being noticed or brought to notice."
        ),
        what_safesoc_can_observe=(
            "When an incident was detected (created_at), its severity, and its detected correlation "
            "category/pattern — supporting a timeliness assessment for a manual CERT-In filing."
        ),
        what_safesoc_cannot_verify=(
            "SafeSOC provides evidence to support a reporting decision but does NOT submit the CERT-In "
            "report itself, and has no way to know whether, or how quickly, a report was actually "
            "filed. Coverage of the full Annexure I category list from SafeSOC's own detection logic "
            "is also partial, not exhaustive."
        ),
        evidence_type="incident_reporting_timeliness",
    ),
    ComplianceRequirement(
        id="CERTIN-R2",
        framework=ComplianceFramework.CERT_IN_DIRECTIONS_2022,
        title="Mandatory log retention (180 days, within Indian jurisdiction)",
        reference="Direction, para 4",
        authoritative_source=(
            "CERT-In Directions No. 20(3)/2022-CERT-In dated 28.04.2022 "
            "(https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf); corroborated via "
            "secondary legal summaries — see docs/compliance.md for sourcing caveats."
        ),
        requirement_summary=(
            "Service providers, intermediaries, data centres, body corporates, and government "
            "organisations must enable logs of all ICT systems and maintain them securely for a "
            "rolling period of 180 days, within Indian jurisdiction."
        ),
        what_safesoc_can_observe=(
            "The actual configured alert-log retention period SafeSOC itself is set to keep "
            "(settings.OPENSEARCH_ILM_RETENTION_DAYS), compared against the 180-day requirement."
        ),
        what_safesoc_cannot_verify=(
            "SafeSOC only controls retention for the alert logs it stores — not every ICT system log "
            "the Direction covers. It also cannot verify the physical/legal jurisdiction of the "
            "underlying log storage; a configured retention period meeting or exceeding 180 days does "
            "NOT establish that storage is within Indian jurisdiction. Requires organizational/"
            "infrastructure verification."
        ),
        evidence_type="log_retention",
    ),
    ComplianceRequirement(
        id="CERTIN-R3",
        framework=ComplianceFramework.CERT_IN_DIRECTIONS_2022,
        title="ICT system clock synchronization",
        reference="Direction, para 5",
        authoritative_source=(
            "CERT-In Directions No. 20(3)/2022-CERT-In dated 28.04.2022 "
            "(https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf); corroborated via "
            "secondary legal summaries — see docs/compliance.md for sourcing caveats."
        ),
        requirement_summary=(
            "All ICT system clocks must be synchronized with the Network Time Protocol (NTP) server "
            "of the National Informatics Centre (NIC) or National Physical Laboratory (NPL), or "
            "servers traceable to them."
        ),
        what_safesoc_can_observe="Nothing — this is an operating-system/infrastructure-level configuration.",
        what_safesoc_cannot_verify=(
            "Clock synchronization source is not represented anywhere in SafeSOC's data model or "
            "telemetry. Requires organizational/infrastructure verification."
        ),
        evidence_type="none",
    ),
    ComplianceRequirement(
        id="CERTIN-R4",
        framework=ComplianceFramework.CERT_IN_DIRECTIONS_2022,
        title="Designated point of contact with CERT-In",
        reference="Direction, para 3",
        authoritative_source=(
            "CERT-In Directions No. 20(3)/2022-CERT-In dated 28.04.2022 "
            "(https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf); corroborated via "
            "secondary legal summaries — see docs/compliance.md for sourcing caveats."
        ),
        requirement_summary="Covered entities must designate a point of contact to interface with CERT-In.",
        what_safesoc_can_observe="Nothing — this is an administrative/organizational designation.",
        what_safesoc_cannot_verify="Whether a point of contact has been designated has no technical telemetry signature. Requires organizational verification.",
        evidence_type="none",
    ),
    # ── DPIIT / Other Applicable Requirements ──
    ComplianceRequirement(
        id="DPIIT-R1",
        framework=ComplianceFramework.DPIIT,
        title="DPIIT applicability",
        reference="N/A",
        authoritative_source=(
            "Department for Promotion of Industry and Internal Trade — official mandate document "
            "(https://www.dpiit.gov.in/static/uploads/2025/06/65688c315685d1869f6cf98c12e6c468.pdf)"
        ),
        requirement_summary=(
            "DPIIT (Ministry of Commerce and Industry) is India's industrial-policy and startup-"
            "recognition body — its mandate covers investment promotion, Make in India, Startup India "
            "recognition, logistics policy, and intellectual property rights."
        ),
        what_safesoc_can_observe="Not applicable.",
        what_safesoc_cannot_verify=(
            "No directly applicable DPIIT cybersecurity technical control was identified for this "
            "assessment. DPIIT is not being treated as a cybersecurity control framework. "
            "Cybersecurity technical directions for Indian entities are issued by MeitY/CERT-In and "
            "under the DPDP Act's own rules — see the DPDP Act and CERT-In Directions requirements "
            "above, which apply to DPIIT-recognized entities the same as any other."
        ),
        evidence_type="none",
    ),
]

_REQUIREMENTS_BY_ID: dict[str, ComplianceRequirement] = {req.id: req for req in COMPLIANCE_REQUIREMENTS}


def get_requirement(requirement_id: str) -> ComplianceRequirement | None:
    """Look up a static requirement definition by id (e.g. "DPDP-R2"). None if unknown."""
    return _REQUIREMENTS_BY_ID.get(requirement_id)
