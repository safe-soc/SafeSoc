"""
SafeSOC — MITRE ATT&CK Pattern Mapping
Static lookup from each correlation pattern type (SS-028) to its MITRE
ATT&CK technique/tactic IDs — data, not inline strings scattered
through correlation.py.

An incident carries MITRE technique ids from two independent sources,
and a view that reads only one of them under-reports:

  * alert-level — `mitre_technique` on the alert document, set by the
    ingest adapters (adapters/wazuh.py carries Wazuh's own rule
    mapping, and comma-joins several ids into ONE string:
    "T1110.001, T1021.004"). Synthetic/injector alerts have no such
    field at all, so this source is frequently empty.
  * pattern-level — MITRE_PATTERN_MAPPING below, resolved through
    `Incident.category` (the correlation pattern that created the
    incident). Present for every correlated incident, whatever its
    alerts carry.

split_technique_ids() / techniques_for_category() / incident_technique_ids()
below are the shared readers for those two sources, so every incident
view reports the same technique list.
"""

from dataclasses import dataclass
from typing import Iterable, Optional

from app.core.enums import CorrelationPattern


@dataclass(frozen=True)
class MitreTechnique:
    technique_ids: tuple[str, ...]
    tactic: str


MITRE_PATTERN_MAPPING: dict[CorrelationPattern, MitreTechnique] = {
    CorrelationPattern.CREDENTIAL_BRUTE_FORCE: MitreTechnique(
        technique_ids=("T1110",), tactic="Credential Access"
    ),
    # The detector observes repeated failed logons FOLLOWED BY a
    # success (services/correlation.py), so the brute-force attempt
    # itself (T1110) is part of what was detected — not just the use
    # of the valid account it produced (T1078).
    CorrelationPattern.SUCCESSFUL_COMPROMISE: MitreTechnique(
        technique_ids=("T1110", "T1078"), tactic="Initial Access"
    ),
    CorrelationPattern.RECON_TO_EXPLOITATION: MitreTechnique(
        technique_ids=("T1595", "T1190"), tactic="Reconnaissance"
    ),
    # The detector observes a login followed by a high/critical
    # privilege-context change — nothing in that signal indicates a
    # software exploit, so T1068 (Exploitation for Privilege
    # Escalation) overstated it. T1548 (Abuse Elevation Control
    # Mechanism) is what the evidence actually supports.
    CorrelationPattern.PRIVILEGE_ESCALATION: MitreTechnique(
        technique_ids=("T1548",), tactic="Privilege Escalation"
    ),
    CorrelationPattern.DATA_EXFILTRATION: MitreTechnique(
        technique_ids=("T1041",), tactic="Exfiltration"
    ),
    CorrelationPattern.LATERAL_MOVEMENT: MitreTechnique(
        technique_ids=("T1021",), tactic="Lateral Movement"
    ),
}


def get_mitre_technique(pattern: CorrelationPattern) -> MitreTechnique:
    """Look up the MITRE ATT&CK technique(s)/tactic for a detected correlation pattern."""
    return MITRE_PATTERN_MAPPING[pattern]


def split_technique_ids(raw: Optional[str]) -> list[str]:
    """
    One alert's `mitre_technique` value as a list of ids. Handles both
    shapes the field takes: a single id ("T1110", what the correlation
    engine and the injector write) and adapters/wazuh.py's comma-joined
    multi-technique string ("T1110.001, T1021.004").
    """
    if not raw:
        return []
    return [technique.strip() for technique in raw.split(",") if technique.strip()]


def techniques_for_category(category: Optional[CorrelationPattern]) -> tuple[str, ...]:
    """The pattern-level technique ids for an incident's category — () for an uncategorized incident."""
    if category is None:
        return ()
    return get_mitre_technique(category).technique_ids


def incident_technique_ids(
    alert_techniques: Iterable[Optional[str]], category: Optional[CorrelationPattern]
) -> list[str]:
    """
    Every MITRE technique id an incident is associated with: the union
    of its alerts' own ids and its category's mapped ids, sorted and
    de-duplicated. The single reader every incident view should use —
    reading either source alone silently drops techniques.
    """
    ids = {
        technique
        for raw in alert_techniques
        for technique in split_technique_ids(raw)
    }
    ids.update(techniques_for_category(category))
    return sorted(ids)
