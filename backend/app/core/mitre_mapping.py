"""
SafeSOC — MITRE ATT&CK Pattern Mapping
Static lookup from each correlation pattern type (SS-028) to its MITRE
ATT&CK technique/tactic IDs — data, not inline strings scattered
through correlation.py.
"""

from dataclasses import dataclass

from app.core.enums import CorrelationPattern


@dataclass(frozen=True)
class MitreTechnique:
    technique_ids: tuple[str, ...]
    tactic: str


MITRE_PATTERN_MAPPING: dict[CorrelationPattern, MitreTechnique] = {
    CorrelationPattern.CREDENTIAL_BRUTE_FORCE: MitreTechnique(
        technique_ids=("T1110",), tactic="Credential Access"
    ),
    CorrelationPattern.SUCCESSFUL_COMPROMISE: MitreTechnique(
        technique_ids=("T1078",), tactic="Initial Access"
    ),
    CorrelationPattern.RECON_TO_EXPLOITATION: MitreTechnique(
        technique_ids=("T1595", "T1190"), tactic="Reconnaissance"
    ),
    CorrelationPattern.PRIVILEGE_ESCALATION: MitreTechnique(
        technique_ids=("T1068",), tactic="Privilege Escalation"
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
