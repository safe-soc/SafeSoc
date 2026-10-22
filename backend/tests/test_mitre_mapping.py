"""
SafeSOC — MITRE ATT&CK Mapping Tests
"""

import re

import pytest

from app.core.enums import CorrelationPattern
from app.core.mitre_mapping import (
    MITRE_PATTERN_MAPPING,
    get_mitre_technique,
    incident_technique_ids,
    split_technique_ids,
    techniques_for_category,
)

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@pytest.mark.parametrize("pattern", list(CorrelationPattern))
def test_every_correlation_pattern_resolves_to_at_least_one_technique_id(pattern):
    mapping = get_mitre_technique(pattern)

    assert len(mapping.technique_ids) >= 1


def test_mapping_covers_every_pattern_exactly_once():
    assert set(MITRE_PATTERN_MAPPING.keys()) == set(CorrelationPattern)


@pytest.mark.parametrize("pattern", list(CorrelationPattern))
def test_technique_ids_are_well_formed_mitre_ids(pattern):
    mapping = get_mitre_technique(pattern)

    for technique_id in mapping.technique_ids:
        assert _TECHNIQUE_ID_RE.match(technique_id), f"'{technique_id}' doesn't look like a MITRE technique ID"


@pytest.mark.parametrize("pattern", list(CorrelationPattern))
def test_every_pattern_has_a_non_empty_tactic(pattern):
    mapping = get_mitre_technique(pattern)

    assert mapping.tactic


def test_get_mitre_technique_returns_the_expected_mapping_for_brute_force():
    mapping = get_mitre_technique(CorrelationPattern.CREDENTIAL_BRUTE_FORCE)

    assert "T1110" in mapping.technique_ids
    assert mapping.tactic == "Credential Access"


def test_mitre_technique_is_immutable():
    mapping = get_mitre_technique(CorrelationPattern.LATERAL_MOVEMENT)

    with pytest.raises(AttributeError):
        mapping.tactic = "Something Else"


# ── split_technique_ids ──────────────────────────────────────────────

@pytest.mark.parametrize("raw, expected", [
    (None, []),
    ("", []),
    ("   ", []),
    ("T1110", ["T1110"]),
    # adapters/wazuh.py's comma-joined multi-technique shape.
    ("T1110.001, T1021.004", ["T1110.001", "T1021.004"]),
    ("T1110,,T1078", ["T1110", "T1078"]),
])
def test_split_technique_ids_handles_every_shape_the_alert_field_takes(raw, expected):
    assert split_technique_ids(raw) == expected


# ── techniques_for_category / incident_technique_ids ─────────────────

def test_techniques_for_category_returns_empty_for_an_uncategorized_incident():
    assert techniques_for_category(None) == ()


def test_techniques_for_category_resolves_through_the_pattern_mapping():
    assert techniques_for_category(CorrelationPattern.CREDENTIAL_BRUTE_FORCE) == ("T1110",)


def test_incident_technique_ids_merges_both_sources_sorted_and_deduplicated():
    """Alert-level ids (comma-joined included) plus the category's mapped ids, as one list."""
    result = incident_technique_ids(
        ["T1021.004, T1110", None, "T1110"], CorrelationPattern.SUCCESSFUL_COMPROMISE
    )

    assert result == ["T1021.004", "T1078", "T1110"]


def test_incident_technique_ids_falls_back_to_the_category_when_alerts_carry_none():
    """The synthetic-alert case: no alert-level MITRE at all must still report the pattern's techniques."""
    assert incident_technique_ids([None, ""], CorrelationPattern.PRIVILEGE_ESCALATION) == ["T1548"]


def test_incident_technique_ids_returns_empty_when_neither_source_has_anything():
    assert incident_technique_ids([None], None) == []
