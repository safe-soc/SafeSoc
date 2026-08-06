"""
SafeSOC — MITRE ATT&CK Mapping Tests
"""

import re

import pytest

from app.core.enums import CorrelationPattern
from app.core.mitre_mapping import MITRE_PATTERN_MAPPING, get_mitre_technique

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
