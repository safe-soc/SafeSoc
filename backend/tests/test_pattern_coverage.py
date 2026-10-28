"""
SafeSOC — Correlation Pattern Coverage Tests
Every CorrelationPattern must be known everywhere a pattern is listed by
hand: a detector, the backend and frontend labels, the frontend type and
chart colours. MITRE and playbook coverage have their own tests
(test_mitre_mapping.py, test_soar_playbooks.py). A pattern missing from
one of these lists still works, but shows as a raw id or a grey bar.
"""

import re
from pathlib import Path

import pytest

from app.core.enums import CorrelationPattern
from app.services import correlation
from app.services.incident_summary import _CATEGORY_LABELS

# Repo root on a checkout; "/" in the test container, where the overlay
# mounts frontend/src at /frontend/src (docker-compose.test.yml).
FRONTEND_SRC = Path(__file__).resolve().parent.parent.parent / "frontend" / "src"


def _frontend(relative: str) -> str:
    path = FRONTEND_SRC / relative
    if not path.exists():
        pytest.skip(f"{path} not available (frontend sources not mounted)")
    return path.read_text(encoding="utf-8")


def _object_keys(source: str, const_name: str) -> set[str]:
    body = re.search(rf"const {const_name}[^=]*=\s*{{(.*?)}};", source, re.DOTALL)
    assert body, f"{const_name} not found"
    return set(re.findall(r"^\s*(\w+):", body.group(1), re.MULTILINE))


def _patterns() -> set[str]:
    return {p.value for p in CorrelationPattern}


def test_every_pattern_has_a_detector():
    detected = set()
    for detector in correlation.DETECTORS:
        source = detector.__code__.co_names + detector.__code__.co_consts
        detected.update(p.value for p in CorrelationPattern if p.name in source)
    assert detected == _patterns()


def test_every_pattern_has_a_backend_label():
    assert {p.value for p in _CATEGORY_LABELS} == _patterns()


def test_the_frontend_type_lists_every_pattern():
    union = re.search(r"export type CorrelationPattern\s*=(.*?);", _frontend("lib/types.ts"), re.DOTALL)
    assert union
    assert set(re.findall(r"'(\w+)'", union.group(1))) == _patterns()


def test_every_pattern_has_a_frontend_label():
    assert _object_keys(_frontend("lib/format.ts"), "CATEGORY_LABELS") == _patterns()


def test_every_pattern_has_a_threat_analytics_colour_and_progression_slot():
    page = _frontend("pages/ThreatAnalytics.tsx")
    assert _object_keys(page, "CATEGORY_COLORS") == _patterns()
    order = re.search(r"const ATTACK_PROGRESSION_ORDER = \[(.*?)\];", page, re.DOTALL)
    assert order and set(re.findall(r"'(\w+)'", order.group(1))) == _patterns()


def test_the_backend_and_frontend_labels_match():
    frontend = dict(re.findall(r"^\s*(\w+): '([^']+)',", _frontend("lib/format.ts"), re.MULTILINE))
    for pattern, label in _CATEGORY_LABELS.items():
        assert frontend[pattern.value] == label
