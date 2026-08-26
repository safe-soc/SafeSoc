"""
SafeSOC — Changelog Section Extractor Tests (SS-076)
Run with: pytest scripts/
"""

import pytest

from changelog_extract import extract_section

_SAMPLE = """\
# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [v0.2.0-alpha] - 2026-01-02

### Added

- Second feature.

## [v0.1.0-alpha] - 2026-01-01

### Added

- First feature.
- Another line.

### Fixed

- A bug.
"""


def test_extracts_the_matching_version_section():
    result = extract_section(_SAMPLE, "v0.1.0-alpha")

    assert "### Added" in result
    assert "- First feature." in result
    assert "### Fixed" in result
    assert "- A bug." in result


def test_extraction_stops_at_the_next_heading():
    result = extract_section(_SAMPLE, "v0.2.0-alpha")

    assert "Second feature" in result
    assert "First feature" not in result


def test_extraction_of_the_last_section_stops_at_end_of_file():
    result = extract_section(_SAMPLE, "v0.1.0-alpha")

    assert result.endswith("- A bug.")


def test_extraction_trims_surrounding_blank_lines():
    result = extract_section(_SAMPLE, "v0.2.0-alpha")

    assert not result.startswith("\n")
    assert not result.endswith("\n")


def test_unreleased_section_with_no_body_extracts_empty_string():
    result = extract_section(_SAMPLE, "Unreleased")

    assert result == ""


def test_raises_for_a_version_not_present_in_the_changelog():
    with pytest.raises(ValueError, match="v9.9.9"):
        extract_section(_SAMPLE, "v9.9.9")


def test_a_version_string_that_is_a_substring_of_another_does_not_match():
    """"v0.1.0" must not accidentally match the heading for "v0.1.0-alpha"."""
    with pytest.raises(ValueError):
        extract_section(_SAMPLE, "v0.1.0")


def test_extracts_correctly_against_the_real_repository_changelog():
    """Live-ish check: the extractor works against this repo's actual CHANGELOG.md, not just a synthetic sample."""
    import pathlib

    changelog_path = pathlib.Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    text = changelog_path.read_text(encoding="utf-8")

    result = extract_section(text, "v0.12.0-alpha")

    assert "SS-066" in result
    assert "BUG-001" in result
