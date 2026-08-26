#!/usr/bin/env python3
"""
SafeSOC — Changelog Section Extractor (SS-076)
Extracts a single version's section from CHANGELOG.md (Keep a
Changelog format: "## [vX.Y.Z] - YYYY-MM-DD" headings) for use as a
GitHub Release body. Pure string processing over text the caller
supplies — no file I/O beyond reading the path it's pointed at, no
network access — so it's testable without touching the real
CHANGELOG.md or GitHub.

Used by .github/workflows/release.yml to populate a GitHub Release
body from the matching CHANGELOG.md section for the tag being
released, and runnable locally for a dry run:

    python scripts/changelog_extract.py v0.12.0-alpha
"""

import argparse
import re
import sys

_HEADING_PATTERN = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*.*)?\s*$")


def extract_section(changelog_text: str, version: str) -> str:
    """
    Returns the body text between this version's "## [version]" heading
    and the next "## [...]" heading (or end of file), heading itself
    excluded and surrounding blank lines trimmed.

    Raises:
        ValueError: if no section for `version` exists in the changelog.
    """
    lines = changelog_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        match = _HEADING_PATTERN.match(line)
        if match and match.group("version") == version:
            start = i + 1
            break
    if start is None:
        raise ValueError(f"No changelog section found for version '{version}'.")

    end = len(lines)
    for i in range(start, len(lines)):
        if _HEADING_PATTERN.match(lines[i]):
            end = i
            break

    return "\n".join(lines[start:end]).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract one version's section from CHANGELOG.md")
    parser.add_argument("version", help="Version to extract, matching a '## [version]' heading exactly (e.g. v0.12.0-alpha)")
    parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to the changelog file (default: ./CHANGELOG.md)")
    args = parser.parse_args()

    with open(args.changelog, encoding="utf-8") as f:
        text = f.read()

    # CHANGELOG.md legitimately contains non-ASCII characters (e.g. "≥"
    # in throughput targets) — force UTF-8 output so this doesn't crash
    # on a Windows console defaulting to a legacy codepage. GitHub
    # Actions runners are UTF-8 by default, so this only matters for a
    # local dry run, but a local dry run is exactly what this script is
    # for.
    sys.stdout.reconfigure(encoding="utf-8")

    try:
        print(extract_section(text, args.version))
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
