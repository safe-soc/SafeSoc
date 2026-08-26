# SafeSOC — Release Process

SS-076. How a SafeSOC release is actually cut, and what `.github/workflows/release.yml` automates once you do.

## Cutting a release

1. Add a section to [`CHANGELOG.md`](https://github.com/safe-soc/SafeSoc/blob/main/CHANGELOG.md) for the new version, following the existing `## [vX.Y.Z] - YYYY-MM-DD` heading format (see any existing entry). **This step is required** — the release workflow extracts this exact section as the GitHub Release body and fails if it doesn't exist, rather than publishing a release with an empty description.
2. Commit that changelog update to `main` through the normal PR process.
3. Tag the commit and push the tag:
   ```bash
   git tag v1.1.0        # or v1.1.0-alpha for a prerelease — see "Prerelease tags" below
   git push origin v1.1.0
   ```
4. Pushing the tag triggers `.github/workflows/release.yml` automatically. An ordinary commit or push to `main` never triggers it — only a tag matching `v*.*.*` does.

## What the automation does

Three jobs, in order:

1. **`validate`** — parses the version out of the pushed tag (or, for a manual `workflow_dispatch` run, out of the `version` input), rejects anything that isn't valid semver (`vX.Y.Z` or `vX.Y.Z-suffix`), and extracts the matching `CHANGELOG.md` section via [`scripts/changelog_extract.py`](https://github.com/safe-soc/SafeSoc/blob/main/scripts/changelog_extract.py) — failing the whole workflow if that section is missing.
2. **`docker`** — builds the backend image (`backend/Dockerfile`) and pushes it to GitHub Container Registry, tagged `ghcr.io/safe-soc/SafeSoc/backend:<version>`. A non-prerelease version (no `-alpha`/`-beta`/`-rc` suffix) also gets tagged `:latest`.
3. **`github-release`** — creates a GitHub Release for the tag, with the extracted changelog section as its body, marked as a prerelease automatically if the version has a suffix.

## Prerelease tags

A version with any `-suffix` (`v1.1.0-alpha`, `v1.1.0-rc1`, ...) is treated as a prerelease: it's still built and pushed to the registry and still gets a GitHub Release, but doesn't receive the `:latest` Docker tag and is marked "Pre-release" on GitHub. This matches the tag convention already used in this repo's own history (`v0.1.0-alpha` through `v0.9.0-alpha`).

## Dry-running the pipeline

Trigger the workflow manually from the Actions tab (`workflow_dispatch`) with a `version` input and `dry_run` left at its default (`true`). Every step still runs — version validation, changelog extraction, the Docker *build* — except the image is never pushed and no GitHub Release is created. Useful for validating a new version/changelog pairing before actually tagging.

You can also validate the changelog-extraction step alone, locally, without touching CI at all:

```bash
python scripts/changelog_extract.py v0.12.0-alpha
```

## Versioning scheme

Both the application (`APP_VERSION` in `backend/app/core/config.py`) and the git tag are expected to describe the same release, but the tag is the authoritative source the automation actually reads from — no file needs to be bumped before tagging. See [`PRODUCT_ROADMAP.md`](https://github.com/safe-soc/SafeSoc/blob/main/PRODUCT_ROADMAP.md#versioning-philosophy) for the semver policy this project follows (loose before `v1.0.0`, strict after).
