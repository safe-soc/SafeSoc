# SafeSOC

SafeSOC is an AI-assisted, multi-tenant Security Operations Platform for SMBs — organizations who can't afford Splunk and can't operate Wazuh unassisted. It normalizes security telemetry from multiple sources (Wazuh, AWS CloudTrail/GuardDuty, CloudLens's AWS IAM findings), enriches it with threat intelligence, correlates multi-step attack chains in real time, scores endpoint risk, and lets analysts investigate incidents in plain English via a local or cloud LLM.

This site is generated from this repository's `docs/` directory (SS-073) — the same files a contributor reading the repo directly would see, just organized into a browsable, searchable site.

## Where to start

- **New to the project?** [Architecture](architecture.md) gives the layer-by-layer implementation status; [Tech Stack](tech-stack.md) lists what's actually in use.
- **Deploying it?** [Deployment](deployment.md) covers the one-command installer and manual setup.
- **Building against the API?** [API Design](api-design.md) has the full endpoint contract; [Versioning Policy](api-versioning-policy.md) covers what's stable.
- **Writing a new source adapter?** [Plugin/Adapter SDK](plugin-architecture.md) is the formal `LogAdapter` contract.
- **Contributing code?** See [`CONTRIBUTING.md`](https://github.com/safe-soc/SafeSoc/blob/main/CONTRIBUTING.md) and [`docs/coding-standards.md`](coding-standards.md).
- **Reporting a security issue?** See [`SECURITY.md`](https://github.com/safe-soc/SafeSoc/blob/main/SECURITY.md) — please don't file it as a public issue.

## Project-level documents (outside `docs/`)

A few meta-documents live at the repository root rather than in `docs/`, by the usual GitHub convention (`CONTRIBUTING.md`, `SECURITY.md`, etc. are recognized specially when placed there) — linked here rather than duplicated into this site:

- [`README.md`](https://github.com/safe-soc/SafeSoc/blob/main/README.md) — project overview, quickstart, feature tour
- [`PRODUCT_ROADMAP.md`](https://github.com/safe-soc/SafeSoc/blob/main/PRODUCT_ROADMAP.md) — the release plan this site's own existence is tracked under (SS-073)
- [`CHANGELOG.md`](https://github.com/safe-soc/SafeSoc/blob/main/CHANGELOG.md) — release history
- [`CONTRIBUTING.md`](https://github.com/safe-soc/SafeSoc/blob/main/CONTRIBUTING.md) · [`CODE_OF_CONDUCT.md`](https://github.com/safe-soc/SafeSoc/blob/main/CODE_OF_CONDUCT.md) · [`SECURITY.md`](https://github.com/safe-soc/SafeSoc/blob/main/SECURITY.md)

## Documentation status discipline

Every document under `docs/` follows an **Implemented / Partial / Planned** tagging convention — when it disagrees with a specific claim elsewhere (a report, a comment, this site's own nav ordering), the tagged status in the relevant `docs/` file is the source of truth. See [`docs/roadmap-issues.md`](roadmap-issues.md) and [`PRODUCT_ROADMAP.md`](https://github.com/safe-soc/SafeSoc/blob/main/PRODUCT_ROADMAP.md) for what's actually shipped vs. planned.
