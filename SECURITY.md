# Security Policy

## Supported Versions

SafeSOC is pre-1.0 (see [`PRODUCT_ROADMAP.md`](PRODUCT_ROADMAP.md)'s versioning philosophy) — only the latest commit on `main` is supported. There is no LTS branch and no backporting of fixes to older tags yet; that policy will be established once `v1.0.0` ships.

| Version | Supported |
|---|---|
| `main` (latest) | :white_check_mark: |
| Any tagged `v0.x.0` release | :x: (upgrade to latest `main`) |

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Public issues are visible to everyone immediately, including before a fix exists.

Instead, use GitHub's private vulnerability reporting:

**https://github.com/safe-soc/SafeSoc/security/advisories/new**

This opens a private advisory visible only to you and the repository maintainers, with room to describe the issue, its impact, and (optionally) a proposed fix. If GitHub's private reporting isn't available to you for any reason, contact one of the maintainers listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) directly via GitHub.

Please include, where possible:

- The affected endpoint(s)/component(s) and, ideally, a minimal reproduction.
- The potential impact (e.g. cross-tenant data exposure, authentication bypass, injection).
- Any suggested mitigation, if you have one.

### What to expect

- **Acknowledgment:** within 5 business days of the report.
- **Triage:** we'll confirm whether it's reproducible and assess severity.
- **Fix timeline:** depends on severity — a confirmed cross-tenant data leak or authentication bypass is treated as highest priority; lower-severity issues are scheduled alongside regular work.
- **Disclosure:** coordinated with the reporter once a fix is available. We're happy to credit reporters in the fix's commit/changelog entry if you'd like (and happy to keep you anonymous if you'd prefer).

### Scope

In scope: the SafeSOC backend (`backend/`), frontend (`frontend/`), CloudLens (`cloud/`), the synthetic injector (`injector/`), and their interaction (e.g. tenant isolation, authentication, the CloudLens→SafeSOC ingestion bridge).

Out of scope: findings that require an already-compromised/malicious tenant admin acting within their own tenant's data (multi-tenancy is meant to isolate *between* tenants, not restrict what a tenant's own admin can do to their own data), denial-of-service via raw traffic volume against a local dev deployment, and social engineering.

### Safe harbor

We consider security research conducted under this policy — in good faith, without accessing or modifying another tenant's data beyond what's needed to demonstrate the issue, and reported privately as above — to be authorized. We won't pursue legal action for research conducted consistently with this policy.

## Known, Deliberately Deferred Items

See [`docs/security-review.md`](docs/security-review.md) for the full OWASP-oriented review (SS-067), including what's already mitigated (rate limiting, tenant isolation, RBAC, constant-time token comparison) and what's explicitly deferred with rationale (e.g. no security-headers middleware yet, JWT refresh doesn't re-check DB user existence). These are documented gaps, not hidden ones — please still report anything not already listed there.
