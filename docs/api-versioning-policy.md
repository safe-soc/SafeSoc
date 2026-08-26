# SafeSOC — API Versioning & Stability Policy

SS-070. This document is the policy referenced by `PRODUCT_ROADMAP.md`'s v0.2.0 release ("Public REST API stabilization & versioning policy") and by `docs/api-design.md`'s endpoint contracts. It describes what "stable" means for `/api/v1`, what kinds of changes are and aren't allowed within it, and how a future `/api/v2` would be introduced if one is ever needed.

## Two different version numbers

SafeSOC has two independent version identifiers that are easy to conflate — they track different things and change on different schedules:

| | Tracks | Where it lives | Changes on |
|---|---|---|---|
| **`APP_VERSION`** (`core/config.py`, currently `1.0.0`) | The application/release as a whole — see `PRODUCT_ROADMAP.md`'s semver philosophy | `GET /` and `GET /health` responses | Every release, per `CHANGELOG.md` |
| **API version** (`/api/v1` prefix) | The shape of the REST contract itself — request/response schemas, status codes, auth requirements | Every router's `prefix=` | Only on a breaking change to the contract (see below) |

A `v0.x.0` → `v0.(x+1).0` application release does **not** imply an API version bump — most SafeSOC releases add functionality without touching the existing `/api/v1` contract at all. The API version is deliberately much more conservative than the application version.

## What "stable" means for `/api/v1`

As of `v1.0.0` (per `PRODUCT_ROADMAP.md`'s versioning philosophy — *"the documented `/api/v1` surface... treated as load-bearing from here on"*), the following are covered by the stability guarantee below:

- Every endpoint's URL path and HTTP method.
- Every required request field's name, type, and semantics.
- Every response field's name, type, and semantics for a `2xx` response.
- The meaning of every documented status code (`docs/api-design.md`).
- Authentication requirements (which endpoints need a JWT, which accept a service token).

**Not covered** (may change without a version bump): internal service/database layout, log message formats, exact wording of error message strings (`error` field content, not its presence/shape), timing/performance characteristics, undocumented/internal-only fields.

## What counts as a breaking change

A change to `/api/v1` requires a new API version (`/api/v2`) if it does any of the following to an **existing, documented** endpoint:

- Removes an endpoint, or changes its URL path or HTTP method.
- Removes a response field, renames one, or changes its type/meaning.
- Adds a **new required** request field (a client built against the old contract would now fail).
- Changes a field from optional to required, or narrows an accepted value set (e.g. removing an enum member a client might send).
- Changes authentication/authorization requirements to be stricter for an existing caller (e.g. an endpoint that didn't require a role now does).
- Changes the meaning of an existing status code for the same condition.

## What's always allowed within `/api/v1` (non-breaking, no version bump)

- Adding a **new** endpoint.
- Adding a **new optional** request field with a sensible default that preserves old behavior when omitted (the same pattern already used throughout this codebase — e.g. `AlertLinkRequest.alert_ids` added alongside the original `alert_id` without breaking existing callers).
- Adding a **new** response field (existing clients that don't read it are unaffected; see `IncidentResponse.accepted_alert_ids`/`rejected_alert_ids` for a concrete precedent — additive, `None` everywhere they don't apply).
- Widening an accepted value set (e.g. a new enum member a client can now send, if old members remain valid).
- Loosening authorization (a `require_role(ANALYST)` endpoint becoming available to `VIEWER` too) — never the reverse without a version bump.
- Fixing a genuine bug where the documented behavior and actual behavior diverged (the fix restores the documented contract; it isn't a new one).
- Performance improvements, internal refactors, new logging/observability — anything with no observable change to the request/response contract.

## If a breaking change is ever genuinely needed

1. Open an ADR in `docs/decisions.md` recording what's breaking and why a non-breaking alternative (a new field, a new endpoint) doesn't work.
2. Introduce `/api/v2` **alongside** `/api/v1`, not as a replacement — both are served by the same running application; existing `/api/v1` callers are not forced to migrate on any particular timeline.
3. Document the deprecation in `CHANGELOG.md` and `docs/api-design.md`, including a target removal release (minimum: two `v0.x.0`/`v1.x.0` releases' notice, longer if there are known external integrations).
4. `/api/v1` continues to function, unmodified, until that removal release actually ships.

No `/api/v2` exists today, and none of the changes made across this project's history so far (SS-001 through the current backlog) have required one — every addition has fit the "always allowed" list above.

## Current API surface

See `docs/api-design.md` for the full, current endpoint-by-endpoint contract this policy governs.
