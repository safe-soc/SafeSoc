# SafeSOC — Security Review (SS-067)

Scope, per the issue: review the implemented surface against OWASP Top 10 concerns now that auth (Milestone 3) exists — with an explicit focus on injection risk in OpenSearch queries, JWT handling, secrets management, and rate limiting on auth endpoints. This is a point-in-time review of the code as of this pass, not a penetration test and not a substitute for one before any production deployment.

Status legend: **Fixed** (code changed this pass) · **Deferred** (real finding, not fixed — severity doesn't require it, or the fix needs a design decision beyond this pass's scope; follow-up recommended) · **No issue found** (checked, no problem).

## Findings

### 1. No rate limiting on `/api/v1/auth/login` or `/api/v1/auth/register` — **Fixed** (High)

Neither endpoint had any limit on attempt frequency — `/login` was brute-forceable at network speed against any known `tenant_id`/`email` pair, and `/register` allowed unlimited automated account creation.

Fix: `backend/app/services/rate_limit.py` — a Redis-backed fixed-window counter (`enforce_rate_limit`), applied to both endpoints in `routers/v1/auth.py`:
- `/login`: keyed by `tenant_id` + `email` (the actual brute-force target), `AUTH_LOGIN_RATE_LIMIT_ATTEMPTS` (5) per `AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS` (300s).
- `/register`: keyed by client IP, `AUTH_REGISTER_RATE_LIMIT_ATTEMPTS` (10) per `AUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS` (300s).

Both limits and windows are configurable in `core/config.py`. The limiter **fails open** if Redis itself is unreachable (logs a warning and allows the request) — an outage in the rate-limit backing store degrading to "unprotected" was judged preferable to degrading to "auth endpoints down," since Redis is not otherwise a hard dependency for authentication. This is a deliberate tradeoff, not an oversight.

Tests: `backend/tests/test_rate_limit.py` (limiter logic in isolation, including the fail-open path), `backend/tests/test_auth_router.py` (429 surfaced end-to-end through both endpoints). Verified live via Docker (§ below).

### 2. `JWT_SECRET` ships with a public, guessable default and no startup guard — **Fixed** (Critical if deployed)

`core/config.py` defaults `JWT_SECRET` to the literal string `"change-me-to-a-64-char-random-string"`. Since this file is committed to source control, that default is public. Nothing previously stopped the app from starting — or from issuing and accepting JWTs — while still using it; a deployer who forgot to override `JWT_SECRET` in `.env` would run a backend where anyone who'd read this repo could forge a valid token for any tenant/role.

Fix: `backend/app/main.py`'s startup event now checks `settings.JWT_SECRET` against the known default. If it's still the default **and** `settings.ENV == "production"`, startup raises `RuntimeError` and the app refuses to come up. Outside production, it logs a loud warning and continues — the default needs to keep working for local dev/test, where there's no real secret to protect.

Tests: `backend/tests/test_startup.py` (refuses in production, warns-but-starts in dev, starts normally with a real secret in production).

### 3. Timing-unsafe comparison on the CloudLens service token — **Fixed** (Medium)

`routers/v1/cloud.py`'s `verify_service_token` compared the caller-supplied `X-Service-Token` header against `settings.CLOUDLENS_SERVICE_TOKEN` with Python's `!=`, a byte-by-byte comparison that short-circuits on the first mismatch — a timing side-channel (CWE-208) that could in principle let an attacker recover the token by measuring response times.

Fix: switched to `hmac.compare_digest`, a constant-time comparison. The existing "closed by default" behavior (empty configured token always rejects, regardless of what's presented) is unchanged and was already correct. `backend/tests/test_cloud_router.py`'s existing coverage of accept/reject behavior continues to pass unmodified — this is a non-functional hardening change, not a behavior change.

### 4. No password length/complexity requirement on registration — **Fixed** (Medium)

`schemas/auth.py`'s `RegisterRequest.password` was a bare `str` with no validation — empty strings and single characters were accepted.

Fix: `password: str = Field(min_length=8)`. This is a minimum floor, not a full complexity policy (no character-class requirements) — bcrypt hashing already means brute-forcing a stored hash is expensive regardless of policy; the length floor mainly guards against trivially-guessable passwords being chosen at all. Two existing tests in `test_auth_router.py` that used a 7-character password were updated to an 8+ character one to keep asserting their actual subject (successful registration / duplicate-email handling) rather than incidentally hitting the new validation; a new test asserts the 422 on a too-short password.

### 5. JWT algorithm confusion — **No issue found**

`core/security.py::decode_access_token` calls `jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])` — the `algorithms` allow-list is explicit and singular, which is exactly what prevents the classic "alg: none" or HS256/RS256 confusion attacks. No change needed.

### 6. OpenSearch query injection — **No issue found**

Every query against OpenSearch (`db/opensearch.py` and all callers) is built as a dict-based Query DSL. There is no use of Lucene `query_string` syntax, scripted queries, or string-interpolated queries anywhere in `backend/app` (confirmed by grep across the tree). User-supplied values flow into DSL fields as data, never as query syntax.

### 7. SQL injection — **No issue found**

All PostgreSQL access goes through SQLAlchemy's ORM/Core (`select(...).where(...)`), which parameterizes automatically. The one raw-SQL usage in the codebase — `services/incidents.py`'s `text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))")` — uses a bound parameter (`:lock_key`), not string interpolation.

### 8. CORS configuration — **No issue found**

`main.py` sets `allow_origins=settings.ALLOWED_ORIGINS` (an explicit whitelist, not a wildcard) together with `allow_credentials=True`. A wildcard origin combined with credentials would be a real vulnerability; an explicit whitelist combined with credentials is the correct, safe configuration.

### 9. `.env.example` contains a real-looking Telegram bot token and chat ID — **Deferred, flagged directly** (High — credential exposure, not a code defect)

`.env.example` is git-tracked (explicitly un-ignored via `!.env.example` in `.gitignore`) and is meant to be a safe-to-commit template. During this pass, its CloudLens Telegram section (`cloud/AWS-IAM-backend`'s notifier, not SafeSOC's own `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` settings) was found populated with what appears to be a real bot token and chat ID instead of empty placeholders.

This isn't something a code fix in this pass addresses — the remediation is credential rotation, which only the token's owner can do. It was flagged directly at the time of discovery, and `.env.example` has been excluded from every commit made during this stabilization phase so as not to compound the exposure. **Action still needed from the repo owner:** revoke/regenerate that Telegram bot token and restore `.env.example` to empty placeholders.

### 10. `SECRET_KEY` — dead config with a weak default — **Deferred, documentation only** (Low)

`core/config.py` defines `SECRET_KEY: str = "change-me-to-a-random-secret-key"`, separate from `JWT_SECRET`. It is not referenced anywhere in `backend/app` outside its own definition — not currently exploitable, since nothing relies on it, but misleading: a reader would reasonably assume it protects something. Recommend either wiring it to an actual use or removing it in a future cleanup pass; out of scope to guess its intended purpose here.

### 11. `INGEST_RATE_LIMIT_PER_MINUTE` — defined but unenforced — **Deferred** (Medium)

`core/config.py` defines this setting; nothing in the ingestion path reads it. Unlike the auth rate limits added in this pass (finding #1), ingest rate limiting raises a real design question this issue isn't the place to settle — per-tenant vs. per-API-key vs. global, and how it should interact with the documented `INGEST_BATCH_SIZE` cap. Recommend a dedicated follow-up issue.

### 12. `POST /api/v1/auth/refresh` doesn't re-verify the user still exists or is active — **Deferred** (Medium)

`refresh` re-signs a new token directly from the claims embedded in the old one, without querying the database. A deleted or deactivated user's token remains refreshable indefinitely as long as the caller keeps refreshing before each token expires. The blast radius is bounded today by `JWT_EXPIRY_HOURS` (24h) and by the fact that no user-deactivation feature exists yet to make this exploitable in practice — but it's worth fixing (adding a DB lookup to `refresh`) at the same time deactivation ships, since that's when this gap becomes live. Recommend a follow-up issue tied to that feature rather than a standalone DB dependency added to `refresh` now.

### 13. No secret redaction in structured logging — **Deferred, documentation only** (Low/Info)

`utils/logger.py`'s `StructuredLogger` does no automatic redaction of sensitive fields. Reviewed every current call site that logs request data (`services/auth.py`, `routers/v1/auth.py`, and others) — none currently log a raw password or token. This is a systemic risk to keep in mind for future call sites, not an active leak today, so it isn't fixed here (there's nothing concrete to fix).

### 14. Missing security response headers (CSP, `X-Content-Type-Options`, `X-Frame-Options`, HSTS, etc.) — **Deferred** (Low/Medium)

No middleware sets these. SafeSOC's backend is a JSON API with no server-rendered HTML, which meaningfully lowers the relevance of clickjacking/XSS-via-HTML-injection headers compared to a traditional web app — but defense-in-depth (especially `X-Content-Type-Options: nosniff` and HSTS once TLS termination exists) is still good practice. Adding a headers middleware is a small, low-risk change, but it's a new piece of infrastructure rather than a fix to a finding in this pass's named focus areas (injection, JWT, secrets, auth rate limiting) — recommend a follow-up issue rather than folding it in here.

### 15. WebSocket auth via query-string JWT — **Documented as an accepted tradeoff** (Info)

`GET /ws?token=<JWT>` carries the JWT as a query parameter rather than a header, because browsers' native WebSocket API can't set custom headers on the handshake request. Query strings can end up in server access logs or browser history, which is a real (if narrow) exposure compared to a header. This is a documented, deliberate tradeoff of the WebSocket protocol as used from a browser, not a defect — `routers/ws.py` already documents the reasoning in its module docstring. No change made.

## Verification

- Full backend suite: `pytest` from `backend/` — 545 passed (including the new/updated tests above, plus BUG-001/BUG-002's own regression tests added afterward), 0 failed.
- Docker verification: see the SS-067 commit's PR/issue comment for the live run confirming the rate limiter returns 429 after the configured attempt count against a running stack, and that the startup guard's warning log line appears on a fresh container start with the default `JWT_SECRET`.

## Out of scope for this pass

Anything not listed above that touches authentication, authorization, or data handling but wasn't named in the issue's focus areas (e.g., a full dependency vulnerability scan of `requirements.txt`, a review of the CloudLens Django app's own security posture, infrastructure-level hardening like TLS termination) was not reviewed here and should be its own future issue.
