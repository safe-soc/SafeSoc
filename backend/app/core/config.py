"""
SafeSOC — Application Configuration
Reads all settings from environment variables with sensible defaults.
Uses pydantic-settings for validation.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project root (backend/ directory)
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # A blank value in .env means "use the default", not "use an
        # empty string" — .env.example ships several of those
        # deliberately (ANOMALY_MODEL_PATH=, REPORT_OUTPUT_DIR=). Now
        # that docker-compose loads .env into the containers, without
        # this those blanks would override real defaults with "".
        env_ignore_empty=True,
    )

    # ──────────────────────────────────────────────
    # Application
    # ──────────────────────────────────────────────
    APP_NAME: str = "SafeSOC"
    APP_VERSION: str = "1.0.0"
    ENV: str = "development"  # development | production
    DEBUG: bool = True
    SECRET_KEY: str = "change-me-to-a-random-secret-key"
    API_PREFIX: str = "/api/v1"

    # ──────────────────────────────────────────────
    # OpenSearch
    # ──────────────────────────────────────────────
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USER: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_VERIFY_CERTS: bool = False
    OPENSEARCH_ILM_RETENTION_DAYS: int = 90

    # ──────────────────────────────────────────────
    # PostgreSQL
    # ──────────────────────────────────────────────
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "safesoc"
    POSTGRES_USER: str = "safesoc"
    POSTGRES_PASSWORD: str = "safesoc"

    @property
    def postgres_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def postgres_url_sync(self) -> str:
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ──────────────────────────────────────────────
    # Redis
    # ──────────────────────────────────────────────
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""

    @property
    def redis_url(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # ──────────────────────────────────────────────
    # JWT Authentication
    # ──────────────────────────────────────────────
    JWT_SECRET: str = "change-me-to-a-64-char-random-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 24

    # Login brute-force protection (SS-067): max failed attempts per
    # (tenant_id, email) pair within the window before POST
    # /api/v1/auth/login starts rejecting with 429, regardless of
    # whether the password given is actually correct.
    AUTH_LOGIN_RATE_LIMIT_ATTEMPTS: int = 5
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300  # 5 minutes

    # Same idea for POST /api/v1/auth/register, keyed by client IP
    # instead — registration isn't tied to one existing account the way
    # login is, so the abuse this guards against (automated mass
    # account creation) is naturally IP-scoped instead.
    AUTH_REGISTER_RATE_LIMIT_ATTEMPTS: int = 10
    AUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS: int = 300  # 5 minutes

    # ──────────────────────────────────────────────
    # Threat Intelligence APIs
    # ──────────────────────────────────────────────
    VT_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # Rate limits
    VT_RATE_LIMIT_PER_MINUTE: int = 4
    ABUSEIPDB_RATE_LIMIT_PER_DAY: int = 1000

    # TI Cache TTLs (seconds)
    TI_CACHE_CLEAN_TTL: int = 86400       # 24 hours
    TI_CACHE_MALICIOUS_TTL: int = 604800  # 7 days

    # ──────────────────────────────────────────────
    # LLM Configuration
    # ──────────────────────────────────────────────
    LLM_PROVIDER: str = "ollama"  # ollama | groq
    OLLAMA_HOST: str = "localhost"
    OLLAMA_PORT: int = 11434
    # SS-091: switched from mistral:7b per the SS-090 benchmark
    # (docs/ai-llm-benchmark.md) — under this project's own measured
    # conditions, mistral:7b's p50 (46-60s) essentially never met the
    # 10s/15s SRS budget, while llama3.2:3b met it comfortably (p50
    # 5.7-7.4s, 100% success on 2/3 tested prompt shapes) with
    # consistently coherent, accurate answers. qwen2.5:0.5b was faster
    # but was directly observed hallucinating on real SafeSOC data and
    # was ruled out on quality grounds, not just latency.
    OLLAMA_MODEL: str = "llama3.2:3b"
    GROQ_API_KEY: str = ""
    # Groq retires hosted models on a published schedule, and a request
    # for a retired id is a hard error, not a fallback: mixtral-8x7b-32768
    # was shut down on 2025-03-20, and llama-3.3-70b-versatile /
    # llama-3.1-8b-instant on 2026-08-16. openai/gpt-oss-120b is Groq's
    # own listed replacement (openai/gpt-oss-20b is the smaller sibling).
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    # gpt-oss are REASONING models: they spend tokens thinking before
    # answering, and that spend comes out of the same completion budget
    # as the answer. "low" keeps the thinking short, and the headroom is
    # added to the caller's max_output_tokens so a small answer budget
    # (120 tokens for a chat turn) isn't consumed entirely by reasoning,
    # which returns an empty completion. Both are only used for gpt-oss
    # models — see clients/groq.py::build_payload.
    GROQ_REASONING_EFFORT: str = "low"       # low | medium | high
    GROQ_REASONING_TOKEN_HEADROOM: int = 512

    @property
    def ollama_url(self) -> str:
        return f"http://{self.OLLAMA_HOST}:{self.OLLAMA_PORT}"

    # How long a conversation session's context survives idle time
    # before a follow-up question is treated as a fresh conversation
    # instead (SS-046). Redis-backed, same TTL-refreshed-on-write
    # pattern as CORRELATION_WINDOW_TTL below.
    INVESTIGATION_SESSION_TTL_SECONDS: int = 600  # 10 minutes

    # The Investigate chat recognizes host and user names by matching
    # them against this tenant's known entities (endpoints table +
    # distinct host_id/user in recent alerts). One aggregation builds
    # the list; it's cached in Redis for this long so a chat turn never
    # rescans alerts.
    INVESTIGATION_KNOWN_ENTITIES_TTL_SECONDS: int = 300  # 5 minutes
    INVESTIGATION_KNOWN_ENTITIES_LOOKBACK_DAYS: int = 30
    INVESTIGATION_KNOWN_ENTITIES_MAX_TERMS: int = 500

    # POST /api/v1/investigate (SS-047) must meet the SRS's 15-second
    # response time target even when the LLM is slow/unreachable — this
    # bounds just the answer-generation step, leaving headroom under 15s
    # for the (normally sub-second) classification + tool query that
    # happen first. A timeout here falls back to a templated summary of
    # the tool's raw data rather than failing the request.
    INVESTIGATION_LLM_TIMEOUT_SECONDS: int = 10

    # Latency diagnosis (docs/ai-llm-latency-diagnosis.md): a realistic
    # investigation prompt against real accumulated data (100 alerts,
    # ~93KB/2050 tokens) left generation completely unbounded — a
    # measured 358-364 tokens when the model wasn't capped, on top of
    # ~8s of prompt processing, blew well past the 10s budget. Caps
    # output length for both providers (ollama.py/groq.py) — the
    # prompt already asks for a "concise" answer; this just enforces
    # it. 120 was the largest value that stayed reliably under budget
    # across repeated real-data measurements (180 measured as high as
    # 10.12s on this hardware).
    # Raised 120 -> 200 alongside the fixed answer format (B2): the
    # format asks for 1-3 sentences plus up to 5 short bullets, under
    # ~120 words, which does not fit in 120 tokens — answers were being
    # cut off mid-sentence. Still well inside the 10s budget above: the
    # 180-token measurement below was taken against a 100-alert raw-JSON
    # prompt, which _describe_tool_result has since replaced with a far
    # smaller readable briefing.
    INVESTIGATION_LLM_MAX_OUTPUT_TOKENS: int = 200

    # POST /api/v1/incidents/{id}/narrative (SS-109/110) has its own,
    # more generous timeout rather than reusing
    # INVESTIGATION_LLM_TIMEOUT_SECONDS unchanged, as originally assumed
    # ("a call of the same shape/cost" — services/incident_narrative.py).
    # Measured directly against this project's local Ollama (llama3.2:3b):
    # a cold call (model not already resident in memory — the common
    # case after Ollama's default ~5-minute idle unload, or after a
    # different model was served in between) took 13.7s end-to-end,
    # already past the 10s budget tuned for the interactive investigate
    # chat's own SRS target; a warm call completed in ~3s. This is a
    # one-shot "click to summarize" action, not a live chat turn, so a
    # longer worst-case wait is an acceptable trade for not silently
    # discarding a genuinely-available AI summary in favor of the
    # (correct, but less specific) deterministic fallback on every cold
    # start.
    INCIDENT_NARRATIVE_LLM_TIMEOUT_SECONDS: int = 25

    # The narrative endpoint previously reused
    # INVESTIGATION_LLM_MAX_OUTPUT_TOKENS too (both clients.ollama.py's
    # num_predict and clients.groq.py's max_tokens were hardcoded to
    # that one setting) — fine for interactive chat's short, single-
    # fact answers, but it cut the attack-chain narrative off mid-
    # sentence on any incident with more than a couple of events, since
    # that prompt explicitly asks for sequence + hosts/users +
    # techniques + evidence + known/unknowns in one answer (see
    # services/incident_narrative.py's _TASK_INSTRUCTIONS). This is a
    # separate, larger budget for that one call site — both
    # clients.ollama.generate()/clients.groq.generate() now take an
    # explicit max_output_tokens argument instead of reading
    # INVESTIGATION_LLM_MAX_OUTPUT_TOKENS directly, so each caller
    # supplies its own. Not "unbounded": this endpoint keeps its own
    # generous 25s timeout above (not the 10s interactive-chat budget),
    # so a larger token cap doesn't reintroduce the latency problem
    # INVESTIGATION_LLM_MAX_OUTPUT_TOKENS itself was added to prevent.
    # Raised 350 -> 450 alongside the fixed four-section markdown format
    # (B1): ~180 words of prose plus four headings and bullet markers
    # lands close enough to 350 that a slightly long summary was losing
    # its last section. The 25s timeout above still bounds the call.
    INCIDENT_NARRATIVE_LLM_MAX_OUTPUT_TOKENS: int = 450

    # Investigation Sessions (persistent, incident-scoped Q&A —
    # services/investigation_session.py) get their own timeout/token
    # budget rather than reusing INCIDENT_NARRATIVE_LLM_* — deliberately
    # NOT shared, even though both currently start from the same
    # measured-safe values (25s / 350 tokens, see that setting's own
    # comment above for the underlying measurement), so this call site
    # can be tuned independently later (e.g. once its prompt grows
    # confirmed-findings/open-questions/prior-turns context beyond what
    # the one-shot narrative prompt carries) without touching the
    # narrative endpoint's already-validated budget.
    INVESTIGATION_SESSION_LLM_TIMEOUT_SECONDS: int = 25
    INVESTIGATION_SESSION_LLM_MAX_OUTPUT_TOKENS: int = 350

    # ──────────────────────────────────────────────
    # Correlation Engine
    # ──────────────────────────────────────────────
    CORRELATION_WINDOW_TTL: int = 3600      # 1 hour (seconds)
    CORRELATION_CONFIDENCE_THRESHOLD: float = 0.6
    # Correlation windows are scored by EVENT time (see docs/decisions.md
    # ADR-011), so an endpoint whose clock runs slightly fast produces
    # events timestamped marginally in the future. They're still real
    # events, so the window's upper bound allows this much skew rather
    # than dropping them.
    CORRELATION_CLOCK_SKEW_SECONDS: int = 300   # 5 minutes

    # ──────────────────────────────────────────────
    # Risk Scoring
    # ──────────────────────────────────────────────
    RISK_SCORE_CRITICAL: int = 40
    RISK_SCORE_HIGH: int = 20
    RISK_SCORE_MEDIUM: int = 10
    RISK_SCORE_LOW: int = 5
    RISK_SCORE_TI_MALICIOUS_BONUS: int = 30
    RISK_SCORE_ANOMALY_BONUS: int = 15
    RISK_SCORE_AFTER_HOURS_BONUS: int = 10
    RISK_SCORE_MITRE_BONUS: int = 20
    RISK_TIME_DECAY_PER_HOUR: float = 0.04

    # How often the scheduled recalculation task (SS-033) re-scores every
    # known endpoint, and how far back it looks for alerts when doing so.
    RISK_RECALC_INTERVAL_MINUTES: int = 15
    RISK_RECALC_LOOKBACK_HOURS: int = 24

    # ──────────────────────────────────────────────
    # Anomaly Detection
    # ──────────────────────────────────────────────
    ANOMALY_THRESHOLD: float = 0.7
    ANOMALY_MODEL_PATH: str = str(BASE_DIR.parent / "ml" / "model" / "isolation_forest.pkl")
    NETWORK_ANOMALY_ZSCORE_THRESHOLD: float = 3.0

    # ──────────────────────────────────────────────
    # Reporting
    # ──────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = str(BASE_DIR / "reports")
    REPORT_SCHEDULE_DAY: int = 0  # Monday (0 = Monday, 6 = Sunday)
    REPORT_SCHEDULE_HOUR: int = 6

    # ──────────────────────────────────────────────
    # Ingestion
    # ──────────────────────────────────────────────
    INGEST_BATCH_SIZE: int = 500
    INGEST_RATE_LIMIT_PER_MINUTE: int = 1000

    # ──────────────────────────────────────────────
    # CORS
    # ──────────────────────────────────────────────
    ALLOWED_ORIGINS: list[str] = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:5176",]

    # ──────────────────────────────────────────────
    # CloudLens Integration
    # ──────────────────────────────────────────────
    # Shared secret checked against the X-Service-Token header on
    # POST /api/v1/cloud/findings (SS-039) — CloudLens is a same-deployment
    # backend service pushing findings, not an interactive user, so it
    # authenticates with this instead of a per-user JWT.
    CLOUDLENS_SERVICE_TOKEN: str = ""

    # ──────────────────────────────────────────────
    # Notifications
    # ──────────────────────────────────────────────
    # SafeSOC's own Telegram bot (SS-055) — separate from CloudLens's
    # own TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID env vars (cloud/AWS-IAM-backend),
    # since these are two independent applications/deployments, not a
    # shared notification channel. Same names as CloudLens's own
    # notifier for familiarity, but read from this app's own env.
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""


# Singleton settings instance
settings = Settings()