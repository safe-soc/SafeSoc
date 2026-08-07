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
    OLLAMA_MODEL: str = "mistral:7b"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "mixtral-8x7b-32768"

    @property
    def ollama_url(self) -> str:
        return f"http://{self.OLLAMA_HOST}:{self.OLLAMA_PORT}"

    # How long a conversation session's context survives idle time
    # before a follow-up question is treated as a fresh conversation
    # instead (SS-046). Redis-backed, same TTL-refreshed-on-write
    # pattern as CORRELATION_WINDOW_TTL below.
    INVESTIGATION_SESSION_TTL_SECONDS: int = 600  # 10 minutes

    # ──────────────────────────────────────────────
    # Correlation Engine
    # ──────────────────────────────────────────────
    CORRELATION_WINDOW_TTL: int = 3600      # 1 hour (seconds)
    CORRELATION_CONFIDENCE_THRESHOLD: float = 0.6

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
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # ──────────────────────────────────────────────
    # CloudLens Integration
    # ──────────────────────────────────────────────
    # Shared secret checked against the X-Service-Token header on
    # POST /api/v1/cloud/findings (SS-039) — CloudLens is a same-deployment
    # backend service pushing findings, not an interactive user, so it
    # authenticates with this instead of a per-user JWT.
    CLOUDLENS_SERVICE_TOKEN: str = ""


# Singleton settings instance
settings = Settings()