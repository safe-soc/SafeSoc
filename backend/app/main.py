"""
SafeSOC — FastAPI Application Entry Point
"""
from app.routers.v1 import alerts
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exceptions import SafeSOCError, safesoc_exception_handler
from app.middleware.observability import ObservabilityMiddleware
from app.routers import health, ws
from app.routers.v1 import auth, cloud, endpoints, incidents, ingest, investigate, reports, threat_analytics

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Observability (SS-077): request ID + Prometheus HTTP metrics.
# Added after CORSMiddleware so it's the outermost wrapper (Starlette
# builds the middleware stack LIFO by add_middleware() call order) —
# every request gets a request_id and is measured, regardless of what
# CORS/routing does with it.
app.add_middleware(ObservabilityMiddleware)

# Error handling: catches SafeSOCError and every subclass (IngestionError,
# OpenSearchError, ...), producing a consistent {"error", "status_code"} body.
app.add_exception_handler(SafeSOCError, safesoc_exception_handler)

# Register routers
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(cloud.router)
app.include_router(endpoints.router)
app.include_router(investigate.router)
app.include_router(reports.router)
app.include_router(threat_analytics.router)
app.include_router(ws.router)


DEFAULT_JWT_SECRET = "change-me-to-a-64-char-random-string"


@app.on_event("startup")
async def startup():
    """Verify services on startup."""
    from app.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("SafeSOC starting", env=settings.ENV)

    # SS-067: JWT_SECRET's default is public (it's right here in source
    # control), so every token becomes forgeable by anyone who's read
    # this file if a deployer forgets to override it. Refuse to start
    # in production rather than run silently insecure; still runnable
    # in dev/test so the default remains a valid out-of-the-box value.
    if settings.JWT_SECRET == DEFAULT_JWT_SECRET:
        if settings.ENV == "production":
            raise RuntimeError(
                "JWT_SECRET is still the default value. Set a unique, random "
                "JWT_SECRET before starting SafeSOC in production."
            )
        logger.warning(
            "JWT_SECRET is still the default value — every issued token is "
            "forgeable. This is only acceptable outside production.",
            env=settings.ENV,
        )

    from app.db.opensearch import ensure_ilm_policy
    try:
        await ensure_ilm_policy()
    except Exception as e:
        # Non-fatal: OpenSearch may not be reachable yet (e.g. manual/non-compose
        # startup ordering). The app should still come up; /health already
        # reports OpenSearch connectivity separately.
        logger.warning("Could not ensure ILM policy at startup", error=str(e))


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }