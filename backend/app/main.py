"""
SafeSOC — FastAPI Application Entry Point
"""
from app.routers.v1 import alerts
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exceptions import SafeSOCError, safesoc_exception_handler
from app.routers import health
from app.routers.v1 import ingest

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

# Error handling: catches SafeSOCError and every subclass (IngestionError,
# OpenSearchError, ...), producing a consistent {"error", "status_code"} body.
app.add_exception_handler(SafeSOCError, safesoc_exception_handler)

# Register routers
app.include_router(health.router)
app.include_router(ingest.router)
app.include_router(alerts.router)


@app.on_event("startup")
async def startup():
    """Verify services on startup."""
    from app.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("SafeSOC starting", env=settings.ENV)

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