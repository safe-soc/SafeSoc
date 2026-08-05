"""
SafeSOC — FastAPI Application Entry Point
"""
from app.routers.v1 import alerts
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
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


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }