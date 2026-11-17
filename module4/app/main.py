"""FastAPI application factory, lifespan management, and route registration."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from app.config import get_settings
from app.db import init_db
from app.routes_audit_receipts import router as audit_receipts_router
from app.routes_run import router as run_router
from app.routes_upload import router as upload_router
from app.schemas import HealthResponse
from app.session_manager import session_manager


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown events."""
    # 1. Initialize SQLite schema
    init_db()

    # 2. Start background TTL expiration loop
    cleanup_task = asyncio.create_task(session_manager.run_ttl_cleanup_loop())

    try:
        yield
    finally:
        # Cancel background task and wipe any remaining sessions on shutdown
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        session_manager.wipe_all()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    settings = get_settings()

    app = FastAPI(
        title="Module 4: Auto-Delete Proxy & API Gateway",
        description="Privacy-preserving proxy ensuring RAM-only processing and leak prevention.",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Register API routers
    app.include_router(upload_router)
    app.include_router(run_router)
    app.include_router(audit_receipts_router)

    @app.get(
        "/health",
        response_model=HealthResponse,
        summary="Service Health Check",
        tags=["System"],
    )
    async def health_check() -> HealthResponse:
        """Return operational health status."""
        return HealthResponse(status="ok")

    return app


app: FastAPI = create_app()
