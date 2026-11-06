"""FastAPI application factory."""

from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging, get_logger

log = get_logger("http")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        started = time.monotonic()
        response = await call_next(request)
        settings = get_settings()
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        if settings.is_production_like:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if request.url.path not in ("/api/v1/health/live",):
            log.info(
                "request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=int((time.monotonic() - started) * 1000),
                request_id=request.state.request_id,
            )
        return response


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(json=settings.environment != "development")
    problems = settings.validate_for_runtime()
    if problems and settings.is_production_like:
        raise RuntimeError("Refusing to start: " + "; ".join(problems))
    for p in problems:
        log.warning("configuration_warning", problem=p)

    app = FastAPI(
        title=f"{settings.product_name} API",
        version="0.1.0",
        description=(
            f"{settings.product_name} by {settings.company_name}. Website security monitoring API. "
            "All tenant-scoped routes live under /api/v1/tenants/{tenant_id}/..."
        ),
        docs_url="/api/docs" if not settings.is_production_like else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if not settings.is_production_like else None,
        debug=settings.debug and not settings.is_production_like,
    )
    install_error_handlers(app)
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID", "Authorization"],
        )

    from app.api.v1 import router as v1

    app.include_router(v1.api_router, prefix="/api/v1")
    return app


app = create_app()
