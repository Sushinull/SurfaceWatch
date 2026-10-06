import logging
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import auth, events, notifications, targets
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import SessionLocal

configure_logging()
app = FastAPI(
    title="SurfaceWatch",
    version="1.0.0",
    description="Authorized service change monitoring. Failed/partial scans never imply removal.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=list(
        {
            "localhost",
            "127.0.0.1",
            "testserver",
            "backend",
            urlparse(get_settings().app_origin).hostname,
        }
    ),
)


@app.middleware("http")
async def security(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if request.headers.get("x-surfacewatch") != "1" or (
            origin and origin != get_settings().app_origin
        ):
            return JSONResponse(
                {"detail": "Invalid origin or missing X-SurfaceWatch header"}, status_code=403
            )
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def error_handler(request: Request, exc: Exception):
    logging.getLogger(__name__).error(
        "request_failed method=%s path=%s type=%s",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse({"detail": "Internal error; check service logs"}, status_code=500)


@app.get("/api/health", tags=["Health"])
def health():
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok"}


for router in (auth.router, targets.router, events.router, notifications.router):
    app.include_router(router, prefix="/api")
