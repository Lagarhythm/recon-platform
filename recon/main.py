"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from recon import __version__
from recon.config import get_settings
from recon.web.deps import _Redirect, redirect_exception_response
from recon.web.middleware import CsrfCookieMiddleware, SetupGateMiddleware
from recon.web.routes import api_router

_STATIC_DIR = Path(__file__).parent / "web" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_settings().ensure_dirs()
    from recon.orchestrator.scans import scan_service

    try:
        await scan_service.reap_orphans()
    except Exception:  # e.g. DB not migrated yet - don't block startup
        pass
    try:
        from recon.db import session_scope
        from recon.orchestrator.auth import AuthService

        async with session_scope() as session:
            await AuthService().maybe_bootstrap_admin(session)
    except Exception:  # DB not migrated yet / no bootstrap vars - never block startup
        pass
    yield
    await scan_service.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Integrated Reconnaissance Platform",
        version=__version__,
        docs_url="/api/docs" if settings.debug else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )

    app.add_middleware(CsrfCookieMiddleware)
    app.add_middleware(SetupGateMiddleware)

    @app.exception_handler(_Redirect)
    async def _handle_redirect(request: Request, exc: _Redirect):  # noqa: ANN202
        return redirect_exception_response(exc)

    _STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    app.include_router(api_router)
    return app


app = create_app()
