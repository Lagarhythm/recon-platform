from fastapi import APIRouter

from recon.web.routes import (
    api_v1,
    assets,
    audit,
    auth,
    dashboard,
    engagements,
    reports,
    scans,
    setup,
    system,
)

api_router = APIRouter()
api_router.include_router(api_v1.router)
api_router.include_router(system.router)
api_router.include_router(setup.router)
api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(engagements.router)
api_router.include_router(scans.router)
api_router.include_router(assets.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)

__all__ = ["api_router"]
