from fastapi import APIRouter

from app.api.v1 import (
    auth,
    commerce,
    dashboard,
    health,
    hosting,
    incidents,
    monitoring,
    notifications,
    platform,
    tenants,
    websites,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(tenants.public_router)
api_router.include_router(dashboard.router)
api_router.include_router(websites.router)
api_router.include_router(hosting.router)
api_router.include_router(hosting.connectors_router)
api_router.include_router(monitoring.router)
api_router.include_router(incidents.router)
api_router.include_router(notifications.router)
api_router.include_router(commerce.router)
api_router.include_router(commerce.public_router)
api_router.include_router(platform.admin)
api_router.include_router(platform.ops)
