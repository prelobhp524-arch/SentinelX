import asyncio
import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.traffic import router as traffic_router
from app.api.alerts import router as alerts_router
from app.core.config import settings
from app.api.analytics import router as analytics_router
from app.api.capture import router as capture_router
from app.api.reputation import router as reputation_router
from app.api.websocket import router as websocket_router
from app.services.ip_reputation_runtime import ip_reputation_worker
from app.services.websocket_manager import websocket_manager
from fastapi.middleware.cors import CORSMiddleware


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):

    websocket_manager.register_loop(asyncio.get_running_loop())

    try:
        if settings.IP_REPUTATION_ENABLED:
            ip_reputation_worker.start()

        yield
    finally:
        try:
            if not ip_reputation_worker.stop():
                logger.warning(
                    "IP reputation worker did not stop within timeout"
                )
        finally:
            websocket_manager.clear_loop()


PUBLIC_DEMO_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class PublicDemoModeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if (
            settings.PUBLIC_DEMO_MODE
            and request.method not in PUBLIC_DEMO_SAFE_METHODS
        ):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": (
                        "This deployment is read-only. "
                        "State-changing requests are disabled in public "
                        "demo mode."
                    )
                }
            )

        return await call_next(request)


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Real-Time Network Intrusion Detection and Prevention System",
    version=settings.PROJECT_VERSION,
    lifespan=lifespan
)
app.add_middleware(PublicDemoModeMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Register API routers
app.include_router(traffic_router)
app.include_router(alerts_router)
app.include_router(analytics_router)
app.include_router(capture_router)
app.include_router(reputation_router)
app.include_router(websocket_router)

@app.get("/")
def home():
    return {
        "message": "Welcome to SentinelX",
        "status": "Running",
        "project": "Network Intrusion Detection System"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelX Backend"
    }