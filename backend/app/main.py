from fastapi import FastAPI

from app.api.traffic import router as traffic_router
from app.api.alerts import router as alerts_router
from app.core.config import settings
from app.api.analytics import router as analytics_router
from app.api.capture import router as capture_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Real-Time Network Intrusion Detection and Prevention System",
    version=settings.PROJECT_VERSION
)
# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Register API routers
app.include_router(traffic_router)
app.include_router(alerts_router)
app.include_router(analytics_router)
app.include_router(capture_router)

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