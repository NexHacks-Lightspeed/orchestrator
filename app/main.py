from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.logging import logger
from app.settings import settings
from app.webhooks import router as webhook_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Lightspeed Orchestrator")
    if not settings.forgejo_api_token:
        logger.critical("FORGEJO_API_TOKEN is not configured - orchestrator cannot push to Forgejo")
        raise SystemExit(1)
    yield
    logger.info("Shutting down Lightspeed Orchestrator")


app = FastAPI(
    title="Lightspeed Orchestrator",
    description="Event-driven orchestrator for handling ForgeJo webhooks",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(webhook_router, prefix="/api/webhooks", tags=["webhooks"])


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
