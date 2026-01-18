import os
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path

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

    repo_root = Path(__file__).parent.parent
    template_path = repo_root / "opencode.json.template"
    output_path = repo_root / "opencode.json"

    if template_path.exists() and not output_path.exists():
        if settings.litellm_proxy_url:
            logger.info("Generating opencode.json from template")
            subprocess.run(
                [
                    "sed",
                    f"s|<LITELLM_PROXY_URL>|{settings.litellm_proxy_url}|g",
                    str(template_path),
                ],
                stdout=open(output_path, "w"),
            )

    yield
    logger.info("Shutting down Lightspeed Orchestrator")


app = FastAPI(
    title="Lightspeed Orchestrator",
    description="Event-driven orchestrator for handling ForgeJo webhooks",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,  # type: ignore[arg-type]
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
