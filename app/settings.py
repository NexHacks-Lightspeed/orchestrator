from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # CORS configuration
    allowed_origins: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Comma-separated list of allowed CORS origins",
    )

    # Forgejo webhook configuration
    # FJ webhooks need a secret
    forgejo_webhook_secret: str = Field(
        default="",
        description="Secret for verifying Forgejo webhook signatures",
    )

    # Modal configuration
    modal_app_name: str = Field(
        default="lightspeed-orchestrator",
        description="Modal app name for sandboxes",
    )

    # Forgejo API token for Git operations and API calls
    forgejo_api_token: str = Field(
        default="",
        description="API token for Git push operations and Forgejo API calls",
    )

    # LiteLLM proxy URL for OpenCode Lens
    litellm_proxy_url: str = Field(
        default="",
        description="URL for the LiteLLM proxy server used by OpenCode Lens",
    )

    # Server configuration
    port: int = Field(default=8000, description="Port to run the server on")
    log_level: str = Field(default="INFO", description="Logging level")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",")]


settings = Settings()
