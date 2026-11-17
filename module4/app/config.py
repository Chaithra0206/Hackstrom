"""Configuration settings loaded via pydantic-settings."""

from functools import lru_cache
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings and environment configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    GEMINI_API_KEY: str = Field(
        default="",
        description="API key for Google Gemini provider.",
    )
    OPENAI_API_KEY: str = Field(
        default="",
        description="API key for OpenAI provider.",
    )
    RECEIPT_SIGNING_KEY: str = Field(
        default="default_insecure_key_for_dev_32chars_min_length",
        min_length=32,
        description="Cryptographic secret key for signing deletion receipts.",
    )
    MAX_IMAGE_MB: int = Field(
        default=10,
        gt=0,
        description="Maximum permitted image size in megabytes.",
    )
    EGRESS_ALLOWED_DOMAINS: str = Field(
        default="",
        description="Comma-separated list of permitted outbound domain names.",
    )
    SESSION_TTL_SECONDS: int = Field(
        default=120,
        gt=0,
        description="Maximum lifespan of an image buffer in seconds before forced deletion.",
    )

    @property
    def allowed_domains_list(self) -> List[str]:
        """Return allowed domains as a trimmed list of strings."""
        if not self.EGRESS_ALLOWED_DOMAINS.strip():
            return []
        return [
            domain.strip().lower()
            for domain in self.EGRESS_ALLOWED_DOMAINS.split(",")
            if domain.strip()
        ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
