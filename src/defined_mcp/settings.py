"""Configuration via environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Defined Networking API settings loaded from DEFINED_* env vars."""

    model_config = SettingsConfigDict(env_prefix="DEFINED_")

    api_key: str
    api_base_url: str = "https://api.defined.net"
    page_size: int = 25
