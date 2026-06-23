from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "MetaSec Security Center"
    app_env: str = "local"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./detectionforge.db"
    data_dir: str = "../../data"
    config_dir: str = "../../configs"
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    sigma_cli_bin: str = "sigma"
    # Generator backend selection: "auto" (pySigma then builtin),
    # "builtin" (AST compiler only), or "pysigma" (no builtin fallback).
    generator_backend: str = "auto"
    # Cache generated queries in the conversion_cache table.
    generator_cache_enabled: bool = True
    # Threat Intel auto-update: minutes between background feed refreshes
    # (0 disables). First run is delayed by one interval so startup never
    # blocks on the network.
    intel_auto_refresh_minutes: int = 720
    # Days after last_seen before an indicator is marked inactive (aged out).
    intel_ttl_days: int = 30

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).resolve()

    @property
    def config_path(self) -> Path:
        return Path(self.config_dir).resolve()

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
