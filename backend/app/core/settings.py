from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "EFF-Monitoring"
    api_prefix: str = "/api"
    database_url: str = "sqlite:///./eff_monitoring.db"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60 * 12
    initial_admin_username: str = "admin"
    initial_admin_password: str = "admin123"
    cors_origins: str = "http://localhost:5173,http://localhost:8080,http://127.0.0.1:5173"
    demo_user_password: str = "demo123456"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def is_production_like(self) -> bool:
        """Heuristic: using PostgreSQL (not SQLite) suggests a real deployment."""
        return self.database_url.startswith("postgresql")


@lru_cache
def get_settings() -> Settings:
    return Settings()
