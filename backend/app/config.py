from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    environment: str = "production"
    secret_key: str
    database_url: str | None = None
    redis_url: str | None = None
    allowed_origins: str = ""
    request_timeout_seconds: int = 12
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def origins(self) -> list[str]:
        return [value.strip() for value in self.allowed_origins.split(",") if value.strip()]

@lru_cache
def get_settings() -> Settings: return Settings()
