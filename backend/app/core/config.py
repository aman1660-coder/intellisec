from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    app_name: str = "IntelliSec"
    environment: str = os.getenv("ENVIRONMENT", "development")
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:5173")
    cors_origins: str = os.getenv("CORS_ORIGINS", "")
    mongodb_uri: str = os.getenv("MONGODB_URI", "")
    mongodb_db: str = os.getenv("MONGODB_DB", "intellisec")
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-in-production")
    jwt_exp_minutes: int = int(os.getenv("JWT_EXP_MINUTES", "1440"))
    ai_provider: str = os.getenv("AI_PROVIDER", "gemini")
    ai_api_key: str = os.getenv("AI_API_KEY", "")
    ai_model: str = os.getenv("AI_MODEL", "gemini-1.5-flash")
    scan_timeout: float = float(os.getenv("SCAN_TIMEOUT", "6"))
    max_redirects: int = int(os.getenv("MAX_REDIRECTS", "3"))
    max_response_bytes: int = int(os.getenv("MAX_RESPONSE_BYTES", "262144"))
    rate_limit: int = int(os.getenv("RATE_LIMIT", "20"))
    data_dir: Path = Path(os.getenv("DATA_DIR", str(BACKEND_DIR / ".data")))

    @property
    def allowed_origins(self) -> list[str]:
        configured = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        return configured or [self.frontend_url, "http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)

