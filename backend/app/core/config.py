from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]

# Load environment variables
load_dotenv(BACKEND_DIR / ".env")


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
    ai_model: str = os.getenv("AI_MODEL", "gemini-3.6-flash")
    scan_timeout: float = float(os.getenv("SCAN_TIMEOUT", "15"))
    max_redirects: int = int(os.getenv("MAX_REDIRECTS", "3"))
    max_response_bytes: int = int(os.getenv("MAX_RESPONSE_BYTES", "262144"))
    rate_limit: int = int(os.getenv("RATE_LIMIT", "20"))
    data_dir: Path = Path(os.getenv("DATA_DIR", str(BACKEND_DIR / ".data")))
    strix_llm: str = os.getenv("STRIX_LLM", "")
    strix_api_key: str = os.getenv("LLM_API_KEY", "")
    strix_docker_image: str = os.getenv("STRIX_DOCKER_IMAGE", "ghcr.io/strix-labs/strix-sandbox:latest")
    strix_max_turns: int = int(os.getenv("STRIX_MAX_TURNS", "100"))
    strix_scan_timeout: int = int(os.getenv("STRIX_SCAN_TIMEOUT", "1800"))

    @property
    def allowed_origins(self) -> list[str]:
        configured = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        return configured or [self.frontend_url, "http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)

