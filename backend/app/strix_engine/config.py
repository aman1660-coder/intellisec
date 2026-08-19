from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path

from app.core.config import BACKEND_DIR

@dataclass(frozen=True)
class StrixConfig:
    llm_model: str = os.getenv("STRIX_LLM", "")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    docker_image: str = os.getenv("STRIX_DOCKER_IMAGE", "ghcr.io/strix-labs/strix-sandbox:latest")
    max_turns: int = int(os.getenv("STRIX_MAX_TURNS", "100"))
    runs_dir: Path = Path(os.getenv("STRIX_RUNS_DIR", str(BACKEND_DIR / "strix_runs")))
    scan_timeout: int = int(os.getenv("STRIX_SCAN_TIMEOUT", "1800"))
    strix_path: str = os.getenv("STRIX_PATH", "C:\\Users\\aman7\\Downloads\\strix-extracted\\strix-main")

    @property
    def is_configured(self) -> bool:
        return bool(self.llm_model and self.llm_api_key)

    @property
    def docker_available(self) -> bool:
        import shutil
        return shutil.which("docker") is not None

strix_config = StrixConfig()
