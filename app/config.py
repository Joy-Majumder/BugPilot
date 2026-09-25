import os
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    PROJECT_DIR: Path = Path(__file__).parent.parent
    VENV_DIR: Path = PROJECT_DIR / "venv"
    TOOLS_DIR: Path = PROJECT_DIR / "tools"
    DATA_DIR: Path = PROJECT_DIR / "data"
    REPORTS_DIR: Path = PROJECT_DIR / "reports"
    NUCLEI_TEMPLATES_DIR: Path = TOOLS_DIR / "nuclei-templates"

    DATABASE_URL: str = f"sqlite:///{DATA_DIR}/findings.db"
    OOB_DOMAIN: str = "oob.local"
    OOB_HTTP_PORT: int = 8081
    OOB_DNS_PORT: int = 5353

    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8080

    DEFAULT_RATE_LIMIT: int = 10
    DEFAULT_CONCURRENCY: int = 5
    REQUEST_TIMEOUT: int = 30

    PLAYWRIGHT_BROWSERS_PATH: Path = TOOLS_DIR / "pw-browsers"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(settings.PLAYWRIGHT_BROWSERS_PATH)