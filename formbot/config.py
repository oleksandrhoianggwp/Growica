"""Application settings, loaded from environment variables and an optional .env file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Target form -------------------------------------------------------
    form_url: str = Field(default="https://linkreclamatiogrwc.uk/")

    # --- CAPTCHA -----------------------------------------------------------
    # "2captcha": token solved through the 2captcha API (fully automatic).
    # "manual":   an operator ticks the reCAPTCHA in a visible browser window (requires HEADLESS=false).
    captcha_provider: Literal["2captcha", "manual"] = "2captcha"
    twocaptcha_api_key: str = ""
    twocaptcha_api_url: str = "https://api.2captcha.com"
    captcha_poll_interval: float = Field(default=5.0, gt=0)
    captcha_solve_timeout: float = Field(default=180.0, gt=0)

    # --- Browser -----------------------------------------------------------
    headless: bool = True
    navigation_timeout: float = Field(default=45.0, gt=0)
    action_timeout: float = Field(default=15.0, gt=0)
    submit_result_timeout: float = Field(default=60.0, gt=0)
    submission_timeout: float = Field(default=420.0, gt=0)
    # When true the form is filled and checked but neither the CAPTCHA is solved nor the form submitted.
    dry_run: bool = False

    # --- Queue / rate limits ----------------------------------------------
    min_submit_interval: float = Field(default=10.0, ge=0)
    max_auto_attempts: int = Field(default=2, ge=1, le=5)
    max_total_attempts: int = Field(default=6, ge=1)
    retry_cooldown: float = Field(default=30.0, ge=0)
    max_targets_per_batch: int = Field(default=100, ge=1)
    max_queue_size: int = Field(default=1000, ge=1)

    # --- Storage -----------------------------------------------------------
    data_dir: Path = Path("data")

    # --- Server / logging --------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    @field_validator("form_url")
    @classmethod
    def _form_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("FORM_URL must start with http:// or https://")
        return value if value.endswith("/") else value + "/"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "submissions.db"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def snapshot_dir(self) -> Path:
        return self.data_dir / "responses"

    def captcha_config_error(self) -> str | None:
        """Return a human readable reason why CAPTCHA solving cannot work, or None if it can."""
        if self.captcha_provider == "2captcha" and not self.twocaptcha_api_key.strip():
            return "TWOCAPTCHA_API_KEY is not set. Add it to .env (see .env.example)."
        if self.captcha_provider == "manual" and self.headless:
            return "CAPTCHA_PROVIDER=manual needs a visible browser: set HEADLESS=false and run the app locally."
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
