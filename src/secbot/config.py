"""
secbot.config
~~~~~~~~~~~~~

Centralised runtime configuration for **SecBot**.

The module leverages *Pydantic*'s `BaseSettings` so that every option can
be overridden via environment variables **or** an optional `.env` file at
project root.  Doing so removes boilerplate from individual modules and
makes unit‑testing easier.

Typical usage
-------------

>>> from secbot.config import settings
>>> print(settings.news_limit)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import AnyUrl, BaseSettings, Field, validator

# -----------------------------------------------------------------------------
# Settings Model
# -----------------------------------------------------------------------------


class Settings(BaseSettings):
    # ------------------------------------------------------------------ #
    # Cron / Scheduler
    # ------------------------------------------------------------------ #
    cron_time: str = Field(
        "06:00",
        env="SEC_BOT_CRON_TIME",
        description="HH:MM in 24‑hour format (local timezone) for daily job.",
    )

    # ------------------------------------------------------------------ #
    # Fetcher limits
    # ------------------------------------------------------------------ #
    news_limit: int = Field(
        10,
        env="SEC_BOT_NEWS_LIMIT",
        ge=1,
        le=50,
        description="Max headlines to fetch per run.",
    )
    advisory_limit: int = Field(
        10,
        env="SEC_BOT_ADVISORY_LIMIT",
        ge=1,
        le=50,
        description="Max KISA advisories to fetch.",
    )
    asec_post_limit: int = Field(
        5,
        env="SEC_BOT_ASEC_LIMIT",
        ge=1,
        le=20,
        description="Number of recent ASEC posts to scan for IOC.",
    )

    # ------------------------------------------------------------------ #
    # Mail / SMTP
    # ------------------------------------------------------------------ #
    smtp_user: str = Field(..., env="SEC_BOT_SMTP_USER", description="Sender address")
    mail_to: List[str] = Field(
        default_factory=list,
        env="SEC_BOT_MAIL_TO",
        description="Comma‑separated recipient list",
    )

    # ------------------------------------------------------------------ #
    # Defence integration toggles
    # ------------------------------------------------------------------ #
    enable_ipset: bool = Field(
        True, env="SEC_BOT_ENABLE_IPSET", description="Enable ipset blocking"
    )
    enable_suricata: bool = Field(
        False, env="SEC_BOT_ENABLE_SURICATA", description="Enable Suricata reload"
    )

    # ------------------------------------------------------------------ #
    # Misc
    # ------------------------------------------------------------------ #
    debug: bool = Field(False, env="SEC_BOT_DEBUG")
    data_dir: Path = Field(Path("./data"), env="SEC_BOT_DATA_DIR")

    # ------------------------------------------------------------------ #
    # Model Config
    # ------------------------------------------------------------------ #
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @validator("mail_to", pre=True)
    def _split_emails(cls, v):
        if isinstance(v, str):
            return [e.strip() for e in v.split(",") if e.strip()]
        return v


# -----------------------------------------------------------------------------
# Singleton / Cached accessor
# -----------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of :class:`Settings`."""
    return Settings()


# Alias for convenience import style:  from secbot.config import settings
settings: Settings = get_settings()
