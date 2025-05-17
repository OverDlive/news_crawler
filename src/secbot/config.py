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

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, validator

# -----------------------------------------------------------------------------
# Settings Model
# -----------------------------------------------------------------------------


class Settings(BaseSettings):
    # ------------------------------------------------------------------ #
    # Cron / Scheduler
    # ------------------------------------------------------------------ #
    cron_time: List[str] = Field(
        default_factory=lambda: ["06:00"],
        env="SEC_BOT_CRON_TIME",
        description="Comma-separated list of HH:MM times (24‑hour local timezone) for daily jobs.",
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
    smtp_user: str = Field(
        "",
        env="SEC_BOT_SMTP_USER",
        description="Sender address (blank = e‑mail disabled)",
    )
    mail_to: List[str] = Field(
        default_factory=list,
        env="SEC_BOT_MAIL_TO",
        description="Comma‑separated recipient list",
    )
    # Note: mail_to can be empty (no recipients) without raising validation errors.

    # Convenience flag
    @property
    def email_enabled(self) -> bool:  # noqa: D401
        "Return True if both smtp_user and at least one recipient are set."
        return bool(self.smtp_user and self.mail_to)

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
    # Model Config (Pydantic v2+)
    # ------------------------------------------------------------------ #
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",   # Ignore unknown env vars like sec_bot_*
    )

    # ------------------------------------------------------------------ #
    # Validators
    # ------------------------------------------------------------------ #
    @validator("mail_to", pre=True)
    def _split_emails(cls, v):
        if isinstance(v, str):
            return [e.strip() for e in v.split(",") if e.strip()]
        return v

    @validator("cron_time", pre=True)
    def _split_cron_time(cls, v):
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v

    # ------------------------------------------------------------------ #
    # IOC Scheduler
    # ------------------------------------------------------------------ #
    ioc_time: str = Field(
        "10:00",
        env="SEC_BOT_IOC_TIME",
        description="HH:MM time (24-hour local timezone) for daily IOC email.",
    )

    @validator("ioc_time", pre=True)
    def _parse_ioc_time(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v

    @validator("enable_ipset", "enable_suricata", pre=True)
    def _parse_bool(cls, v):
        """
        Convert common truthy / falsy strings to real booleans so that
        Docker `-e SEC_BOT_ENABLE_IPSET=false` is parsed as False.
        """
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "yes", "y", "on"}
        return bool(v)


# -----------------------------------------------------------------------------
# Singleton / Cached accessor
# -----------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton instance of :class:`Settings`."""
    return Settings()


# Alias for convenience import style:  from secbot.config import settings
settings: Settings = get_settings()
