from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    root_dir: Path
    site_dir: Path
    static_dir: Path
    template_dir: Path
    dist_dir: Path
    public_base_url: str
    canonical_host: str
    allowed_hosts: list[str]
    force_https: bool
    canonical_redirect: bool
    rate_limit_per_minute: int
    security_contact: str
    site_name: str = "CryptEX"
    tagline: str = "512-bit SHA3 network"
    organization: str = "CryptEX Network"
    marketing_domain: str = "cryptexorg.duckdns.org"
    repository_url: str = "https://github.com/Anonymous137-sudo/CryptEX_Core"


def load_settings() -> Settings:
    root_dir = Path(__file__).resolve().parents[2]
    site_dir = root_dir / "website"
    public_base_url = os.getenv("CRYPTEX_SITE_URL", "https://cryptexorg.duckdns.org").rstrip("/")
    canonical_host = public_base_url.split("://", 1)[-1].split("/", 1)[0]
    allowed_hosts_env = os.getenv("CRYPTEX_ALLOWED_HOSTS", canonical_host + ",localhost,127.0.0.1")
    allowed_hosts = [host.strip() for host in allowed_hosts_env.split(",") if host.strip()]
    return Settings(
        root_dir=root_dir,
        site_dir=site_dir,
        static_dir=site_dir / "static",
        template_dir=site_dir / "templates",
        dist_dir=root_dir / "dist",
        public_base_url=public_base_url,
        canonical_host=canonical_host,
        allowed_hosts=allowed_hosts,
        force_https=_env_flag("CRYPTEX_FORCE_HTTPS", False),
        canonical_redirect=_env_flag("CRYPTEX_CANONICAL_REDIRECT", False),
        rate_limit_per_minute=max(30, int(os.getenv("CRYPTEX_RATE_LIMIT_PER_MINUTE", "240"))),
        security_contact=os.getenv("CRYPTEX_SECURITY_CONTACT", "security@cryptexorg.duckdns.org"),
        repository_url=os.getenv("CRYPTEX_REPOSITORY_URL", "https://github.com/Anonymous137-sudo/CryptEX_Core"),
    )
