from __future__ import annotations

import os
import sys
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
    data_dir: Path
    reserve_status_path: Path
    public_base_url: str
    canonical_host: str
    allowed_hosts: list[str]
    force_https: bool
    canonical_redirect: bool
    rate_limit_per_minute: int
    security_contact: str
    rpc_url: str
    rpc_user: str
    rpc_password: str
    rpc_timeout_seconds: float
    site_name: str = "CryptEX"
    tagline: str = "512-bit SHA3 network"
    organization: str = "CryptEX Network"
    marketing_domain: str = "cryptexorg.duckdns.org"
    repository_url: str = "https://github.com/Anonymous137-sudo/CryptEX_Core"


def load_settings() -> Settings:
    root_dir = Path(__file__).resolve().parents[2]
    site_dir = root_dir / "website"
    if os.name == "nt":
        data_home = os.getenv("APPDATA") or str(Path.home() / "AppData/Roaming")
    elif sys.platform == "darwin":
        data_home = str(Path.home() / "Library/Application Support")
    else:
        data_home = os.getenv("XDG_DATA_HOME") or str(Path.home() / ".local/share")
    data_dir = Path(os.getenv("CRYPTEX_DATA_DIR", str(Path(data_home) / "CryptEX")))
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
        data_dir=data_dir,
        reserve_status_path=Path(os.getenv("CRYPTEX_RESERVE_STATUS_PATH", str(site_dir / "data" / "reserve_status.json"))),
        public_base_url=public_base_url,
        canonical_host=canonical_host,
        allowed_hosts=allowed_hosts,
        force_https=_env_flag("CRYPTEX_FORCE_HTTPS", False),
        canonical_redirect=_env_flag("CRYPTEX_CANONICAL_REDIRECT", False),
        rate_limit_per_minute=max(30, int(os.getenv("CRYPTEX_RATE_LIMIT_PER_MINUTE", "240"))),
        security_contact=os.getenv("CRYPTEX_SECURITY_CONTACT", "Anon-Sec-BTCC@proton.me"),
        rpc_url=os.getenv("CRYPTEX_RPC_URL", "").strip(),
        rpc_user=os.getenv("CRYPTEX_RPC_USER", "").strip(),
        rpc_password=os.getenv("CRYPTEX_RPC_PASSWORD", ""),
        rpc_timeout_seconds=max(1.0, float(os.getenv("CRYPTEX_RPC_TIMEOUT_SECONDS", "3.0"))),
        repository_url=os.getenv("CRYPTEX_REPOSITORY_URL", "https://github.com/Anonymous137-sudo/CryptEX_Core"),
    )
