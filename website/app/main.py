from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import load_settings
from .security import CanonicalHostMiddleware, HttpsEnforcementMiddleware, SecurityHeadersMiddleware, SimpleRateLimitMiddleware

settings = load_settings()
app = FastAPI(title="CryptEX Website", docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(CanonicalHostMiddleware, canonical_host=settings.canonical_host, enabled=settings.canonical_redirect)
app.add_middleware(HttpsEnforcementMiddleware, force_https=settings.force_https)
app.add_middleware(SimpleRateLimitMiddleware, requests_per_minute=settings.rate_limit_per_minute)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=512)
app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")
templates = Jinja2Templates(directory=str(settings.template_dir))


ARTIFACTS = [
    {
        "slug": "macos-gui-zip",
        "label": "CryptEX Qt macOS ARM64 bundle",
        "platform": "macOS",
        "arch": "ARM64",
        "kind": "Application archive",
        "filename": "CryptEX_macos_arm64_bundle.zip",
        "highlight": True,
    },
    {
        "slug": "macos-cli",
        "label": "cryptexd macOS ARM64",
        "platform": "macOS",
        "arch": "ARM64",
        "kind": "CLI/backend",
        "filename": "cryptexd_macos_arm64",
        "highlight": False,
    },
    {
        "slug": "windows-bundle",
        "label": "CryptEX Windows x86_64 runtime bundle",
        "platform": "Windows",
        "arch": "x86_64",
        "kind": "Runtime bundle",
        "filename": "CryptEX_windows_x86_64_bundle.zip",
        "highlight": True,
    },
    {
        "slug": "windows-gui",
        "label": "CryptEX Qt Windows x86_64",
        "platform": "Windows",
        "arch": "x86_64",
        "kind": "GUI exe",
        "filename": "cryptexqt_windows_x86_64.exe",
        "highlight": False,
    },
    {
        "slug": "windows-cli",
        "label": "cryptexd Windows x86_64",
        "platform": "Windows",
        "arch": "x86_64",
        "kind": "CLI/backend",
        "filename": "cryptexd_windows_x86_64.exe",
        "highlight": False,
    },
    {
        "slug": "linux-gui-x64",
        "label": "CryptEX Qt Linux x86_64 AppImage",
        "platform": "Linux",
        "arch": "x86_64",
        "kind": "AppImage",
        "filename": "cryptexqt_linux_x86_64.AppImage",
        "highlight": True,
    },
    {
        "slug": "linux-cli-x64",
        "label": "cryptexd Linux x86_64",
        "platform": "Linux",
        "arch": "x86_64",
        "kind": "CLI/backend",
        "filename": "cryptexd_linux_x86_64",
        "highlight": False,
    },
    {
        "slug": "linux-gui-arm64",
        "label": "CryptEX Qt Linux ARM64 AppImage",
        "platform": "Linux",
        "arch": "ARM64",
        "kind": "AppImage",
        "filename": "cryptexqt_linux_arm64.AppImage",
        "highlight": True,
    },
    {
        "slug": "linux-cli-arm64",
        "label": "cryptexd Linux ARM64",
        "platform": "Linux",
        "arch": "ARM64",
        "kind": "CLI/backend",
        "filename": "cryptexd_linux_arm64",
        "highlight": False,
    },
]


class RpcUnavailable(RuntimeError):
    pass


def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(size_bytes)
    unit = 0
    while size >= 1024 and unit < len(units) - 1:
        size /= 1024.0
        unit += 1
    if unit == 0:
        return f"{int(size)} {units[unit]}"
    return f"{size:.1f} {units[unit]}"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifacts() -> list[dict[str, str]]:
    built: list[dict[str, str]] = []
    for artifact in ARTIFACTS:
        path = settings.dist_dir / artifact["filename"]
        if not path.exists() or not path.is_file():
            continue
        built.append(
            {
                **artifact,
                "download_url": f"/artifacts/{artifact['filename']}",
                "size": human_size(path.stat().st_size),
                "sha256": file_sha256(path),
            }
        )
    return built


def parse_simple_config(path: Path) -> dict[str, str]:
    if not path.exists() or not path.is_file():
        return {}
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        entries[key.strip().lower()] = value.strip()
    return entries


def loopback_rpc_host(bind: str) -> str:
    bind = bind.strip()
    if bind in {"", "0.0.0.0", "::", "*"}:
        return "127.0.0.1"
    return bind


def resolve_rpc_settings() -> tuple[str, str, str]:
    config_entries = parse_simple_config(settings.data_dir / "cryptex.conf")
    rpc_url = settings.rpc_url
    if not rpc_url:
        host = loopback_rpc_host(config_entries.get("rpcbind", "127.0.0.1"))
        port = config_entries.get("rpcport", "9332")
        rpc_url = f"http://{host}:{port}/"
    rpc_user = settings.rpc_user or config_entries.get("rpcuser", "")
    rpc_password = settings.rpc_password or config_entries.get("rpcpassword", "")
    return rpc_url, rpc_user, rpc_password


def rpc_call(method: str, params: list[Any] | None = None) -> Any:
    rpc_url, rpc_user, rpc_password = resolve_rpc_settings()
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": method,
            "method": method,
            "params": params or [],
        }
    ).encode("utf-8")
    request = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    if rpc_user:
        auth = base64.b64encode(f"{rpc_user}:{rpc_password}".encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(request, timeout=settings.rpc_timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RpcUnavailable(f"HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RpcUnavailable(str(exc.reason)) from exc
    except TimeoutError as exc:
        raise RpcUnavailable("RPC timeout") from exc

    error = body.get("error")
    if error:
        if isinstance(error, dict):
            raise RpcUnavailable(error.get("message", "RPC error"))
        raise RpcUnavailable(str(error))
    return body.get("result")


def safe_rpc_call(method: str, params: list[Any] | None = None) -> tuple[Any | None, str | None]:
    try:
        return rpc_call(method, params), None
    except RpcUnavailable as exc:
        return None, str(exc)


def format_coins(sats: int | float | None) -> str:
    if sats is None:
        return "-"
    value = int(sats)
    negative = value < 0
    value = abs(value)
    whole = value // 100_000_000
    frac = value % 100_000_000
    return f"{'-' if negative else ''}{whole}.{frac:08d} CryptEX"


def format_hashrate(hps: float | int | None) -> str:
    if hps is None:
        return "-"
    value = float(hps)
    if value >= 1e12:
        return f"{value / 1e12:.2f} TH/s"
    if value >= 1e9:
        return f"{value / 1e9:.2f} GH/s"
    if value >= 1e6:
        return f"{value / 1e6:.2f} MH/s"
    if value >= 1e3:
        return f"{value / 1e3:.2f} kH/s"
    return f"{value:.2f} H/s"


def format_percent(progress: float | None) -> str:
    if progress is None:
        return "-"
    return f"{progress * 100.0:.2f}%"


def format_timestamp(timestamp: int | None) -> str:
    if not timestamp:
        return "-"
    from datetime import datetime, timezone

    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def shorten(value: str, prefix: int = 14, suffix: int = 14) -> str:
    if len(value) <= prefix + suffix + 3:
        return value
    return f"{value[:prefix]}...{value[-suffix:]}"


def format_token_units_18(value_wei: int | None) -> str:
    if value_wei is None:
        return "-"
    amount = Decimal(int(value_wei)) / Decimal(10**18)
    return f"{amount:.8f} CRX"


def load_reserve_snapshot() -> tuple[dict[str, Any] | None, str | None]:
    path = settings.reserve_status_path
    if not path.exists() or not path.is_file():
        return None, f"reserve snapshot file not found at {path}"

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        native_locked_sats = int(payload.get("native_locked_sats", 0))
        wrapped_supply_wei = int(payload.get("wrapped_supply_wei", 0))
    except (ValueError, TypeError, InvalidOperation, json.JSONDecodeError) as exc:
        return None, f"invalid reserve snapshot: {exc}"

    native_backing_wei = native_locked_sats * 10_000_000_000
    surplus_wei = native_backing_wei - wrapped_supply_wei
    if wrapped_supply_wei == 0:
        coverage_ratio = None
    else:
        coverage_ratio = (Decimal(native_backing_wei) / Decimal(wrapped_supply_wei)) * Decimal(100)

    snapshot = {
        "wrapped_contract_address": payload.get("wrapped_contract_address", ""),
        "reserve_wallet_address": payload.get("reserve_wallet_address", ""),
        "evm_chain_name": payload.get("evm_chain_name", "Ethereum Mainnet"),
        "evm_chain_id": payload.get("evm_chain_id", 1),
        "explorer_url": payload.get("explorer_url", ""),
        "operator_mode": payload.get("operator_mode", "manual-custodial"),
        "status": payload.get("status", "draft"),
        "notes": payload.get("notes", ""),
        "last_reconciled_at": payload.get("last_reconciled_at", ""),
        "pending_mint_count": int(payload.get("pending_mint_count", 0)),
        "pending_release_count": int(payload.get("pending_release_count", 0)),
        "processed_deposit_count": int(payload.get("processed_deposit_count", 0)),
        "processed_redemption_count": int(payload.get("processed_redemption_count", 0)),
        "native_locked_sats": native_locked_sats,
        "wrapped_supply_wei": wrapped_supply_wei,
        "native_locked_display": format_coins(native_locked_sats),
        "wrapped_supply_display": format_token_units_18(wrapped_supply_wei),
        "surplus_display": format_token_units_18(surplus_wei),
        "coverage_ratio_display": "∞" if coverage_ratio is None else f"{coverage_ratio:.4f}%",
        "is_solvent": native_backing_wei >= wrapped_supply_wei,
        "native_backing_wei": native_backing_wei,
        "surplus_wei": surplus_wei,
    }
    return snapshot, None


def common_context(request: Request, *, page: str, title: str, description: str) -> dict:
    artifacts = build_artifacts()
    return {
        "request": request,
        "site_name": settings.site_name,
        "tagline": settings.tagline,
        "organization": settings.organization,
        "marketing_domain": settings.marketing_domain,
        "repository_url": settings.repository_url,
        "base_url": settings.public_base_url,
        "page": page,
        "title": title,
        "description": description,
        "artifacts": artifacts,
        "featured_artifacts": [artifact for artifact in artifacts if artifact.get("highlight")],
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="home",
        title="CryptEX | 512-bit SHA3 network",
        description="CryptEX is a 512-bit SHA3 proof-of-work cryptocurrency with separate GUI and CLI stacks, secure chat, JSON-RPC, and operator-focused tooling.",
    )
    context["hero_stats"] = [
        {"label": "total supply", "value": "1,000,000,000"},
        {"label": "starting reward", "value": "2,500"},
        {"label": "halving interval", "value": "200,000 blocks"},
    ]
    context["pillars"] = [
        {
            "title": "Operator-grade node stack",
            "body": "Separate GUI and CLI binaries, JSON-RPC, structured logging, and secure system datadirs keep the chain manageable in real-world environments.",
        },
        {
            "title": "Full-width 512-bit proof-of-work",
            "body": "CryptEX consensus uses SHA3-512 and 512-bit chainwork math rather than truncating the model back down to Bitcoin-era defaults.",
        },
        {
            "title": "Security-aware delivery",
            "body": "The site is served by an app stack with host validation, HTTPS enforcement, strict security headers, rate limiting, and deploy-ready reverse-proxy config.",
        },
    ]
    return templates.TemplateResponse("home.html", context)


@app.get("/technology", response_class=HTMLResponse)
def technology(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "technology.html",
        common_context(
            request,
            page="technology",
            title="Technology | CryptEX",
            description="Consensus, networking, storage, wallet recovery, and operator features behind CryptEX.",
        ),
    )


@app.get("/downloads", response_class=HTMLResponse)
def downloads(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="downloads",
        title="Downloads | CryptEX",
        description="Current CryptEX builds for macOS, Windows, and Linux.",
    )
    grouped: dict[str, list[dict[str, str]]] = {"macOS": [], "Windows": [], "Linux": []}
    for artifact in context["artifacts"]:
        grouped.setdefault(artifact["platform"], []).append(artifact)
    context["grouped_artifacts"] = grouped
    return templates.TemplateResponse("downloads.html", context)


@app.get("/network", response_class=HTMLResponse)
def network_status(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="network",
        title="Network Status | CryptEX",
        description="Live CryptEX chain, peer, sync, checkpoint, and mining telemetry.",
    )
    chain, chain_error = safe_rpc_call("getblockchaininfo")
    network, network_error = safe_rpc_call("getnetworkinfo")
    mining, mining_error = safe_rpc_call("getmininginfo")
    checkpoint, checkpoint_error = safe_rpc_call("getcheckpointinfo")
    recent_blocks, recent_error = safe_rpc_call("getrecentblocks", [12])

    backend_error = chain_error or network_error or mining_error or checkpoint_error or recent_error
    chain = chain or {}
    network = network or {}
    mining = mining or {}
    checkpoint = checkpoint or {}
    recent_blocks = recent_blocks or []

    context["backend_online"] = backend_error is None
    context["backend_error"] = backend_error
    context["status_cards"] = [
        {"label": "Blocks", "value": chain.get("blocks", "-")},
        {"label": "Headers", "value": chain.get("headers", "-")},
        {"label": "Sync progress", "value": format_percent(chain.get("verificationprogress"))},
        {"label": "Best peer height", "value": chain.get("bestpeerheight", "-")},
        {"label": "Peers", "value": network.get("connections", "-")},
        {"label": "Validated peers", "value": network.get("validatedpeers", "-")},
        {"label": "Chain approval", "value": "Approved" if chain.get("chain_approved", True) else "Locked until approval"},
        {"label": "Estimated hashrate", "value": format_hashrate(mining.get("networkhashps"))},
    ]
    context["chain_details"] = [
        ("Best block hash", chain.get("bestblockhash", "-")),
        ("Difficulty", f"{float(chain.get('difficulty', 0.0)):.6f}" if chain else "-"),
        ("Blocks left", chain.get("blocksleft", "-")),
        ("Queued blocks", chain.get("queuedblocks", "-")),
        ("Inflight blocks", chain.get("inflightblocks", "-")),
        ("Checkpoint", f"height {checkpoint.get('height')}" if checkpoint.get("present") else "None"),
        ("Checkpoint mode", "Pinned" if checkpoint.get("pinned") else "Auto" if checkpoint.get("present") else "-"),
        ("External endpoint", network.get("externalip") or network.get("portmapping_external") or "-")
    ]
    context["recent_blocks"] = recent_blocks
    return templates.TemplateResponse("network.html", context)


@app.get("/explorer", response_class=HTMLResponse)
def explorer(request: Request, q: str = "") -> HTMLResponse:
    context = common_context(
        request,
        page="explorer",
        title="Explorer | CryptEX",
        description="Search CryptEX blocks, transactions, and addresses from the website.",
    )
    query = q.strip()
    search_result = None
    search_error = None
    recent_blocks, recent_error = safe_rpc_call("getrecentblocks", [8])
    if query:
        search_result, search_error = safe_rpc_call("searchchain", [query])
    context["query"] = query
    context["search_error"] = search_error
    context["recent_error"] = recent_error
    context["recent_blocks"] = recent_blocks or []
    context["search_type"] = None
    context["search_payload"] = None
    if search_result:
        context["search_type"] = search_result.get("type")
        context["search_payload"] = search_result.get("result")
        context["search_query"] = search_result.get("query", query)
    return templates.TemplateResponse("explorer.html", context)


@app.get("/reserve", response_class=HTMLResponse)
def reserve_page(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="reserve",
        title="Reserve Transparency | CryptEX",
        description="Bridge reserve tracking for wrapped CryptEX supply versus locked native CRX.",
    )
    snapshot, snapshot_error = load_reserve_snapshot()
    context["snapshot"] = snapshot
    context["snapshot_error"] = snapshot_error
    if snapshot:
        context["reserve_cards"] = [
            {"label": "Wrapped supply", "value": snapshot["wrapped_supply_display"]},
            {"label": "Native locked", "value": snapshot["native_locked_display"]},
            {"label": "Coverage ratio", "value": snapshot["coverage_ratio_display"]},
            {"label": "Status", "value": "Solvent" if snapshot["is_solvent"] else "Under-collateralized"},
        ]
        context["reserve_details"] = [
            ("Operator mode", snapshot["operator_mode"]),
            ("Reconciled at", snapshot["last_reconciled_at"] or "-"),
            ("EVM chain", f"{snapshot['evm_chain_name']} (id {snapshot['evm_chain_id']})"),
            ("Wrapped contract", snapshot["wrapped_contract_address"] or "-"),
            ("Reserve wallet", snapshot["reserve_wallet_address"] or "-"),
            ("Pending mints", snapshot["pending_mint_count"]),
            ("Pending releases", snapshot["pending_release_count"]),
            ("Processed deposits", snapshot["processed_deposit_count"]),
            ("Processed redemptions", snapshot["processed_redemption_count"]),
            ("Explorer", snapshot["explorer_url"] or "-"),
        ]
    else:
        context["reserve_cards"] = []
        context["reserve_details"] = []
    return templates.TemplateResponse("reserve.html", context)


@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="security",
        title="Security | CryptEX",
        description="CryptEX web delivery, domain, and infrastructure security posture.",
    )
    context["security_contact"] = settings.security_contact
    return templates.TemplateResponse("security.html", context)


@app.get("/roadmap", response_class=HTMLResponse)
def roadmap(request: Request) -> HTMLResponse:
    context = common_context(
        request,
        page="roadmap",
        title="Roadmap | CryptEX",
        description="Near-term product and infrastructure roadmap for CryptEX.",
    )
    context["roadmap_items"] = [
        {
            "phase": "Release infrastructure",
            "items": [
                "Automatic release manifests and checksums",
                "Production deployment for the website on a real domain",
                "Repeatable packaging for macOS, Linux, and Windows",
            ],
        },
        {
            "phase": "Network maturity",
            "items": [
                "Explorer-ready indexing and public network telemetry",
                "UPnP and NAT-PMP for friendlier home-node onboarding",
                "Broader peer observability and sync diagnostics",
            ],
        },
        {
            "phase": "User experience",
            "items": [
                "Richer wallet history, labels, and address book support",
                "GUI transaction detail views and operator dashboards",
                "Expanded miner management and remote monitoring",
            ],
        },
    ]
    return templates.TemplateResponse("roadmap.html", context)


@app.get("/api/health")
def health() -> JSONResponse:
    backend, error = safe_rpc_call("getblockchaininfo")
    return JSONResponse({
        "status": "ok",
        "site": settings.site_name,
        "backend_available": error is None,
        "backend_error": error,
        "chain": backend.get("chain") if backend else None,
        "blocks": backend.get("blocks") if backend else None,
    })


@app.get("/api/downloads")
def downloads_api() -> JSONResponse:
    return JSONResponse({"artifacts": build_artifacts()})


@app.get("/api/security")
def security_api() -> JSONResponse:
    return JSONResponse(
        {
            "canonical_host": settings.canonical_host,
            "force_https": settings.force_https,
            "rate_limit_per_minute": settings.rate_limit_per_minute,
            "security_contact": settings.security_contact,
        }
    )


@app.get("/api/reserve")
def reserve_api() -> JSONResponse:
    snapshot, error = load_reserve_snapshot()
    return JSONResponse({"snapshot": snapshot, "error": error})


@app.get("/api/network")
def network_api() -> JSONResponse:
    chain, chain_error = safe_rpc_call("getblockchaininfo")
    network, network_error = safe_rpc_call("getnetworkinfo")
    mining, mining_error = safe_rpc_call("getmininginfo")
    checkpoint, checkpoint_error = safe_rpc_call("getcheckpointinfo")
    recent_blocks, recent_error = safe_rpc_call("getrecentblocks", [12])
    return JSONResponse(
        {
            "chain": chain,
            "network": network,
            "mining": mining,
            "checkpoint": checkpoint,
            "recent_blocks": recent_blocks,
            "error": chain_error or network_error or mining_error or checkpoint_error or recent_error,
        }
    )


@app.get("/api/explorer/search")
def explorer_api(q: str) -> JSONResponse:
    result, error = safe_rpc_call("searchchain", [q.strip()])
    return JSONResponse({"query": q.strip(), "result": result, "error": error})


@app.get("/artifacts/{filename}")
def artifact_download(filename: str):
    for artifact in ARTIFACTS:
        if artifact["filename"] != filename:
            continue
        path = settings.dist_dir / filename
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="Artifact not found")
        media_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        response = FileResponse(path, media_type=media_type, filename=path.name)
        response.headers["Content-Disposition"] = f'attachment; filename="{path.name}"'
        return response
    raise HTTPException(status_code=404, detail="Artifact not found")


@app.get("/robots.txt")
def robots() -> PlainTextResponse:
    return PlainTextResponse(f"User-agent: *\nAllow: /\nSitemap: {settings.public_base_url}/sitemap.xml\n")


@app.get("/.well-known/security.txt")
def security_txt() -> PlainTextResponse:
    body = (
        f"Contact: mailto:{settings.security_contact}\n"
        f"Canonical: {settings.public_base_url}/.well-known/security.txt\n"
        f"Policy: {settings.public_base_url}/security\n"
        "Preferred-Languages: en\n"
    )
    return PlainTextResponse(body)


@app.get("/sitemap.xml")
def sitemap() -> Response:
    pages = ["/", "/technology", "/downloads", "/network", "/explorer", "/reserve", "/security", "/roadmap"]
    xml = [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
    ]
    for page in pages:
        xml.append("  <url>")
        xml.append(f"    <loc>{settings.public_base_url}{page}</loc>")
        xml.append("  </url>")
    xml.append("</urlset>")
    return Response("\n".join(xml), media_type="application/xml")
