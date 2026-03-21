from __future__ import annotations

import hashlib
import mimetypes
from pathlib import Path

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
    return JSONResponse({"status": "ok", "site": settings.site_name})


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
    pages = ["/", "/technology", "/downloads", "/security", "/roadmap"]
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
