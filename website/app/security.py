from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from fastapi import Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        csp = "; ".join(
            [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self' data:",
                "connect-src 'self'",
                "object-src 'none'",
                "base-uri 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
            ]
        )
        response.headers["Content-Security-Policy"] = csp
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "credentialless"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

        path = request.url.path
        if path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path.startswith("/artifacts/"):
            response.headers["Cache-Control"] = "public, max-age=3600"
        elif path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif path in {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}:
            response.headers["Cache-Control"] = "public, max-age=300"
        else:
            response.headers["Cache-Control"] = "no-store"
        return response


class HttpsEnforcementMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, force_https: bool = False):
        super().__init__(app)
        self.force_https = force_https

    async def dispatch(self, request: Request, call_next: Callable):
        if not self.force_https:
            return await call_next(request)
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if request.url.scheme != "https" and forwarded_proto.lower() != "https":
            secure_url = request.url.replace(scheme="https")
            return RedirectResponse(str(secure_url), status_code=308)
        return await call_next(request)


class CanonicalHostMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, canonical_host: str, enabled: bool = False):
        super().__init__(app)
        self.canonical_host = canonical_host
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next: Callable):
        if not self.enabled or request.method not in {"GET", "HEAD"}:
            return await call_next(request)
        host = request.headers.get("x-forwarded-host", request.headers.get("host", "")).split(":", 1)[0].strip().lower()
        if not host or host == self.canonical_host.lower():
            return await call_next(request)
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme) or request.url.scheme
        redirect_url = request.url.replace(scheme=scheme, netloc=self.canonical_host)
        return RedirectResponse(str(redirect_url), status_code=308)


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int = 240):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable):
        client_ip = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip() or (request.client.host if request.client else "unknown")
        now = time.monotonic()
        window = self._hits[client_ip]
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= self.requests_per_minute:
            return PlainTextResponse("Too many requests", status_code=429)
        window.append(now)
        return await call_next(request)
