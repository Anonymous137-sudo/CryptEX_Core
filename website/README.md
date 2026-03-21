# CryptEX Website

This is the production-style website app for CryptEX. It replaces the old single `index.html`
with a FastAPI + Jinja stack so the site can serve dynamic release metadata, domain-aware
security headers, and deployment-ready endpoints.

## Stack
- FastAPI
- Jinja2 server-rendered templates
- Static CSS/JS assets
- Security middleware for host validation, canonical redirects, HTTPS enforcement, headers, and rate limiting

## Local run
```bash
cd /Users/gitanshchakravarty/Desktop/CryptEX/website
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
./run.sh
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080)

When the runner starts, it now prints:
- public site URL
- detected public IP
- detected local IP
- effective host allowlist

That makes it easier to debug LAN and public reachability.

## Production environment
Use environment variables rather than editing source:

```bash
export CRYPTEX_SITE_URL="https://cryptexorg.duckdns.org"
export CRYPTEX_ALLOWED_HOSTS="cryptexorg.duckdns.org,localhost,127.0.0.1"
export CRYPTEX_FORCE_HTTPS="true"
export CRYPTEX_CANONICAL_REDIRECT="true"
export CRYPTEX_SECURITY_CONTACT="security@cryptexorg.duckdns.org"
export CRYPTEX_REPOSITORY_URL="https://github.com/Anonymous137-sudo/CryptEX_Core"
```

## Security features
- Trusted host allowlist
- Optional canonical host redirect
- Optional HTTPS enforcement
- Strict CSP
- HSTS on HTTPS
- `security.txt`, `robots.txt`, and `sitemap.xml`
- Basic in-memory request rate limiting
- Download delivery through the app with explicit attachment responses

## Deployment
- `deploy/Caddyfile.example` contains a production reverse-proxy example.
- `deploy/Caddyfile.cryptexorg` is a concrete Caddy config for `cryptexorg.duckdns.org`.
- `deploy/nginx-cryptexorg.conf` is a concrete Nginx config for the same hostname.
- `deploy/start-cloudflared-tunnel.sh` starts a temporary HTTPS tunnel if you want external access without depending on router reachability.
- Run the app behind Caddy or another TLS terminator.
- Keep `CRYPTEX_ALLOWED_HOSTS` tight to the public hosts you actually serve.
- Put the final public domain in `CRYPTEX_SITE_URL` so canonical URLs and metadata are correct.

## Reachability notes

If `http://cryptexorg.duckdns.org:8080` fails from inside your home Wi-Fi while `http://127.0.0.1:8080` works, the most common cause is router NAT loopback/hairpin behavior rather than the app itself.

Useful checks:

- local machine: `http://127.0.0.1:8080`
- local LAN: `http://<your-lan-ip>:8080`
- public hostname: `http://cryptexorg.duckdns.org:8080`

For a cleaner public setup, prefer HTTPS through Caddy on `443` or use the Cloudflared tunnel helper.

Cloudflared quick tunnel:

```bash
cd /Users/gitanshchakravarty/Desktop/CryptEX/website
./deploy/start-cloudflared-tunnel.sh
```

The helper sends `Host: cryptexorg.duckdns.org` to the origin so the site still works with host validation enabled.
