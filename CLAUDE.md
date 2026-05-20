# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

PS Panel is a lightweight server management web panel targeting Ubuntu 24.04 LTS. It manages a FrankenPHP + PHP 8.3 + PostgreSQL 16 + Redis + Node.js stack via a Node.js backend and a single-file HTML/CSS/JS frontend.

## Running the Panel

```bash
# Direct (development)
node server.js

# Via PM2 (production, as installed by install.sh)
pm2 start server.js --name ps-panel
pm2 logs ps-panel
pm2 restart ps-panel
```

Default port: **8765**. Default password: `admin123` (override with `PANEL_PASS` env var).

Environment variables:
- `PANEL_PORT` — listening port (default 8765)
- `PANEL_PASS` — admin password (default `admin123`)
- `PANEL_SECRET` — JWT signing secret (auto-generated if unset)

## Architecture

### Two-file structure

- **`server.js`** — Express REST API + WebSocket server. Runs on the host Linux machine and calls `systemctl`, `psql`, Redis, and `systeminformation` directly.
- **`ps-panel-v2.html`** — The entire frontend: all HTML, CSS (inline `<style>`), and JS (inline `<script>`). This file must be copied to `public/index.html` for the server to serve it (see `install.sh`).

The server serves static files from `./public/`. The HTML file is not served directly from the repo root — `install.sh` downloads it to `/opt/ps-panel/public/index.html`.

### Auth flow

JWT-based. Login POSTs to `/api/login` → receives a token → stored in `localStorage` as `psp_tok` → passed as `Authorization: Bearer <token>` on all subsequent API calls. Token expiry is 8 hours.

### Backend API surface (`server.js`)

| Route | What it does |
|---|---|
| `POST /api/login` | bcrypt password check → JWT |
| `GET /api/metrics` | CPU, RAM, disk, network, top 5 processes via `systeminformation` |
| `GET /api/services` | `systemctl is-active` for each managed service |
| `POST /api/services/:name/:action` | `systemctl start/stop/restart` |
| `GET /api/redis` | Connects to `127.0.0.1:6379`, parses `INFO` output |
| `GET /api/postgres` | Connects as `postgres` user, runs `pg_stat_activity` / `pg_database_size` queries |
| `GET /api/phpfpm` | Calls php-fpm status socket via `cgi-fcgi`; falls back to `systemctl status` |
| `GET/POST/DELETE /api/vhosts` | Reads/writes `.conf` files in `/etc/frankenphp/sites/` |
| `GET /api/databases` | `sudo -u postgres psql -c "\l"` |
| `POST /api/databases` | `sudo -u postgres createdb <name>` |
| `POST /api/deploy` | `cd <path> && git pull origin <branch>` |
| WebSocket `/` | Pushes CPU/RAM/network stats every 2 seconds |

### Frontend structure (`ps-panel-v2.html`)

Single-page app with no framework or build step. Navigation hides/shows `<div class="page">` sections. Each page loads data from the API on entry via `go(name)`. The dashboard auto-refreshes metrics every 5 seconds and services every 10 seconds via `setInterval`.

CSS uses short utility class names (`mc` = metric card, `sr` = status row, `ir` = info row, `ni` = nav item, etc.) defined in the `<style>` block.

## SSL / Let's Encrypt

FrankenPHP (Caddy) handles Let's Encrypt automatically. The Caddyfile at `/etc/frankenphp/Caddyfile` uses `http://:80` for the default site (no cert). Virtual hosts created with SSL enabled generate a config without the `http://` prefix (e.g., `example.com { ... }`), which triggers Caddy's auto-HTTPS. Sites without SSL use `http://example.com { ... }` to stay HTTP-only.

## Installation

```bash
# On target Ubuntu 24.04 server (as root)
bash install.sh
```

Update `GITHUB_RAW` in `install.sh` to point to the actual raw GitHub URL before distributing.
