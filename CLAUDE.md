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

The password hash and JWT secret are persisted in `/root/.pspanel_auth` (mode 600, override with `PANEL_AUTH_FILE`). Once that file exists it is the source of truth; `PANEL_PASS` is only the initial password. Changing the password (Settings page → *Ubah Password*) bumps a token version so old tokens stop working. Forgotten password: `node server.js --reset-password [newpass]` on the server, then `pm2 restart ps-panel`.

### Backend API surface (`server.js`)

| Route | What it does |
|---|---|
| `POST /api/login` | bcrypt password check → JWT |
| `POST /api/password` | change admin password (old + new); revokes all existing tokens |
| `GET /api/autotune`, `POST /api/autotune/{apply,revert,boot}` | auto-tune FrankenPHP `num_threads` + PostgreSQL memory from cores/RAM (writes need the panel password) |
| `GET /api/settings`, `GET /api/settings/effective`, `POST /api/settings/update` | PHP ini + FrankenPHP threads; `effective` probes the running web process |
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

## PHP runtimes (FrankenPHP vs PHP-FPM)

FrankenPHP is always the web server. Each site (and the `http://:80` default site) runs PHP through ONE of two runtimes: `php_server` (FrankenPHP's embedded PHP) or `php_fastcgi unix//run/php/php<ver>-fpm.sock` + `file_server` (PHP-FPM). The runtime is read from the site block by `parseRuntime()`; PHP-FPM versions are discovered from `/etc/php/<ver>` + `/usr/sbin/php-fpm<ver>` (`fpmRuntimes()`, never hardcode a version). **PHP 8.5 is the target** (`PREFERRED_PHP`, env `PANEL_PHP_VERSION`; falls back to the newest installed). Why FPM is the default: the embedded PHP is tied to the FrankenPHP binary (v1.3.2 = PHP 8.3.14, vulnerable to PHP2Shell and not updated by apt) and v1.3.2 segfaults under parallel outbound HTTPS. `POST /api/runtime/convert` switches a site: backup (`*.conf.bak.<ts>`, not matched by `import sites/*.conf`) → write → `frankenphp validate --adapter caddyfile` → restore on failure → reload. FPM is only ever reloaded, never restarted, by the panel automatically. Test overrides: `PANEL_PHP_ETC`, `PANEL_PHP_SBIN`, `PANEL_FPM_RUN`, `PANEL_FRANKENPHP_BIN`.

`install.sh` installs `php${PS_PHP_VER}` (default 8.5) CLI + FPM from the Ondrej PPA, filters extension packages with `apt-cache` (some, e.g. opcache in 8.5, are not separate packages) and writes a default Caddyfile that uses PHP-FPM.

## PHP configuration (Settings page)

FrankenPHP is a static binary with its own embedded PHP. It does **not** read the apt PHP's `/etc/php/8.3/*/php.ini`. Verified on v1.3.2: `/etc/frankenphp/php.ini` is only loaded when the service has `PHPRC=/etc/frankenphp` (`PHP_INI_SCAN_DIR` also works), and the Caddyfile `php_ini` directive parses but has **no effect**. So the panel writes `/etc/frankenphp/php.ini`, installs a systemd drop-in (`/etc/systemd/system/frankenphp.service.d/10-ps-panel-php.conf`, `Environment=PHPRC=/etc/frankenphp`) when the unit lacks it, restarts FrankenPHP, then verifies the EFFECTIVE values through the running web process (`probeEffectivePhp`: a throw-away `psprobe-<random>.php` in a served docroot, fetched over localhost and deleted). A mismatch is shown as a warning in the UI. The same keys are mirrored to every PHP-FPM version in use (`/etc/php/<ver>/fpm/conf.d/99-ps-panel.ini`, validated with `php-fpm -t`, pool RELOADED). Saving restarts FrankenPHP only when a site still uses its embedded PHP, so avoid doing it during peak/exam hours. `frankenphp php-cli -i` does not work on v1.3.2; use the probe instead.

## Auto-tune

`computeTuneProfile(cores, ramMB)` in `server.js` is a pure function that recommends `num_threads` and PostgreSQL memory settings. PostgreSQL values go to `/etc/postgresql/<ver>/main/conf.d/90-ps-panel-autotune.conf` (validated with `postgres -C`, rolled back on failure); `num_threads` is merged into the Caddyfile's single global `{ frankenphp }` block (Caddy rejects a second global block). The optional boot unit `ps-panel-autotune.service` runs `node server.js --autotune` before PostgreSQL/FrankenPHP start. Keep all panel code in `server.js`: the self-update only downloads the files listed in `UPDATE_FILES`, so a new `require`d file would crash older installs after an update.

## SSL / Let's Encrypt

FrankenPHP (Caddy) handles Let's Encrypt automatically. The Caddyfile at `/etc/frankenphp/Caddyfile` uses `http://:80` for the default site (no cert). Virtual hosts created with SSL enabled generate a config without the `http://` prefix (e.g., `example.com { ... }`), which triggers Caddy's auto-HTTPS. Sites without SSL use `http://example.com { ... }` to stay HTTP-only.

## Installation

```bash
# On target Ubuntu 24.04 server (as root)
bash install.sh
```

Update `GITHUB_RAW` in `install.sh` to point to the actual raw GitHub URL before distributing.
