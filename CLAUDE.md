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

The password hash and JWT secret are persisted in `/root/.pspanel_auth` (mode 600, override with `PANEL_AUTH_FILE`). The file also holds the admin `user` (lowercase, `^[a-z0-9._-]{3,32}$`; installs from before usernames get `admin`). Login needs username + password (`Username atau password salah` either way; bcrypt always runs). Once that file exists it is the source of truth; `PANEL_PASS` is only the initial password. `install.sh` asks the admin for the username/password at the start (read from `/dev/tty`, or `PS_PANEL_USER`/`PS_PANEL_PASS`; no terminal and no variables → `admin` + random password) and writes them with `node server.js --init-credentials` (password passed via `PANEL_INIT_PASS` env, never argv); a re-install keeps an existing auth file. Settings → *Username Panel* changes the name (`POST /api/username`, needs the password, revokes tokens); forms that re-check the password use `POST /api/verify-password`, not `/api/login`. CLI: `--set-username <name>`; `--reset-password` also prints the username. Changing the password (Settings page → *Ubah Password*) bumps a token version so old tokens stop working. Forgotten password: `node server.js --reset-password [newpass]` on the server, then `pm2 restart ps-panel`.

### Backend API surface (`server.js`)

| Route | What it does |
|---|---|
| `POST /api/login` | username + bcrypt password check → JWT |
| `POST /api/password` | change admin password (old + new); revokes all existing tokens |
| `GET /api/account`, `POST /api/username`, `POST /api/verify-password` | current username, change username (password + new name; revokes tokens), re-check the password for the current session |
| `GET /api/security/php`, `POST /api/security/switch-to-fpm`, `GET/POST /api/frankenphp/upgrade*` | PHP2Shell status, one-click switch to PHP-FPM, safe FrankenPHP upgrade job |
| `GET /api/phpworker`, `POST /api/phpworker/restart`, `GET /api/autotune` | PHP Worker page data (status, automatic capacity, history), confirmed restart of services awaiting a restart, PostgreSQL memory card |
| `GET /api/settings`, `GET /api/settings/effective`, `POST /api/settings/update` | php.ini values (never worker counts); `effective` probes the running web processes |
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

## Auto-tune and the PHP Worker page

Worker capacity is **automatic only**: there is no input anywhere for a worker count, and no endpoint accepts one (`POST /api/settings/update` rejects `frankenphp`; the old `POST /api/autotune/{apply,revert,boot}` are gone). The engine lives in `server.js` (`computePlan` → `applyPlan` → `autotuneTick`; keep it all in `server.js` because the self-update only downloads the files in `UPDATE_FILES`).

- **Pure calculations** (`computeFpmPool`, `computePgProfile`, `computePlan`): `pm.max_children = floor((RAM − PostgreSQL − Redis − 1 GB) / avg RSS per worker)`, per-worker estimate never below 50 MB (initial 70 MB, measured from `ps` when ≥5 workers run), at least 8 and at most 8 × cores; `request_terminate_timeout = max_execution_time + 10 s`. FrankenPHP's embedded PHP never exceeds 2 × cores; when every site uses PHP-FPM, FrankenPHP only gets 2 threads.
- **Files**: `/etc/php/<ver>/fpm/pool.d/zz-ps-panel.conf` (pool `[www]`, loaded last so it wins; manual pool files that only set managed keys are adopted = renamed to `*.diambil-alih-panel.<ts>`), `num_threads` in the Caddyfile's single global `{ frankenphp }` block, `conf.d/90-ps-panel-autotune.conf` for PostgreSQL. Validation: `php-fpm -t` / `postgres -C`; rollback on failure. `php-fpm -tt` shows the merged effective pool.
- **When**: boot (`ps-panel-autotune.service`, installed and enabled by the panel itself on every start, runs `node server.js --autotune` before PostgreSQL/PHP-FPM/FrankenPHP), core/RAM change, a site's runtime change, `max_execution_time` change, and every 10 min (hysteresis: max_children drift < max(3, 10%) is ignored). State is in `/root/.pspanel_autotune.json`, history is parsed from `/var/log/ps-panel-autotune.log` (`CHANGE target=… key=… old=… new=… reason="…"`).
- **Restart policy**: PHP-FPM is only RELOADED. Changes that need a restart (FrankenPHP threads, PostgreSQL memory) are written but the panel never restarts a serving service by itself: the page shows "waiting for restart" with a password-confirmed button (`POST /api/phpworker/restart`). Under high load (loadavg/core > 0.4) writes are deferred. Safety net: > 3 restarts of a service within a minute after a change → previous value restored, same values blocked for 24 h, alert recorded (`notify()`).
- **API**: `GET /api/phpworker` (everything the page shows), `GET /api/autotune` (PostgreSQL memory card), `POST /api/phpworker/restart`. Test overrides: `PANEL_AUTOTUNE_LOG`, `PANEL_AUTOTUNE_STATE`, `PANEL_AUTOTUNE_UNIT`, `PANEL_AUTOTUNE_GUARD_MS`, `PANEL_AUTOTUNE_INTERVAL_MS`, `PANEL_AUTOTUNE_FORCE_LOW_LOAD`, `PANEL_REDIS_BIN`. Manual: `node server.js --autotune [--dry-run [--cores=N --ram=MB]]`.

## PHP security (PHP2Shell) and the FrankenPHP upgrade

`phpSecurityStatus()` judges every runtime that serves web requests. A runtime is safe when its upstream version is at/above `PHP_ADVISORY.fixed[branch]` (8.5.12, 8.4.27, 8.3.36, 8.2.35 — update this table for future advisories) **or** its package changelog (`/usr/share/doc/php<ver>-{fpm,common,cli}/changelog.Debian.gz`) lists all advisory CVEs. The changelog check is essential: Ubuntu backports fixes without changing the upstream number. A vulnerable runtime that is in use is `critical` (Dashboard banner, `notify()` alert); the php.net "latest release" lookup is optional and cached, and failures are ignored. `POST /api/security/switch-to-fpm` moves every `php_server` site to a safe PHP-FPM (`convertRuntime`: backup → validate → rollback). `securityTick()` (runs with the 10-minute tick) also updates vulnerable PHP-FPM packages itself — deferred under high load but at most 24 h — and, when PHP packages change (by the panel or unattended-upgrades), reloads PHP-FPM and restarts systemd units that run `queue:work`. `ensureUnattendedSury()` writes `/etc/apt/apt.conf.d/52ps-panel-php-security` so unattended-upgrades may use the Sury origin.

FrankenPHP upgrade (`/api/frankenphp/upgrade*`, job state in memory): download to a temp dir → ELF check → `version` + `php-cli` → start on TEMPORARY ports with `XDG_*` pointed at a temp dir and hammer it with parallel cURL/OpenSSL HTTPS from several PHP threads (this reproduces the v1.3.2 crash: `socket hang up`) → only then back up the live binary, swap atomically, restart and watch `NRestarts` for 60 s, restoring the backup if it rises by more than 3. `AUTO.fpUpgradePending` lets `recoverFrankenUpgrade()` finish that watch if the panel itself restarted mid-way. Test overrides: `PANEL_FRANKENPHP_URL_BASE`, `PANEL_FRANKENPHP_ASSETS`, `PANEL_UPGRADE_WATCH_MS`, `PANEL_PHPNET_URL`, `PANEL_DOC_DIR`, `PANEL_APT_CONF_D`, `PANEL_APT_LISTS`, `PANEL_SYSTEMD_DIR`, `PANEL_SECURITY_APT=0`. Verified facts: FrankenPHP v1.3.2 embeds PHP 8.3.14 and crashes under that stress test; v1.13.2 embeds PHP 8.5.12 and passes on a modern CPU.

## Laravel (deploy, queue worker, scheduler)

A Laravel site is a vhost whose docroot is `<root>/public` with `<root>/artisan` present (`laravelRootFor`). `runDeploySteps` runs `laravelPreflight` before and after the deploy: `checkLaravelEnv` (APP_ENV ≠ production, APP_DEBUG=true, INERTIA_DEVTOOLS_ENABLED not false when Inertia is installed) and `storageReport` (`du -k --max-depth=1`, NOT `-s`, which GNU du rejects together with `--max-depth`; threshold `PANEL_STORAGE_WARN_MB`, default 1024; non-empty `storage/inertia-devtools`). These are warnings (`warn: true` steps, `warnings` count in deploy-history.json), never failures. The reload follows the site runtime: `systemctl reload php<ver>-fpm` for FPM vhosts, FrankenPHP reload otherwise.
Queue worker: unit `ps-queue-<domain>.service` (User=www-data, `artisan queue:work --sleep=3 --tries=3 --max-time=3600`, no connection argument so it follows `QUEUE_CONNECTION`), restarted when the site's `.env` is saved and after a PHP package change. Scheduler: `/etc/cron.d/ps-scheduler-<domain with dots → dashes>` (cron ignores file names containing dots), created automatically by `ensureSchedulers()` unless the user opted out (`AUTO.laravelOptOut`). Existing hand-made units/cron files are never skipped silently: enabling needs `adopt: true` (UI confirms), then the old file is renamed `*.diambil-alih-panel.<ts>` and, for a unit, disabled. Routes: `/api/laravel*`; enable/disable need the panel password. Test overrides: `PANEL_SYSTEMD_DIR`, `PANEL_CRON_DIR`, `PANEL_PHP_BIN`.

## Redis settings

`GET /api/redis` also returns `INFO keyspace`, the live `maxmemory`/`maxmemory-policy`/`appendonly`/`appendfsync` and the recommended values (1gb, volatile-lru, yes, everysec). `POST /api/redis/config` (password) validates, backs up the file named by `INFO config_file`, applies with `CONFIG SET` (rolled back on error) then `CONFIG REWRITE` (the backup is restored if that fails). maxmemory must be ≥16mb and ≤ RAM, or 0.

## Health checks and Telegram

`healthTick` runs inside the panel process every `PANEL_HEALTH_INTERVAL_MS` (60 s): `NRestarts` of frankenphp and every `php<ver>-fpm` over a 5-minute window (threshold from the notify file, default 3), kernel log lines matching `segfault|invalid opcode` (`journalctl -k`, falls back to `dmesg`), and `server reached pm.max_children` in each FPM unit's journal. The first tick only records a baseline so old events do not alert after a panel restart; the same alert key is rate-limited by `PANEL_ALERT_COOLDOWN_MS` (30 min). Alerts go through `notify()` (Alerts list + autotune log) which also calls `sendTelegram()`. Credentials live in `/root/.pspanel_notify` (mode 600, `PANEL_NOTIFY_FILE`); the API never returns the token. `GET /api/health` feeds the Dashboard card. Test overrides: `PANEL_TELEGRAM_API`, `PANEL_KERNEL_LOG_FILE`, `PANEL_FPM_LOG_FILE`, `PANEL_HEALTH_WINDOW_MS`.

Small self-heals: every Caddyfile write is followed by `frankenphp fmt --overwrite`; the frankenphp unit gets a drop-in with `XDG_CONFIG_HOME=/var/lib/caddy/config` (owned by www-data; `XDG_DATA_HOME` is deliberately untouched); `package.json`'s version is synced with `version.json` at startup and after a self-update.

## SSL / Let's Encrypt

FrankenPHP (Caddy) handles Let's Encrypt automatically. The Caddyfile at `/etc/frankenphp/Caddyfile` uses `http://:80` for the default site (no cert). Virtual hosts created with SSL enabled generate a config without the `http://` prefix (e.g., `example.com { ... }`), which triggers Caddy's auto-HTTPS. Sites without SSL use `http://example.com { ... }` to stay HTTP-only.

## Installation

```bash
# On target Ubuntu 24.04 server (as root)
bash install.sh
```

Update `GITHUB_RAW` in `install.sh` to point to the actual raw GitHub URL before distributing.
