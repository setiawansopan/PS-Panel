#!/usr/bin/env bash
# ============================================================
#  PS Panel Installer  v2.1
#  Stack: FrankenPHP + PHP 8.3 + PostgreSQL 16 + Redis + Node.js 20
#  Target: Ubuntu 24.04 LTS
#  Usage : curl -fsSL https://raw.githubusercontent.com/setiawansopan/PS-Panel/main/install.sh | sudo bash
# ============================================================

# --- strict mode, but errors are caught via our own trap ---
set -uo pipefail

# ── Config ──────────────────────────────────────────────────
PANEL_DIR="/opt/ps-panel"
PANEL_PORT=8765
NODE_VERSION=20
GITHUB_RAW="https://raw.githubusercontent.com/setiawansopan/PS-Panel/main"
LOG_FILE="/var/log/pspanel-install.log"
CREDS_FILE="/root/.pspanel_credentials"
MIN_DISK_GB=2
WARN_DISK_GB=5
MIN_RAM_MB=512
MAX_RETRIES=3
RETRY_DELAY=5
FRANKENPHP_FALLBACK="v1.3.2"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'
BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; RESET='\033[0m'
BG_RED='\033[41m'; BG_GREEN='\033[42m'

# ── State ────────────────────────────────────────────────────
SPINNER_PID=""
STEP_START_TIME=0
CURRENT_STEP_MSG=""
TOTAL_STEPS=8
CURRENT_STEP=0
INSTALL_ERRORS=()

# ── Step definitions: name|estimated_time ────────────────────
declare -a STEPS=(
  "System Update|~1-2 min"
  "PHP 8.3|~2-3 min"
  "FrankenPHP|~1-2 min"
  "PostgreSQL 16|~1-2 min"
  "Redis|~30 sec"
  "Node.js v${NODE_VERSION}|~1-2 min"
  "PS Panel|~1-2 min"
  "Firewall|~10 sec"
)

# ════════════════════════════════════════════════════════════
#  LOGGING
# ════════════════════════════════════════════════════════════

# Ensure log file exists and is writable
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
: > "$LOG_FILE" 2>/dev/null || true

log_raw() {
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[${ts}] $*" >> "$LOG_FILE" 2>/dev/null || true
}

# Run a command, tee its output to log, return its exit code
run_logged() {
  log_raw "CMD: $*"
  local rc=0
  "$@" >> "$LOG_FILE" 2>&1 || rc=$?
  log_raw "EXIT: $rc"
  return $rc
}

# ════════════════════════════════════════════════════════════
#  SPINNER + TIMER
# ════════════════════════════════════════════════════════════

SPINNER_CHARS=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)

_spinner_loop() {
  local msg="$1"
  local start=$2
  local i=0
  # Hide cursor
  tput civis 2>/dev/null || true
  while true; do
    local elapsed=$(( $(date +%s) - start ))
    local mins=$(( elapsed / 60 ))
    local secs=$(( elapsed % 60 ))
    local timer
    printf -v timer "%02d:%02d" "$mins" "$secs"
    local char="${SPINNER_CHARS[$((i % ${#SPINNER_CHARS[@]}))]}"
    printf "\r  ${CYAN}%s${RESET}  %s  ${DIM}[%s]${RESET}   " \
      "$char" "$msg" "$timer" >&2
    (( i++ )) || true
    sleep 0.1
  done
}

spinner_start() {
  CURRENT_STEP_MSG="$1"
  STEP_START_TIME=$(date +%s)
  log_raw "STEP START: $1"
  _spinner_loop "$1" "$STEP_START_TIME" &
  SPINNER_PID=$!
  disown "$SPINNER_PID" 2>/dev/null || true
}

spinner_stop() {
  local status="${1:-ok}"   # ok | skip | fail
  if [[ -n "$SPINNER_PID" ]]; then
    kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
  fi
  tput cnorm 2>/dev/null || true

  local elapsed=$(( $(date +%s) - STEP_START_TIME ))
  local mins=$(( elapsed / 60 ))
  local secs=$(( elapsed % 60 ))
  local timer
  printf -v timer "%02d:%02d" "$mins" "$secs"

  case "$status" in
    ok)
      printf "\r  ${GREEN}✓${RESET}  %-52s ${DIM}[%s]${RESET}\n" \
        "$CURRENT_STEP_MSG" "$timer" >&2
      log_raw "STEP OK: $CURRENT_STEP_MSG (${timer})"
      ;;
    skip)
      printf "\r  ${BLUE}↷${RESET}  %-52s ${DIM}[SKIP]${RESET}\n" \
        "$CURRENT_STEP_MSG" >&2
      log_raw "STEP SKIP: $CURRENT_STEP_MSG"
      ;;
    fail)
      printf "\r  ${RED}✗${RESET}  %-52s ${DIM}[FAIL]${RESET}\n" \
        "$CURRENT_STEP_MSG" >&2
      log_raw "STEP FAIL: $CURRENT_STEP_MSG"
      ;;
  esac
}

# ════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ════════════════════════════════════════════════════════════

draw_progress() {
  local step=$1
  local total=$2
  local bar_width=30
  local filled=$(( step * bar_width / total ))
  local empty=$(( bar_width - filled ))
  local pct=$(( step * 100 / total ))
  local bar=""
  local i
  for (( i=0; i<filled; i++ )); do bar+="█"; done
  for (( i=0; i<empty;  i++ )); do bar+="░"; done
  printf "\n  ${CYAN}Progress: [%s] %3d%% (%d/%d)${RESET}\n\n" \
    "$bar" "$pct" "$step" "$total" >&2
}

# ════════════════════════════════════════════════════════════
#  SECTION HEADER
# ════════════════════════════════════════════════════════════

section() {
  local name="$1"
  local est="${2:-}"
  (( CURRENT_STEP++ )) || true
  draw_progress "$CURRENT_STEP" "$TOTAL_STEPS"
  if [[ -n "$est" ]]; then
    echo -e "  ${BOLD}${CYAN}── ${name} ──${RESET}  ${DIM}(${est})${RESET}" >&2
  else
    echo -e "  ${BOLD}${CYAN}── ${name} ──${RESET}" >&2
  fi
  log_raw "=== SECTION: $name ==="
}

# ════════════════════════════════════════════════════════════
#  PRINT HELPERS
# ════════════════════════════════════════════════════════════

log()   { echo -e "  ${GREEN}[✓]${RESET} $1" >&2; log_raw "OK: $1"; }
warn()  { echo -e "  ${YELLOW}[!]${RESET} $1" >&2; log_raw "WARN: $1"; }
info()  { echo -e "  ${CYAN}[→]${RESET} $1" >&2; log_raw "INFO: $1"; }
skip()  { echo -e "  ${BLUE}[↷]${RESET} $1 — ${DIM}already installed, skipping${RESET}" >&2; log_raw "SKIP: $1"; }

fatal() {
  # Kill spinner if running
  if [[ -n "$SPINNER_PID" ]]; then
    spinner_stop fail
  fi
  echo -e "\n  ${BG_RED}${BOLD} FATAL ERROR ${RESET}" >&2
  echo -e "  ${RED}$1${RESET}" >&2
  [[ -n "${2:-}" ]] && echo -e "  ${DIM}Suggestion: $2${RESET}" >&2
  echo -e "  ${DIM}Full log: ${LOG_FILE}${RESET}\n" >&2
  log_raw "FATAL: $1"
  exit 1
}

# ════════════════════════════════════════════════════════════
#  RETRY WRAPPER
# ════════════════════════════════════════════════════════════

# retry_run <description> <cmd> [args...]
# Retries up to MAX_RETRIES times on failure; shows attempt counter.
retry_run() {
  local desc="$1"; shift
  local attempt=1
  while (( attempt <= MAX_RETRIES )); do
    log_raw "ATTEMPT $attempt/$MAX_RETRIES: $*"
    if "$@" >> "$LOG_FILE" 2>&1; then
      return 0
    fi
    if (( attempt < MAX_RETRIES )); then
      printf "\r  ${YELLOW}[!]${RESET}  Retrying %s... (attempt %d/%d, waiting %ds)   \n" \
        "$desc" "$(( attempt + 1 ))" "$MAX_RETRIES" "$RETRY_DELAY" >&2
      sleep "$RETRY_DELAY"
    fi
    (( attempt++ )) || true
  done
  return 1
}

# apt_install — retry-aware apt-get install
apt_install() {
  retry_run "apt-get install" \
    apt-get install -y -qq "$@"
}

# curl_download <url> <dest>
curl_download() {
  local url="$1" dest="$2"
  retry_run "download $(basename "$dest")" \
    curl -fsSL --connect-timeout 10 --max-time 30 --retry 3 \
      -H "User-Agent: ps-panel-installer/2.1" "$url" -o "$dest"
}

# wget_download <url> <dest>
wget_download() {
  local url="$1" dest="$2"
  retry_run "download $(basename "$dest")" \
    wget -q --timeout=30 "$url" -O "$dest"
}

# ════════════════════════════════════════════════════════════
#  ERROR TRAP
# ════════════════════════════════════════════════════════════

_on_error() {
  local rc=$? line="${BASH_LINENO[0]}" cmd="$BASH_COMMAND"
  [[ -n "$SPINNER_PID" ]] && spinner_stop fail
  echo -e "\n  ${BG_RED}${BOLD} INSTALLATION FAILED ${RESET}" >&2
  echo -e "  ${RED}Error at line ${line}: ${cmd} (exit ${rc})${RESET}" >&2
  echo -e "  ${DIM}Full log: ${LOG_FILE}${RESET}\n" >&2
  log_raw "ERROR at line $line: $cmd (exit $rc)"
  tput cnorm 2>/dev/null || true
  exit "$rc"
}
trap '_on_error' ERR

# ════════════════════════════════════════════════════════════
#  BANNER
# ════════════════════════════════════════════════════════════

print_banner() {
  echo -e "${CYAN}" >&2
  echo "  ╔══════════════════════════════════════════════╗" >&2
  echo "  ║           PS Panel Installer v2.1            ║" >&2
  echo "  ║  FrankenPHP · PHP 8.3 · PostgreSQL 16        ║" >&2
  echo "  ║  Redis · Node.js v${NODE_VERSION} · PM2                 ║" >&2
  echo "  ╚══════════════════════════════════════════════╝" >&2
  echo -e "${RESET}" >&2
  echo -e "  ${DIM}Log: ${LOG_FILE}${RESET}\n" >&2
  log_raw "PS Panel Installer v2.1 started"
}

# ════════════════════════════════════════════════════════════
#  PRE-FLIGHT CHECKS
# ════════════════════════════════════════════════════════════

preflight_checks() {
  echo -e "  ${BOLD}Pre-flight checks${RESET}" >&2
  echo -e "  ─────────────────────────────────────────────" >&2

  local all_ok=true

  # Root check
  if [[ $EUID -eq 0 ]]; then
    printf "  ${GREEN}✓${RESET}  Root privileges\n" >&2
  else
    printf "  ${RED}✗${RESET}  Root privileges — ${RED}FAIL${RESET}\n" >&2
    all_ok=false
  fi

  # OS check
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
      printf "  ${GREEN}✓${RESET}  OS: %s\n" "${PRETTY_NAME:-Ubuntu 24.04}" >&2
    else
      printf "  ${YELLOW}!${RESET}  OS: %s — ${YELLOW}WARN${RESET} (optimized for Ubuntu 24.04)\n" \
        "${PRETTY_NAME:-Unknown}" >&2
    fi
  else
    printf "  ${RED}✗${RESET}  OS detection — ${RED}FAIL${RESET}\n" >&2
    all_ok=false
  fi

  # Disk space
  local free_kb free_gb
  free_kb=$(df / --output=avail -k | tail -1 | tr -d ' ')
  free_gb=$(( free_kb / 1024 / 1024 ))
  if (( free_gb >= WARN_DISK_GB )); then
    printf "  ${GREEN}✓${RESET}  Disk space: %dGB free\n" "$free_gb" >&2
  elif (( free_gb >= MIN_DISK_GB )); then
    printf "  ${YELLOW}!${RESET}  Disk space: %dGB free — ${YELLOW}WARN${RESET} (recommend ≥5GB)\n" \
      "$free_gb" >&2
  else
    printf "  ${RED}✗${RESET}  Disk space: %dGB free — ${RED}FAIL${RESET} (need ≥2GB)\n" \
      "$free_gb" >&2
    all_ok=false
  fi

  # RAM
  local ram_mb
  ram_mb=$(awk '/MemAvailable/ {printf "%d", $2/1024}' /proc/meminfo)
  if (( ram_mb >= MIN_RAM_MB )); then
    printf "  ${GREEN}✓${RESET}  RAM available: %dMB\n" "$ram_mb" >&2
  else
    printf "  ${YELLOW}!${RESET}  RAM available: %dMB — ${YELLOW}WARN${RESET} (recommend ≥512MB)\n" \
      "$ram_mb" >&2
  fi

  # Internet connectivity
  if ping -c1 -W3 8.8.8.8 &>/dev/null; then
    printf "  ${GREEN}✓${RESET}  Internet connectivity\n" >&2
  else
    printf "  ${RED}✗${RESET}  Internet connectivity — ${RED}FAIL${RESET}\n" >&2
    all_ok=false
  fi

  # Port availability
  local ports=(80 443 "$PANEL_PORT")
  for port in "${ports[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
      printf "  ${YELLOW}!${RESET}  Port %s — ${YELLOW}IN USE${RESET} (may conflict)\n" "$port" >&2
    else
      printf "  ${GREEN}✓${RESET}  Port %s available\n" "$port" >&2
    fi
  done

  echo -e "  ─────────────────────────────────────────────\n" >&2
  log_raw "Pre-flight checks complete. all_ok=$all_ok"

  if [[ "$all_ok" == "false" ]]; then
    fatal "Pre-flight checks failed. Fix the issues above and re-run the installer." \
      "Ensure you are root, have ≥2GB disk, and have internet access."
  fi
}

# ════════════════════════════════════════════════════════════
#  STEP: SYSTEM UPDATE
# ════════════════════════════════════════════════════════════

update_system() {
  section "System Update" "~1-2 min"

  spinner_start "Updating package lists..."
  retry_run "apt-get update" apt-get update -qq
  spinner_stop ok

  spinner_start "Installing base dependencies... (this may take a while)"
  apt_install \
    curl wget gnupg2 ca-certificates lsb-release \
    apt-transport-https software-properties-common \
    unzip git build-essential net-tools iproute2 openssl
  spinner_stop ok

  log "System dependencies installed"
}

# ════════════════════════════════════════════════════════════
#  STEP: PHP 8.3
# ════════════════════════════════════════════════════════════

install_php() {
  section "PHP 8.3" "~2-3 min"

  if php -v 2>/dev/null | grep -q "8\.3"; then
    skip "PHP 8.3"; return
  fi

  spinner_start "Adding Ondrej PHP PPA..."
  retry_run "add-apt-repository php" \
    add-apt-repository -y ppa:ondrej/php
  retry_run "apt-get update" apt-get update -qq
  spinner_stop ok

  spinner_start "Installing PHP 8.3 extensions... (this may take a while)"
  apt_install \
    php8.3 php8.3-fpm php8.3-cli php8.3-common \
    php8.3-pgsql php8.3-redis php8.3-curl php8.3-mbstring \
    php8.3-xml php8.3-zip php8.3-bcmath php8.3-intl \
    php8.3-gd php8.3-opcache php8.3-tokenizer
  spinner_stop ok

  spinner_start "Configuring PHP-FPM status page..."
  sed -i 's/^;pm.status_path.*/pm.status_path = \/status/' \
    /etc/php/8.3/fpm/pool.d/www.conf
  run_logged systemctl enable php8.3-fpm
  run_logged systemctl start php8.3-fpm
  spinner_stop ok

  log "PHP $(php -r 'echo PHP_VERSION;') installed"
}

# ════════════════════════════════════════════════════════════
#  STEP: FrankenPHP
# ════════════════════════════════════════════════════════════

install_frankenphp() {
  section "FrankenPHP" "~1-2 min"

  if command -v frankenphp &>/dev/null; then
    skip "FrankenPHP"; return
  fi

  spinner_start "Fetching latest FrankenPHP release info..."
  local arch latest api_response
  arch=$(dpkg --print-architecture)
  latest=""

  # FrankenPHP moved from dunglas/frankenphp to php/frankenphp (PHP Foundation).
  # Try the new repo first, then the legacy one as fallback.
  local repos=("php/frankenphp" "dunglas/frankenphp")
  local working_repo=""

  # Strategy 1: GitHub API with User-Agent and timeouts
  for repo in "${repos[@]}"; do
    api_response=$(curl -sf \
      --connect-timeout 10 --max-time 30 \
      -H "User-Agent: ps-panel-installer/2.1" \
      "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null || true)

    if echo "$api_response" | grep -qi "rate limit\|API rate limit exceeded"; then
      warn "GitHub API rate limit hit — skipping API method"
      api_response=""
      break
    fi

    if [[ -n "$api_response" ]]; then
      latest=$(echo "$api_response" | grep '"tag_name"' | head -1 | cut -d'"' -f4 || true)
      if [[ -n "$latest" ]]; then
        working_repo="$repo"
        log_raw "Resolved via API from ${repo}: $latest"
        break
      fi
    fi
  done

  # Strategy 2: Parse version from redirect URL (follow redirects to handle repo transfer)
  if [[ -z "$latest" ]]; then
    warn "GitHub API unavailable — trying redirect method..."
    for repo in "${repos[@]}"; do
      # -L follows redirects so we land on the final /tag/<version> location
      local redirect_target
      redirect_target=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        --connect-timeout 10 --max-time 30 \
        -H "User-Agent: ps-panel-installer/2.1" \
        "https://github.com/${repo}/releases/latest" 2>/dev/null || true)

      if [[ "$redirect_target" == *"/tag/"* ]]; then
        latest="${redirect_target##*/tag/}"
        latest="${latest%%[[:space:]]*}"
        # Detect which repo it actually landed on
        if [[ "$redirect_target" == *"/php/frankenphp/"* ]]; then
          working_repo="php/frankenphp"
        elif [[ "$redirect_target" == *"/dunglas/frankenphp/"* ]]; then
          working_repo="dunglas/frankenphp"
        else
          working_repo="$repo"
        fi
        log_raw "Resolved via redirect from ${repo} → ${working_repo}: $latest"
        break
      fi
    done
  fi

  # Validate version matches expected semver-ish pattern (e.g. v1.3.2)
  if [[ ! "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    log_raw "Resolved version '$latest' is invalid — discarding"
    latest=""
  fi

  # Strategy 3: Hardcoded fallback
  if [[ -z "$latest" ]]; then
    warn "Could not fetch FrankenPHP version — using fallback ${FRANKENPHP_FALLBACK}"
    latest="$FRANKENPHP_FALLBACK"
    working_repo="dunglas/frankenphp"
  fi

  # Default repo if still unset (shouldn't happen, but be safe)
  [[ -z "$working_repo" ]] && working_repo="php/frankenphp"

  log_raw "FrankenPHP version resolved: $latest (repo: $working_repo)"
  spinner_stop ok

  # Download with retry and exponential backoff (5s, 10s, 20s).
  # Try BOTH repos for each attempt since the release tarball may exist under
  # the legacy repo even after the transfer (and vice versa).
  spinner_start "Downloading FrankenPHP ${latest}..."
  local delays=(5 10 20)
  local dl_ok=false
  local attempt

  # Build candidate URL list — primary repo first, then the other one, plus x86_64 fallbacks
  local urls=(
    "https://github.com/${working_repo}/releases/download/${latest}/frankenphp-linux-${arch}"
    "https://github.com/${working_repo}/releases/download/${latest}/frankenphp-linux-x86_64"
  )
  for repo in "${repos[@]}"; do
    if [[ "$repo" != "$working_repo" ]]; then
      urls+=("https://github.com/${repo}/releases/download/${latest}/frankenphp-linux-${arch}")
      urls+=("https://github.com/${repo}/releases/download/${latest}/frankenphp-linux-x86_64")
    fi
  done

  for attempt in 1 2 3; do
    for url in "${urls[@]}"; do
      log_raw "FrankenPHP download attempt $attempt/3: $url"
      if curl -fsSL \
          --connect-timeout 10 --max-time 120 \
          -H "User-Agent: ps-panel-installer/2.1" \
          "$url" -o /usr/local/bin/frankenphp >> "$LOG_FILE" 2>&1; then
        # Sanity check: file must be non-trivial size (real binary is ~50MB+)
        if [[ -s /usr/local/bin/frankenphp ]] && \
           [[ $(stat -c%s /usr/local/bin/frankenphp 2>/dev/null || echo 0) -gt 1048576 ]]; then
          dl_ok=true
          log_raw "Download succeeded from: $url"
          break 2
        else
          log_raw "Downloaded file too small — discarding and trying next URL"
          rm -f /usr/local/bin/frankenphp
        fi
      fi
    done
    if (( attempt < 3 )); then
      local delay="${delays[$((attempt - 1))]}"
      printf "\r  ${YELLOW}[!]${RESET}  Download failed, retrying in %ds... (attempt %d/3)   \n" \
        "$delay" "$(( attempt + 1 ))" >&2
      sleep "$delay"
    fi
  done

  if [[ "$dl_ok" != "true" ]]; then
    spinner_stop fail
    fatal "Failed to download FrankenPHP after 3 attempts" \
      "Check connectivity or manually download from github.com/php/frankenphp/releases"
  fi

  chmod +x /usr/local/bin/frankenphp
  # Allow binding to privileged ports (80/443) without running as root
  setcap 'cap_net_bind_service=+ep' /usr/local/bin/frankenphp 2>/dev/null || true
  spinner_stop ok

  # Verify the downloaded binary is a valid ELF executable
  spinner_start "Verifying FrankenPHP binary..."
  if ! file /usr/local/bin/frankenphp 2>/dev/null | grep -q "ELF"; then
    spinner_stop fail
    fatal "Downloaded FrankenPHP binary is not a valid ELF executable" \
      "The download may be corrupted or the wrong architecture. Check ${LOG_FILE} and retry."
  fi
  spinner_stop ok

  spinner_start "Creating FrankenPHP config and systemd service..."
  mkdir -p /etc/frankenphp/sites /var/www/html
  # Caddy/FrankenPHP stores TLS state here; must be writable by www-data
  mkdir -p /var/www/.local/share/caddy/locks
  chown -R www-data:www-data /var/www/.local

  cat > /etc/frankenphp/Caddyfile << 'CADDYFILE'
http://:80 {
  root * /var/www/html
  php_server
}

import /etc/frankenphp/sites/*.conf
CADDYFILE

  cat > /etc/systemd/system/frankenphp.service << 'SVC'
[Unit]
Description=FrankenPHP Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www
ExecStart=/usr/local/bin/frankenphp run --config /etc/frankenphp/Caddyfile
Restart=always
RestartSec=5
LimitNOFILE=1048576
# Allow www-data to bind to privileged ports (80/443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVC

  run_logged systemctl daemon-reload
  run_logged systemctl enable frankenphp
  run_logged systemctl start frankenphp
  spinner_stop ok

  log "FrankenPHP ${latest} installed"
}

# ════════════════════════════════════════════════════════════
#  STEP: PostgreSQL 16
# ════════════════════════════════════════════════════════════

install_postgresql() {
  section "PostgreSQL 16" "~1-2 min"

  if systemctl is-active --quiet postgresql 2>/dev/null; then
    skip "PostgreSQL"; return
  fi

  spinner_start "Adding PostgreSQL APT repository..."
  curl_download \
    "https://www.postgresql.org/media/keys/ACCC4CF8.asc" \
    /tmp/postgresql.asc
  gpg --dearmor < /tmp/postgresql.asc \
    > /etc/apt/trusted.gpg.d/postgresql.gpg 2>> "$LOG_FILE"
  echo "deb [signed-by=/etc/apt/trusted.gpg.d/postgresql.gpg] \
https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  retry_run "apt-get update" apt-get update -qq
  spinner_stop ok

  spinner_start "Installing PostgreSQL 16... (this may take a while)"
  apt_install postgresql-16 postgresql-client-16
  spinner_stop ok

  spinner_start "Starting PostgreSQL and setting password..."
  run_logged systemctl enable postgresql
  run_logged systemctl start postgresql
  local pg_pass
  pg_pass=$(openssl rand -base64 16 | tr -d '=+/')
  sudo -u postgres psql -c "ALTER USER postgres PASSWORD '${pg_pass}';" \
    >> "$LOG_FILE" 2>&1
  grep -q "PG_PASSWORD" "$CREDS_FILE" 2>/dev/null \
    || echo "PG_PASSWORD=${pg_pass}" >> "$CREDS_FILE"
  spinner_stop ok

  log "PostgreSQL 16 installed"
}

# ════════════════════════════════════════════════════════════
#  STEP: Redis
# ════════════════════════════════════════════════════════════

install_redis() {
  section "Redis" "~30 sec"

  if systemctl is-active --quiet redis-server 2>/dev/null; then
    skip "Redis"; return
  fi

  spinner_start "Installing Redis..."
  apt_install redis-server
  spinner_stop ok

  spinner_start "Configuring Redis (bind 127.0.0.1)..."
  sed -i 's/^# bind 127.0.0.1/bind 127.0.0.1/' /etc/redis/redis.conf
  sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
  run_logged systemctl enable redis-server
  run_logged systemctl start redis-server
  spinner_stop ok

  log "Redis installed and bound to 127.0.0.1"
}

# ════════════════════════════════════════════════════════════
#  STEP: Node.js + PM2
# ════════════════════════════════════════════════════════════

install_nodejs() {
  section "Node.js v${NODE_VERSION}" "~1-2 min"

  if node -v 2>/dev/null | grep -q "v${NODE_VERSION}"; then
    skip "Node.js v${NODE_VERSION}"
  else
    spinner_start "Adding NodeSource repository..."
    curl_download \
      "https://deb.nodesource.com/setup_${NODE_VERSION}.x" \
      /tmp/nodesource_setup.sh
    retry_run "nodesource setup" bash /tmp/nodesource_setup.sh
    spinner_stop ok

    spinner_start "Installing Node.js v${NODE_VERSION}... (this may take a while)"
    apt_install nodejs
    spinner_stop ok

    log "Node.js $(node -v) installed"
  fi

  if pm2 -v &>/dev/null; then
    skip "PM2"
  else
    spinner_start "Installing PM2 globally..."
    retry_run "npm install pm2" npm install -g pm2
    run_logged pm2 startup systemd -u root --hp /root || true
    spinner_stop ok
    log "PM2 $(pm2 -v) installed"
  fi
}

# ════════════════════════════════════════════════════════════
#  STEP: PS Panel
# ════════════════════════════════════════════════════════════

install_panel() {
  section "PS Panel" "~1-2 min"

  mkdir -p "${PANEL_DIR}/public"
  cd "${PANEL_DIR}"

  spinner_start "Downloading panel UI..."
  wget_download "${GITHUB_RAW}/public/index.html" \
    "${PANEL_DIR}/public/index.html" \
    || warn "UI download failed — copy public/index.html manually later."
  spinner_stop ok

  spinner_start "Downloading panel backend (server.js)..."
  wget_download "${GITHUB_RAW}/server.js" \
    "${PANEL_DIR}/server.js" \
    || warn "server.js download failed — copy server.js manually later."
  spinner_stop ok

  spinner_start "Writing package.json..."
  cat > "${PANEL_DIR}/package.json" << 'PKGJSON'
{
  "name": "ps-panel",
  "version": "2.0.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "systeminformation": "^5.21.7",
    "pg": "^8.11.3",
    "ioredis": "^5.3.2",
    "ws": "^8.14.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2"
  }
}
PKGJSON
  spinner_stop ok

  spinner_start "Installing npm packages... (this may take a while)"
  retry_run "npm install" npm install --prefix "${PANEL_DIR}" --silent
  spinner_stop ok

  # Generate credentials
  local panel_pass
  panel_pass=$(openssl rand -base64 12 | tr -d '=+/')
  grep -q "PANEL_PASS" "$CREDS_FILE" 2>/dev/null \
    || echo "PANEL_PASS=${panel_pass}" >> "$CREDS_FILE"
  chmod 600 "$CREDS_FILE"

  spinner_start "Starting PS Panel via PM2..."
  pm2 delete ps-panel >> "$LOG_FILE" 2>&1 || true
  PANEL_PASS="${panel_pass}" pm2 start server.js \
    --name ps-panel \
    --env production >> "$LOG_FILE" 2>&1
  pm2 save >> "$LOG_FILE" 2>&1
  spinner_stop ok

  log "PS Panel started on port ${PANEL_PORT}"
}

# ════════════════════════════════════════════════════════════
#  STEP: Firewall
# ════════════════════════════════════════════════════════════

configure_firewall() {
  section "Firewall" "~10 sec"

  if ! command -v ufw &>/dev/null; then
    warn "UFW not found — skipping firewall config"
    return
  fi

  spinner_start "Configuring UFW rules (80, 443, ${PANEL_PORT})..."
  run_logged ufw allow 80/tcp || true
  run_logged ufw allow 443/tcp || true
  run_logged ufw allow "${PANEL_PORT}/tcp" || true
  spinner_stop ok

  log "UFW rules added (80, 443, ${PANEL_PORT})"
}

# ════════════════════════════════════════════════════════════
#  SERVICE STATUS HELPER
# ════════════════════════════════════════════════════════════

svc_status() {
  local svc="$1"
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    echo -e "${GREEN}● running${RESET}"
  else
    echo -e "${RED}○ stopped${RESET}"
  fi
}

# ════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ════════════════════════════════════════════════════════════

print_summary() {
  local creds panel_pass pg_pass server_ip
  creds=$(cat "$CREDS_FILE" 2>/dev/null || echo "")
  panel_pass=$(echo "$creds" | grep "^PANEL_PASS=" | cut -d= -f2)
  pg_pass=$(echo "$creds"   | grep "^PG_PASSWORD=" | cut -d= -f2)
  server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

  echo -e "\n${BOLD}${GREEN}" >&2
  echo "  ╔══════════════════════════════════════════════════════╗" >&2
  echo "  ║            PS Panel — Installation Complete          ║" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2
  printf  "  ║  %-20s %-33s║\n" "Panel URL:" "http://${server_ip}:${PANEL_PORT}" >&2
  printf  "  ║  %-20s %-33s║\n" "Password:" "${panel_pass:-[see ${CREDS_FILE}]}" >&2
  printf  "  ║  %-20s %-33s║\n" "PostgreSQL password:" "${pg_pass:-[see ${CREDS_FILE}]}" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2
  echo "  ║  Service Status                                      ║" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2

  local services=( "frankenphp:FrankenPHP" "php8.3-fpm:PHP-FPM" \
                   "postgresql:PostgreSQL" "redis-server:Redis" )
  for entry in "${services[@]}"; do
    local svc="${entry%%:*}"
    local label="${entry##*:}"
    local status
    status=$(svc_status "$svc")
    printf  "  ║  %-16s %s%-35s${RESET}║\n" "${label}" "" "${status}" >&2
  done

  # PM2 ps-panel status
  local pm2_status
  if pm2 show ps-panel 2>/dev/null | grep -q "online"; then
    pm2_status="${GREEN}● running${RESET}"
  else
    pm2_status="${RED}○ stopped${RESET}"
  fi
  printf "  ║  %-16s %s%-35s${RESET}║\n" "PS Panel (PM2)" "" "${pm2_status}" >&2

  echo "  ╠══════════════════════════════════════════════════════╣" >&2
  printf  "  ║  %-52s║\n" "Credentials saved: ${CREDS_FILE}" >&2
  printf  "  ║  %-52s║\n" "Install log: ${LOG_FILE}" >&2
  echo "  ╚══════════════════════════════════════════════════════╝" >&2
  echo -e "${RESET}" >&2
  echo -e "  ${YELLOW}${BOLD}⚠  Save your credentials now — they won't be shown again.${RESET}\n" >&2

  log_raw "Installation complete. URL=http://${server_ip}:${PANEL_PORT}"
}

# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

main() {
  print_banner
  preflight_checks
  update_system
  install_php
  install_frankenphp
  install_postgresql
  install_redis
  install_nodejs
  install_panel
  configure_firewall
  draw_progress "$TOTAL_STEPS" "$TOTAL_STEPS"
  print_summary
}

main "$@"
