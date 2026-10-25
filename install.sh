#!/usr/bin/env bash
# ============================================================
#  PS Panel Installer  v2.3
#  Stack: FrankenPHP (web server) + PHP 8.5 (PHP-FPM) + PostgreSQL 16 + Redis + Node.js 20
#  Target: Ubuntu 24.04 LTS
#  Usage : curl -fsSL https://raw.githubusercontent.com/setiawansopan/PS-Panel/main/install.sh | sudo bash
# ============================================================

# --- strict mode: -e (exit on error) + -E (propagate ERR trap into functions/subshells)
#     are BOTH required for the ERR trap below to actually fire on failures that happen
#     inside a function — without -E, `trap ... ERR` at top level silently does nothing
#     for errors raised inside install_php/install_panel/etc, and steps report "OK" even
#     when the command they ran failed. ---
set -Eeuo pipefail

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
# PHP version served through PHP-FPM (Ondrej PPA). 8.5 is the target; override with e.g.
#   PS_PHP_VER=8.4 bash install.sh
# Fixed against PHP2Shell (CVE-2026-109618/109619): 8.5.12, 8.4.27, 8.3.36, 8.2.35 or newer.
PS_PHP_VER="${PS_PHP_VER:-8.5}"
# Panel login. Asked interactively at the start of the install (read from /dev/tty, so it also
# works with "curl ... | sudo bash"); for unattended installs pass them as variables:
#   PS_PANEL_USER=admin PS_PANEL_PASS='secret123' bash install.sh
# Without a terminal and without variables: username "admin" and a random password.
PS_PANEL_USER="${PS_PANEL_USER:-}"
PS_PANEL_PASS="${PS_PANEL_PASS:-}"
AUTH_FILE="/root/.pspanel_auth"
PANEL_CRED_MODE=""   # chosen | random | kept

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
UFW_INACTIVE=false

# ── Step definitions: name|estimated_time ────────────────────
declare -a STEPS=(
  "System Update|~1-2 min"
  "PHP ${PS_PHP_VER}|~2-3 min"
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
  echo "  ║           PS Panel Installer v2.3            ║" >&2
  echo "  ║  FrankenPHP · PHP 8.5 · PostgreSQL 16        ║" >&2
  echo "  ║  Redis · Node.js v${NODE_VERSION} · PM2                 ║" >&2
  echo "  ╚══════════════════════════════════════════════╝" >&2
  echo -e "${RESET}" >&2
  echo -e "  ${DIM}Log: ${LOG_FILE}${RESET}\n" >&2
  log_raw "PS Panel Installer v2.3 started"
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
    unzip git build-essential net-tools iproute2 openssl cron
  spinner_stop ok

  log "System dependencies installed"
}

# ════════════════════════════════════════════════════════════
#  STEP: PHP (PHP-FPM, version PS_PHP_VER, default 8.5)
# ════════════════════════════════════════════════════════════

# Warns when the installed PHP is older than the release that fixes PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619, per public reports: 8.5.12, 8.4.27, 8.3.36, 8.2.35).
php_security_check() {
  local ver patched
  ver=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "")
  case "${ver%.*}" in
    8.5) patched="8.5.12" ;;
    8.4) patched="8.4.27" ;;
    8.3) patched="8.3.36" ;;
    8.2) patched="8.2.35" ;;
    *)   patched="" ;;
  esac
  if [[ -z "$patched" ]]; then
    warn "PHP ${ver:-?}: no PHP2Shell fix is published for this branch — use PHP 8.5, 8.4 or 8.3"
  elif [[ "$(printf '%s\n%s\n' "$patched" "$ver" | sort -V | head -n1)" != "$patched" ]]; then
    warn "PHP ${ver} is older than ${patched} (vulnerable to PHP2Shell). Run: apt-get update && apt-get upgrade"
  else
    log "PHP ${ver} includes the PHP2Shell fix (>= ${patched})"
  fi
}

# Ondrej Sury's PHP PPA. `add-apt-repository` needs the Launchpad API (api.launchpad.net), which
# times out on some VPS networks (seen in the field: 3 × "Connection timed out", install aborted).
# The package archive itself lives on another host (ppa.launchpadcontent.net), so when the API is
# unreachable the source is written by hand with the PPA's signing key, fetched from the Ubuntu
# keyserver and checked against its known fingerprint.
ONDREJ_PPA_FPR="14AA40EC0831756756D7F66C4F4EA0AAE5267A6C"
add_ondrej_ppa() {
  if grep -rqs "ondrej/php" /etc/apt/sources.list /etc/apt/sources.list.d/; then
    log_raw "Ondrej PHP PPA already configured"; return 0
  fi
  if timeout 90 add-apt-repository -y ppa:ondrej/php >> "$LOG_FILE" 2>&1; then return 0; fi
  log_raw "add-apt-repository failed (Launchpad API unreachable?) — adding the PPA manually"
  local codename keyring="/etc/apt/keyrings/ondrej-php.gpg" tmp fpr
  codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
  [[ -n "$codename" ]] || codename=$(lsb_release -cs 2>/dev/null || true)
  tmp=$(mktemp)
  if ! curl -fsSL --retry 3 -m 60 -o "$tmp" \
      "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x${ONDREJ_PPA_FPR}"; then
    rm -f "$tmp"
    fatal "Could not add the PHP PPA: Launchpad API and keyserver.ubuntu.com are both unreachable" \
      "Check outbound HTTPS (and IPv6) on this server, then re-run the installer"
  fi
  fpr=$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
  if [[ "$fpr" != "$ONDREJ_PPA_FPR" ]]; then
    rm -f "$tmp"
    fatal "Downloaded PHP PPA key has an unexpected fingerprint (${fpr:-none})" "Re-run the installer later"
  fi
  install -d -m 0755 /etc/apt/keyrings
  gpg --dearmor < "$tmp" > "$keyring"; chmod 644 "$keyring"; rm -f "$tmp"
  cat > "/etc/apt/sources.list.d/ondrej-ubuntu-php-${codename}.sources" <<SRC
Types: deb
URIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu/
Suites: ${codename}
Components: main
Signed-By: ${keyring}
SRC
  log_raw "Ondrej PHP PPA added manually for ${codename}"
}

install_php() {
  local V="$PS_PHP_VER"
  section "PHP ${V}" "~2-3 min"

  if dpkg -s "php${V}-fpm" &>/dev/null && php -v 2>/dev/null | grep -q "^PHP ${V}\." && command -v composer &>/dev/null; then
    systemctl enable --now "php${V}-fpm" >> "$LOG_FILE" 2>&1 || true
    skip "PHP ${V} (CLI + FPM) + Composer"; php_security_check; return
  fi

  if ! dpkg -s "php${V}-fpm" &>/dev/null; then
    spinner_start "Adding Ondrej PHP PPA..."
    add_ondrej_ppa
    retry_run "apt-get update" apt-get update -qq
    spinner_stop ok

    # Fail early and clearly if this PHP version is not published, instead of a cryptic apt error.
    if ! apt-cache show "php${V}-fpm" &>/dev/null; then
      fatal "PHP ${V} (php${V}-fpm) is not available in the apt repositories" \
        "Check https://launchpad.net/~ondrej/+archive/ubuntu/php or re-run with PS_PHP_VER=8.4 (fixed releases: 8.5.12, 8.4.27, 8.3.36)"
    fi

    # Deliberately NOT the bare `php${V}` metapackage: it depends on
    # libapache2-mod-php | php-fpm | php-cgi, and apt can resolve that to Apache — which is
    # then enabled at boot and grabs port 80 before FrankenPHP on the next reboot. Only the
    # CLI (composer, artisan) and FPM (serves the sites) are installed explicitly.
    # Extension packages that are built into core or renamed in a given PHP version (e.g.
    # opcache in 8.5) are skipped; what is really loaded is verified with `php -m` below.
    local pkgs=("php${V}-cli" "php${V}-common" "php${V}-fpm") p
    for p in pgsql mysql sqlite3 redis curl mbstring xml zip bcmath intl gd opcache tokenizer fileinfo iconv soap; do
      if apt-cache show "php${V}-${p}" &>/dev/null; then
        pkgs+=("php${V}-${p}")
      else
        log_raw "SKIP: php${V}-${p} is not a separate package in this repo"
      fi
    done

    spinner_start "Installing PHP ${V} (CLI + FPM + extensions)... (this may take a while)"
    apt_install "${pkgs[@]}"
    spinner_stop ok

    # Make the chosen version the default `php` CLI when several are installed
    update-alternatives --set php "/usr/bin/php${V}" >> "$LOG_FILE" 2>&1 || true
  fi

  # PHP-FPM serves the sites (FrankenPHP only handles HTTP and forwards to the FPM socket).
  if [[ ! -x "/usr/sbin/php-fpm${V}" ]]; then
    fatal "php-fpm${V} binary not found after installation" "Check ${LOG_FILE}"
  fi
  run_logged systemctl enable --now "php${V}-fpm"
  if ! systemctl is-active --quiet "php${V}-fpm"; then
    fatal "php${V}-fpm is not running" "Check: journalctl -u php${V}-fpm --no-pager | tail -30"
  fi

  # Automatic security updates: the panel allows the Sury PPA origin for PHP packages in
  # unattended-upgrades (Ubuntu's own origins do not include it); it needs the package itself.
  if ! dpkg -s unattended-upgrades &>/dev/null; then
    apt_install unattended-upgrades || warn "Could not install unattended-upgrades; install it to get automatic PHP security updates"
  fi

  # Report (not fail on) extensions Laravel-style apps normally need.
  local ext missing=()
  for ext in pdo_pgsql mbstring xml curl zip bcmath intl gd redis tokenizer fileinfo iconv; do
    php -m 2>/dev/null | grep -qix "$ext" || missing+=("$ext")
  done
  if (( ${#missing[@]} > 0 )); then
    warn "PHP ${V}: extensions not loaded: ${missing[*]} (install them with apt if your apps need them)"
  fi

  log "PHP $(php -r 'echo PHP_VERSION;') + PHP-FPM installed"
  php_security_check

  # Install Composer (Laravel & PHP package manager)
  if ! command -v composer &>/dev/null; then
    spinner_start "Installing Composer (PHP dependency manager)..."
    (
      cd /tmp
      php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" >> "$LOG_FILE" 2>&1
      php composer-setup.php --install-dir=/usr/local/bin --filename=composer --quiet >> "$LOG_FILE" 2>&1
      rm -f composer-setup.php
    ) || true   # Composer failure is non-fatal here — checked below and reported as WARN, not FATAL
    if command -v composer &>/dev/null; then
      spinner_stop ok
      log "Composer $(composer --version --no-ansi 2>/dev/null | head -n1) installed"
    else
      spinner_stop fail
      log "${YELLOW}WARN: Composer installation failed, you may need to install manually${RESET}"
    fi
  fi
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
  mkdir -p /var/lib/caddy/config
  chown -R www-data:www-data /var/lib/caddy
  # Caddy/FrankenPHP stores TLS state here; must be writable by www-data
  mkdir -p /var/www/.local/share/caddy/locks
  chown -R www-data:www-data /var/www/.local

  # The global options block below is NOT optional. Without it, FrankenPHP's PHP
  # app is never provisioned — php_server directives still show up in Caddy's
  # routing table, but every PHP request then hangs forever (no error, no log,
  # just a connection that never completes) the moment a real vhost is added.
  # The default site goes through PHP-FPM when it is installed (security updates then arrive
  # through apt, independent of the FrankenPHP binary); FrankenPHP's embedded PHP otherwise.
  local default_site
  if [[ -x "/usr/sbin/php-fpm${PS_PHP_VER}" ]]; then
    default_site=$'\troot * /var/www/html\n\tencode zstd gzip\n\tphp_fastcgi unix//run/php/php'"${PS_PHP_VER}"$'-fpm.sock\n\tfile_server'
  else
    default_site=$'\troot * /var/www/html\n\tphp_server'
  fi
  printf '{\n\tfrankenphp\n}\n\nhttp://:80 {\n%s\n}\n\nimport /etc/frankenphp/sites/*.conf\n' "$default_site" > /etc/frankenphp/Caddyfile

  # php.ini for FrankenPHP's embedded PHP. FrankenPHP is a static binary: it does not read
  # the apt PHP's /etc/php/8.3/*/php.ini, and finds this file only because the unit below
  # sets PHPRC=/etc/frankenphp. The panel (Settings > PHP Configuration) edits this file.
  [[ -f /etc/frankenphp/php.ini ]] || cat > /etc/frankenphp/php.ini << 'PHPINI'
; Managed by PS Panel (Settings > PHP Configuration). FrankenPHP loads this file through
; PHPRC=/etc/frankenphp. Only the keys below are set; everything else keeps PHP's defaults.
PHPINI

  cat > /etc/systemd/system/frankenphp.service << 'SVC'
[Unit]
Description=FrankenPHP Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www
Environment=PHPRC=/etc/frankenphp
# Caddy autosaves its config here; HOME=/var/www is not writable by www-data (XDG_DATA_HOME is left alone: TLS certs live there)
Environment=XDG_CONFIG_HOME=/var/lib/caddy/config
ExecStart=/usr/local/bin/frankenphp run --config /etc/frankenphp/Caddyfile
ExecReload=/usr/local/bin/frankenphp reload --config /etc/frankenphp/Caddyfile
Restart=always
RestartSec=5
LimitNOFILE=1048576
# Allow www-data to bind to privileged ports (80/443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVC

  # Apache left enabled from an older install (see install_php) binds :80 at
  # boot, so FrankenPHP fails with "address already in use" and restart-loops
  # while the domain serves Apache's default page. Nothing else here uses it.
  if systemctl list-unit-files apache2.service 2>/dev/null | grep -q '^apache2\.service'; then
    run_logged systemctl disable --now apache2
    log "Disabled apache2 (conflicts with FrankenPHP on port 80)"
  fi

  run_logged systemctl daemon-reload
  run_logged systemctl enable frankenphp
  run_logged systemctl start frankenphp
  spinner_stop ok

  # `systemctl is-active` only proves the process is running — it does NOT prove
  # PHP requests are actually processed. Without the global `frankenphp` options
  # block in the Caddyfile, php_server still routes requests but they hang
  # forever (no error, no timeout on the server side) because the PHP runtime
  # was never provisioned. Prove it end-to-end with a real request instead.
  spinner_start "Verifying PHP requests are actually processed..."
  echo '<?php echo "pspanel-ok";' > /var/www/html/__pspanel_healthcheck.php
  local php_body
  php_body=$(curl -s -m 5 "http://127.0.0.1/__pspanel_healthcheck.php" 2>/dev/null || echo "")
  rm -f /var/www/html/__pspanel_healthcheck.php
  if [[ "$php_body" != "pspanel-ok" ]]; then
    spinner_stop fail
    fatal "FrankenPHP is running but a PHP request did not return the expected response (got: '${php_body}')." \
      "Check php${PS_PHP_VER}-fpm (systemctl status php${PS_PHP_VER}-fpm) and that /etc/frankenphp/Caddyfile starts with a global '{ frankenphp }' options block, then run: systemctl restart frankenphp"
  fi
  spinner_stop ok

  log "FrankenPHP ${latest} installed and verified serving PHP (via ${default_site:+PHP-FPM ${PS_PHP_VER}})"
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
    if ! curl -sf -m 5 https://registry.npmjs.org/ &>/dev/null; then
      spinner_stop fail
      fatal "Cannot reach the npm registry (registry.npmjs.org)" \
        "Check the server's internet/DNS connectivity, then re-run the installer."
    fi
    retry_run "npm install pm2" npm install -g pm2
    spinner_stop ok

    # Verify pm2 is actually usable — npm can report success without leaving a
    # working binary on PATH (e.g. custom npm prefix not in root's PATH).
    if ! command -v pm2 &>/dev/null; then
      fatal "PM2 installed via npm but the 'pm2' command is not on PATH" \
        "Run 'npm config get prefix' and ensure its bin directory is in root's \$PATH, then re-run the installer."
    fi

    run_logged pm2 startup systemd -u root --hp /root || true
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
  if ! wget_download "${GITHUB_RAW}/server.js" "${PANEL_DIR}/server.js"; then
    spinner_stop fail
    fatal "Failed to download server.js — the panel cannot run without it." \
      "Check connectivity to raw.githubusercontent.com and re-run the installer."
  fi
  spinner_stop ok

  spinner_start "Downloading version manifest..."
  wget_download "${GITHUB_RAW}/version.json" \
    "${PANEL_DIR}/version.json" \
    || warn "version.json download failed — self-update check may show outdated version."
  spinner_stop ok

  spinner_start "Writing package.json..."
  cat > "${PANEL_DIR}/package.json" << 'PKGJSON'
{
  "name": "ps-panel",
  "version": "2.3.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "systeminformation": "^5.21.7",
    "pg": "^8.11.3",
    "ioredis": "^5.3.2",
    "ws": "^8.14.2",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "nodemailer": "^6.9.13"
  }
}
PKGJSON
  # pm2 shows this version: keep it equal to the panel's real version (version.json)
  panel_version=$(grep -m1 '"version"' "${PANEL_DIR}/version.json" 2>/dev/null | sed -E 's/.*"version"[^"]*"([^"]+)".*/\1/' || true)
  if [[ -n "${panel_version:-}" ]]; then
    sed -i "s/\"version\": \"[0-9.]*\"/\"version\": \"${panel_version}\"/" "${PANEL_DIR}/package.json"
  fi
  spinner_stop ok

  spinner_start "Installing npm packages... (this may take a while)"
  if ! curl -sf -m 5 https://registry.npmjs.org/ &>/dev/null; then
    spinner_stop fail
    fatal "Cannot reach the npm registry (registry.npmjs.org)" \
      "Check the server's internet/DNS connectivity, then re-run the installer."
  fi
  retry_run "npm install" npm install --prefix "${PANEL_DIR}" --silent
  spinner_stop ok

  # npm can report a "successful" install while node_modules ends up empty/partial
  # (seen in the wild after a flaky registry connection) — verify explicitly.
  if [[ ! -d "${PANEL_DIR}/node_modules/express" ]]; then
    fatal "npm install finished but node_modules/express is missing — dependencies did not install correctly." \
      "Check connectivity to registry.npmjs.org, then run: cd ${PANEL_DIR} && npm install"
  fi

  # Panel login: written straight into the panel's auth file (bcrypt hash) before the first
  # start. The password goes through the environment only (not argv, not the pm2 dump).
  touch "$CREDS_FILE"; chmod 600 "$CREDS_FILE"
  if [[ "$PANEL_CRED_MODE" != "kept" ]]; then
    if ! ( cd "${PANEL_DIR}" && PANEL_INIT_USER="$PS_PANEL_USER" PANEL_INIT_PASS="$PS_PANEL_PASS" \
             node server.js --init-credentials ) >> "$LOG_FILE" 2>&1; then
      fatal "Could not set the panel login" "See ${LOG_FILE}; you can set it later with: cd ${PANEL_DIR} && node server.js --reset-password"
    fi
    sed -i '/^PANEL_USER=/d;/^PANEL_PASS=/d' "$CREDS_FILE"
    echo "PANEL_USER=${PS_PANEL_USER}" >> "$CREDS_FILE"
    # a generated password is kept here so it can be looked up later; a chosen one is not stored
    if [[ "$PANEL_CRED_MODE" == "random" ]]; then echo "PANEL_PASS=${PS_PANEL_PASS}" >> "$CREDS_FILE"; fi
  fi

  spinner_start "Starting PS Panel via PM2..."
  pm2 delete ps-panel >> "$LOG_FILE" 2>&1 || true
  pm2 start server.js \
    --name ps-panel \
    --env production >> "$LOG_FILE" 2>&1
  pm2 save >> "$LOG_FILE" 2>&1
  spinner_stop ok

  # "pm2 start" exiting 0 only means the command was accepted — it does NOT mean the
  # process is actually up. Verify something is really listening before claiming success.
  spinner_start "Verifying PS Panel is responding on port ${PANEL_PORT}..."
  local panel_ok=false http_code i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    http_code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 "http://127.0.0.1:${PANEL_PORT}/" 2>/dev/null || echo "000")
    if [[ "$http_code" != "000" ]]; then
      panel_ok=true
      break
    fi
    sleep 1
  done

  if [[ "$panel_ok" != "true" ]]; then
    spinner_stop fail
    fatal "PS Panel did not start — nothing is listening on port ${PANEL_PORT} after 10s." \
      "Run 'pm2 logs ps-panel' and check ${LOG_FILE} for the real error (common cause: crash on startup)."
  fi
  spinner_stop ok

  log "PS Panel started and responding on port ${PANEL_PORT}"
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

  if ufw status 2>/dev/null | grep -q "^Status: active"; then
    log "UFW rules added (80, 443, ${PANEL_PORT}) — UFW is active and enforcing them"
  else
    log "UFW rules added (80, 443, ${PANEL_PORT})"
    warn "UFW itself is NOT enabled — these rules are not filtering anything yet."
    warn "If your VPS provider's security group/cloud firewall already restricts access, this is fine as-is."
    warn "To enforce locally instead, run (in this order, or you may lock yourself out of SSH):"
    warn "  ufw allow 22/tcp && ufw enable"
    UFW_INACTIVE=true
  fi
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
  local creds panel_user panel_pass pg_pass server_ip
  creds=$(cat "$CREDS_FILE" 2>/dev/null || echo "")
  panel_user="${PS_PANEL_USER:-$(echo "$creds" | grep "^PANEL_USER=" | cut -d= -f2- || true)}"
  case "$PANEL_CRED_MODE" in
    chosen) panel_pass="(as entered during install)" ;;
    random) panel_pass="$PS_PANEL_PASS" ;;
    *)      panel_user="${panel_user:-(unchanged)}"; panel_pass="(unchanged)" ;;
  esac
  pg_pass=$(echo "$creds"   | grep "^PG_PASSWORD=" | cut -d= -f2 || true)
  server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

  echo -e "\n${BOLD}${GREEN}" >&2
  echo "  ╔══════════════════════════════════════════════════════╗" >&2
  echo "  ║            PS Panel — Installation Complete          ║" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2
  printf  "  ║  %-20s %-33s║\n" "Panel URL:" "http://${server_ip}:${PANEL_PORT}" >&2
  printf  "  ║  %-20s %-33s║\n" "Username:" "${panel_user:-admin}" >&2
  printf  "  ║  %-20s %-33s║\n" "Password:" "${panel_pass:-[see ${CREDS_FILE}]}" >&2
  printf  "  ║  %-20s %-33s║\n" "PostgreSQL password:" "${pg_pass:-[see ${CREDS_FILE}]}" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2
  echo "  ║  Service Status                                      ║" >&2
  echo "  ╠══════════════════════════════════════════════════════╣" >&2

  local services=( "frankenphp:FrankenPHP" \
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

  if [[ "$UFW_INACTIVE" == "true" ]]; then
    echo -e "  ${YELLOW}${BOLD}⚠  UFW rules were added but UFW is NOT enabled${RESET} ${DIM}(see Firewall step above for how to enable it)${RESET}\n" >&2
  fi

  log_raw "Installation complete. URL=http://${server_ip}:${PANEL_PORT}"
}

# ════════════════════════════════════════════════════════════
#  PANEL LOGIN (username + password chosen by the admin)
# ════════════════════════════════════════════════════════════

valid_panel_user() { [[ "$1" =~ ^[a-z0-9._-]{3,32}$ ]]; }

ask_panel_credentials() {
  echo -e "\n  ${BOLD}PS Panel login${RESET}" >&2
  echo -e "  ─────────────────────────────────────────────" >&2
  # Re-install over an existing panel: its login (possibly changed in Settings) stays as is.
  if [[ -s "$AUTH_FILE" ]]; then
    PANEL_CRED_MODE="kept"
    echo -e "  ${GREEN}✓${RESET}  Existing panel login found (${AUTH_FILE}) — keeping it unchanged" >&2
    return
  fi
  local tty_ok=false
  if [[ -z "$PS_PANEL_USER" || -z "$PS_PANEL_PASS" ]] && { : < /dev/tty; } 2>/dev/null; then tty_ok=true; fi

  PS_PANEL_USER=$(echo "$PS_PANEL_USER" | tr '[:upper:]' '[:lower:]')
  if [[ -n "$PS_PANEL_USER" ]] && ! valid_panel_user "$PS_PANEL_USER"; then
    fatal "PS_PANEL_USER '${PS_PANEL_USER}' is not valid" "Use 3-32 characters: lowercase letters, digits, '.', '-' or '_'"
  fi
  if [[ -z "$PS_PANEL_USER" && "$tty_ok" == true ]]; then
    local u
    while true; do
      read -r -p "  Panel username [admin]: " u < /dev/tty || u=""
      u=$(echo "${u:-admin}" | tr '[:upper:]' '[:lower:]')
      valid_panel_user "$u" && break
      echo -e "  ${RED}✗${RESET}  3-32 characters: lowercase letters, digits, '.', '-' or '_'" >&2
    done
    PS_PANEL_USER="$u"
  fi
  PS_PANEL_USER="${PS_PANEL_USER:-admin}"

  if [[ -n "$PS_PANEL_PASS" ]]; then
    [[ ${#PS_PANEL_PASS} -ge 8 ]] || fatal "PS_PANEL_PASS is too short" "Use at least 8 characters"
    PANEL_CRED_MODE="chosen"
  elif [[ "$tty_ok" == true ]]; then
    local p1 p2
    while true; do
      read -r -s -p "  Panel password (min 8 chars, empty = generate one): " p1 < /dev/tty || p1=""; echo >&2
      if [[ -z "$p1" ]]; then break; fi
      if [[ ${#p1} -lt 8 ]]; then echo -e "  ${RED}✗${RESET}  At least 8 characters" >&2; continue; fi
      read -r -s -p "  Repeat password: " p2 < /dev/tty || p2=""; echo >&2
      if [[ "$p1" == "$p2" ]]; then break; fi
      echo -e "  ${RED}✗${RESET}  Passwords do not match, try again" >&2
    done
    if [[ -n "$p1" ]]; then PS_PANEL_PASS="$p1"; PANEL_CRED_MODE="chosen"; fi
  fi
  if [[ -z "$PS_PANEL_PASS" ]]; then
    PS_PANEL_PASS=$(openssl rand -base64 12 | tr -d '=+/')
    PANEL_CRED_MODE="random"
  fi
  echo -e "  ${GREEN}✓${RESET}  Panel username: ${BOLD}${PS_PANEL_USER}${RESET}  password: $([[ $PANEL_CRED_MODE == chosen ]] && echo 'as entered' || echo 'generated, shown at the end')" >&2
}

# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════

main() {
  print_banner
  preflight_checks
  ask_panel_credentials
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
