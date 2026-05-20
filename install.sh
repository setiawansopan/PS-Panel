#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  PS Panel Installer
#  Stack: FrankenPHP + PHP 8.3 + PostgreSQL + Redis + Node.js
#  Target: Ubuntu 24.04 LTS
#  Usage : curl -fsSL https://raw.githubusercontent.com/USERNAME/ps-panel/main/install.sh | sudo bash
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PANEL_DIR="/opt/ps-panel"
PANEL_PORT=8765
NODE_VERSION=20

# ── Ganti dengan URL repo Anda ──────────────────────────────
GITHUB_RAW="https://raw.githubusercontent.com/setiawansopan/PS-Panel/main"
# ────────────────────────────────────────────────────────────

print_banner() {
  echo -e "${CYAN}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║            PS Panel Installer            ║"
  echo "  ║   FrankenPHP · PHP 8.3 · PostgreSQL      ║"
  echo "  ║         Redis · Node.js v${NODE_VERSION}             ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${RESET}"
}

log()     { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
info()    { echo -e "${CYAN}[→]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}── $1 ──${RESET}"; }

check_root() {
  [[ $EUID -eq 0 ]] || error "Jalankan sebagai root: sudo bash install.sh"
}

check_os() {
  [[ -f /etc/os-release ]] || error "/etc/os-release tidak ditemukan"
  . /etc/os-release
  [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]] \
    || warn "Dioptimalkan untuk Ubuntu 24.04. OS Anda: $PRETTY_NAME"
}

update_system() {
  section "Update System"
  info "Updating package lists..."
  apt-get update -qq
  apt-get install -y -qq \
    curl wget gnupg2 ca-certificates lsb-release \
    apt-transport-https software-properties-common \
    unzip git build-essential
  log "System dependencies installed"
}

install_php() {
  section "PHP 8.3"
  if php -v 2>/dev/null | grep -q "8.3"; then
    log "PHP 8.3 sudah terinstall, skip"; return
  fi
  info "Adding Ondrej PHP PPA..."
  add-apt-repository -y ppa:ondrej/php > /dev/null 2>&1
  apt-get update -qq
  info "Installing PHP 8.3 + extensions..."
  apt-get install -y -qq \
    php8.3 php8.3-fpm php8.3-cli php8.3-common \
    php8.3-pgsql php8.3-redis php8.3-curl php8.3-mbstring \
    php8.3-xml php8.3-zip php8.3-bcmath php8.3-intl \
    php8.3-gd php8.3-opcache php8.3-tokenizer
  # Aktifkan status page untuk PS Panel
  sed -i 's/^;pm.status_path.*/pm.status_path = \/status/' /etc/php/8.3/fpm/pool.d/www.conf
  systemctl enable php8.3-fpm
  systemctl start php8.3-fpm
  log "PHP $(php -r 'echo PHP_VERSION;') installed"
}

install_frankenphp() {
  section "FrankenPHP"
  if command -v frankenphp &>/dev/null; then
    log "FrankenPHP sudah terinstall, skip"; return
  fi
  info "Downloading FrankenPHP..."
  ARCH=$(dpkg --print-architecture)
  LATEST=$(curl -s https://api.github.com/repos/dunglas/frankenphp/releases/latest \
    | grep '"tag_name"' | cut -d'"' -f4)
  curl -fsSL "https://github.com/dunglas/frankenphp/releases/download/${LATEST}/frankenphp-linux-${ARCH}" \
    -o /usr/local/bin/frankenphp
  chmod +x /usr/local/bin/frankenphp

  mkdir -p /etc/frankenphp/sites /var/www/html

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

[Install]
WantedBy=multi-user.target
SVC

  systemctl daemon-reload
  systemctl enable frankenphp
  systemctl start frankenphp
  log "FrankenPHP ${LATEST} installed"
}

install_postgresql() {
  section "PostgreSQL 16"
  if systemctl is-active --quiet postgresql 2>/dev/null; then
    log "PostgreSQL sudah berjalan, skip"; return
  fi
  info "Adding PostgreSQL APT repository..."
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
  echo "deb [signed-by=/etc/apt/trusted.gpg.d/postgresql.gpg] \
    https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  apt-get update -qq
  apt-get install -y -qq postgresql-16 postgresql-client-16
  systemctl enable postgresql
  systemctl start postgresql
  PG_PASS=$(openssl rand -base64 16 | tr -d '=+/')
  sudo -u postgres psql -c "ALTER USER postgres PASSWORD '${PG_PASS}';" > /dev/null
  echo "PG_PASSWORD=${PG_PASS}" >> /root/.pspanel_credentials
  log "PostgreSQL 16 installed"
}

install_redis() {
  section "Redis"
  if systemctl is-active --quiet redis-server 2>/dev/null; then
    log "Redis sudah berjalan, skip"; return
  fi
  apt-get install -y -qq redis-server
  sed -i 's/^# bind 127.0.0.1/bind 127.0.0.1/' /etc/redis/redis.conf
  sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
  systemctl enable redis-server
  systemctl start redis-server
  log "Redis installed"
}

install_nodejs() {
  section "Node.js v${NODE_VERSION}"
  if node -v 2>/dev/null | grep -q "v${NODE_VERSION}"; then
    log "Node.js v${NODE_VERSION} sudah terinstall, skip"; return
  fi
  info "Installing Node.js via NodeSource..."
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_VERSION}.x" | bash - > /dev/null 2>&1
  apt-get install -y -qq nodejs
  npm install -g pm2 > /dev/null 2>&1
  pm2 startup systemd -u root --hp /root > /dev/null 2>&1 || true
  log "Node.js $(node -v) + PM2 installed"
}

install_panel() {
  section "PS Panel"
  info "Setting up panel at ${PANEL_DIR}..."
  mkdir -p "${PANEL_DIR}/public"
  cd "${PANEL_DIR}"

  # Download panel UI dari GitHub
  info "Downloading panel UI..."
  wget -qO "${PANEL_DIR}/public/index.html" \
    "${GITHUB_RAW}/public/index.html" \
    || warn "Gagal download UI, coba manual: wget -O /opt/ps-panel/public/index.html ${GITHUB_RAW}/public/index.html"

  # Download server.js dari GitHub
  info "Downloading panel backend..."
  wget -qO "${PANEL_DIR}/server.js" \
    "${GITHUB_RAW}/server.js" \
    || warn "Gagal download server.js"

  # Install dependencies
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

  info "Installing npm packages..."
  npm install --silent > /dev/null 2>&1
  log "npm packages installed"

  # Generate panel password
  PANEL_PASS=$(openssl rand -base64 12 | tr -d '=+/')
  echo "PANEL_PASS=${PANEL_PASS}" >> /root/.pspanel_credentials

  # Start dengan PM2
  pm2 delete ps-panel 2>/dev/null || true
  PANEL_PASS="${PANEL_PASS}" pm2 start server.js \
    --name ps-panel \
    --env production > /dev/null 2>&1
  pm2 save > /dev/null 2>&1
  log "PS Panel started on port ${PANEL_PORT}"
}

configure_firewall() {
  section "Firewall"
  if command -v ufw &>/dev/null; then
    ufw allow 80/tcp > /dev/null 2>&1 || true
    ufw allow 443/tcp > /dev/null 2>&1 || true
    ufw allow "${PANEL_PORT}/tcp" > /dev/null 2>&1 || true
    log "UFW rules added (80, 443, ${PANEL_PORT})"
  else
    warn "UFW tidak ditemukan, skip firewall config"
  fi
}

print_summary() {
  section "Instalasi Selesai"
  CREDS=$(cat /root/.pspanel_credentials 2>/dev/null || echo "")
  PANEL_PASS=$(echo "$CREDS" | grep PANEL_PASS | cut -d= -f2)
  PG_PASS=$(echo "$CREDS" | grep PG_PASSWORD | cut -d= -f2)
  SERVER_IP=$(hostname -I | awk '{print $1}')

  echo -e "\n${BOLD}"
  echo -e "  ╔══════════════════════════════════════════════════╗"
  echo -e "  ║              PS Panel — Akses Info               ║"
  echo -e "  ╠══════════════════════════════════════════════════╣"
  printf  "  ║  URL      : http://%-30s║\n" "${SERVER_IP}:${PANEL_PORT}"
  printf  "  ║  Password : %-35s║\n" "${PANEL_PASS}"
  echo -e "  ╠══════════════════════════════════════════════════╣"
  printf  "  ║  PostgreSQL password: %-27s║\n" "${PG_PASS:-'[lihat /root/.pspanel_credentials]'}"
  echo -e "  ╚══════════════════════════════════════════════════╝"
  echo -e "${RESET}"
  echo -e "  Semua kredensial: ${CYAN}/root/.pspanel_credentials${RESET}\n"
}

main() {
  print_banner
  check_root
  check_os
  update_system
  install_php
  install_frankenphp
  install_postgresql
  install_redis
  install_nodejs
  install_panel
  configure_firewall
  print_summary
}

main "$@"
