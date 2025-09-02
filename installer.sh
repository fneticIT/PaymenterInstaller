#!/usr/bin/env bash
# Paymenter Interactive Installer / Updater / Uninstaller (pure Bash)
# Author: Fnetic — MIT
# Tested on: Ubuntu 20.04/22.04/24.04, Debian 10/11/12


set -Eeo pipefail

export DEBIAN_FRONTEND=noninteractive
export COMPOSER_ALLOW_SUPERUSER=1

LOG_FILE="/var/log/paymenter-installer.log"
: > "$LOG_FILE" || true

trap 'rc=$?; echo; echo "[ERROR] Line $LINENO: \"$BASH_COMMAND\" (exit $rc)"; echo "See log: $LOG_FILE"; exit $rc' ERR

supports_truecolor() {
  [[ "${COLORTERM:-}" == "truecolor" ]] || [[ "${TERM:-}" == *"256color"* ]]
}

grad() {
  local text="${1-}"
  [[ -z "$text" ]] && return 0
  local len=${#text} i ch r g b den
  local r1=90 g1=96  b1=255
  local r2=0  g2=224 b2=200
  den=$(( len>1 ? len-1 : 1 ))
  for ((i=0;i<len;i++)); do
    ch="${text:i:1}"
    r=$(( r1 + (r2 - r1) * i / den ))
    g=$(( g1 + (g2 - g1) * i / den ))
    b=$(( b1 + (b2 - b1) * i / den ))
    printf "\x1b[38;2;%d;%d;%dm%s" "$r" "$g" "$b" "$ch"
  done
  printf "\x1b[0m\n"
}

logo() {
  clear
  local BANNER
  BANNER="$(cat <<'EOF'
██████     ██████   ██    ██  ██    ██  ████████  ██    ██  ████████  ████████  ██████  
██   ██   ██    ██   ██  ██   ███  ███  ██        ███   ██     ██     ██        ██   ██ 
██████    ████████    ████    ██ ██ ██  ██████    ██ ██ ██     ██     ██████    ██████  
██        ██    ██     ██     ██    ██  ██        ██  ███      ██     ██        ██  ██  
██        ██    ██     ██     ██    ██  ████████  ██   ██      ██     ████████  ██   ██ 

████████  ██    ██  ████████  ████████   ██████   ██        ██        ████████  ██████  
   ██     ███   ██  ██           ██     ██    ██  ██        ██        ██        ██   ██ 
   ██     ██ ██ ██  ████████     ██     ████████  ██        ██        ██████    ██████  
   ██     ██  ███         ██     ██     ██    ██  ██        ██        ██        ██  ██  
████████  ██   ██   ████████     ██     ██    ██  ████████  ████████  ████████  ██   ██ 
EOF
)"
  if supports_truecolor; then grad "$BANNER"; else echo "$BANNER"; fi
  echo -e "by \e[1mFnetic\e[0m • \e[2m$(date)\e[0m"
  echo
}

PROG_PCT=0
PROG_MSG=""

progress_render() {
  local p="$PROG_PCT" msg="$PROG_MSG"
  local cols=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
  local barw=$(( cols - 28 ))
  if (( barw < 10 )); then barw=10; fi
  if (( barw > 60 )); then barw=60; fi

  local filled=$(( p*barw/100 ))
  local empty=$(( barw - filled ))

  printf "\r[%s%s] %3d%%  %s\x1b[K" \
    "$(printf '#%.0s' $(seq 1 $filled))" \
    "$(printf '.%.0s' $(seq 1 $empty))" \
    "$p" "$msg"

  if (( p >= 100 )); then
    printf "\n"
  fi
}

progress_set() {
  PROG_PCT="${1:-0}"
  shift || true
  PROG_MSG="${*:-}"
  progress_render
}

say()  { echo -e "• $*"; }
warn() { echo -e "\e[33m! $*\e[0m"; }
err()  { echo -e "\e[31m✗ $*\e[0m"; }

spin() {
  local msg="$1"; shift
  printf "\n"
  ( "$@" >>"$LOG_FILE" 2>&1 ) &
  local pid=$!
  local frames='|/-\' idx=0 flen=4
  printf "  %s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  %s %s" "$msg" "${frames:idx:1}"
    idx=$(( (idx + 1) % flen ))
    sleep 0.1
  done
  if wait "$pid"; then
    printf "\r  %s \e[32mOK\e[0m\n" "$msg"
  else
    printf "\r  %s \e[31mERROR\e[0m\n" "$msg"
    echo "  ↳ Details in $LOG_FILE"
    exit 1
  fi
  progress_render
}

spin_soft() {
  local msg="$1"; shift
  printf "\n"
  ( "$@" >>"$LOG_FILE" 2>&1 ) &
  local pid=$! frames='|/-\' idx=0 flen=4
  printf "  %s " "$msg"
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  %s %s" "$msg" "${frames:idx:1}"; idx=$(( (idx + 1) % flen )); sleep 0.1
  done
  if wait "$pid"; then
    printf "\r  %s \e[32mOK\e[0m\n" "$msg"
  else
    printf "\r  %s \e[31mERROR (skipping)\e[0m\n" "$msg"
    echo "  ↳ Details in $LOG_FILE" >&2
  fi
  progress_render
}

require_root() {
  if (( EUID != 0 )); then
    err "Run as root: sudo ./paymenter.sh"
    exit 1
  fi
}

detect_os() {
  . /etc/os-release
  OS_ID="$ID"
  [[ "$OS_ID" =~ ^(ubuntu|debian)$ ]] || { err "Supported: Ubuntu/Debian. Detected: ${PRETTY_NAME:-$ID}"; exit 1; }
}

ask() {
  local prompt="$1"; local def=""; local input=""
  if [[ $# -ge 2 ]]; then def="$2"; fi
  local line="$prompt"; [[ -n "$def" ]] && line="$prompt [$def]"
  read -r -p "$line: " input || true
  [[ -n "$input" ]] && echo "$input" || echo "$def"
}

ask_hidden_once() {
  local prompt="$1" password="" ch
  local tty="/dev/tty"
  if [[ -r "$tty" && -w "$tty" ]]; then
    printf "%s: " "$prompt" >"$tty"
    while IFS= read -rsn1 ch <"$tty"; do
      if [[ -z "$ch" || "$ch" == $'\n' || "$ch" == $'\r' ]]; then
        printf "\n" >"$tty"; break
      fi
      if [[ "$ch" == $'\177' || "$ch" == $'\b' ]]; then
        if (( ${#password} > 0 )); then
          password="${password%?}"; printf "\b \b" >"$tty"
        fi
        continue
      fi
      if [[ "$ch" == $'\e' ]]; then read -rsn2 -t 0.001 _junk <"$tty" || true; continue; fi
      password+="$ch"; printf "*" >"$tty"
    done
    echo "$password"
  else
    read -r -s -p "$prompt: " password || true; echo; echo "$password"
  fi
}

ask_hidden_confirm() {
  local prompt="$1" v1 v2
  while :; do
    v1="$(ask_hidden_once "$prompt")"
    v2="$(ask_hidden_once "Confirm password")"
    [[ "$v1" == "$v2" ]] && { echo "$v1"; return; }
    warn "Passwords do not match, try again."
  done
}

ask_yn() {
  local prompt="$1"; local def_yn="${2:-y}" ans=""
  read -r -p "$prompt [y/n] (default $def_yn): " ans || true
  ans="${ans:-$def_yn}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

gen_password() { openssl rand -base64 20 | tr -dc 'A-Za-z0-9!@#%^*()_+-=' | head -c 20; }

cmd_exists() { command -v "$1" &>/dev/null; }
php_sock_path() {
  local candidates=(
    /run/php/php-fpm.sock
    /var/run/php/php-fpm.sock
    /run/php/php8.3-fpm.sock
    /var/run/php/php8.3-fpm.sock
    /run/php/php8.2-fpm.sock
    /var/run/php/php8.2-fpm.sock
    /run/php/php8.1-fpm.sock
    /var/run/php/php8.1-fpm.sock
  )
  for s in "${candidates[@]}"; do
    [[ -S "$s" ]] && { echo "$s"; return 0; }
  done
  local svc ver
  svc=$(systemctl list-units --type=service --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}' | head -n1)
  if [[ -n "$svc" ]]; then
    ver="${svc#php}"; ver="${ver%-fpm.service}"
    for s in "/run/php/php${ver}-fpm.sock" "/var/run/php/php${ver}-fpm.sock"; do
      [[ -S "$s" ]] && { echo "$s"; return 0; }
    done
  fi
  echo "/run/php/php8.3-fpm.sock"
}

env_set() {
  local key="$1" val="$2" esc
  [[ -f .env ]] || touch .env
  esc=$(printf '%s' "$val" | sed -e 's/[\\&|]/\\&/g')
  if grep -q "^$key=" .env; then
    sed -i "s|^$key=.*|$key=$esc|" .env
  else
    printf "%s=%s\n" "$key" "$esc" >> .env
  fi
}

PAYMENTER_DIR="/var/www/paymenter"
PAYMENTER_USER="www-data"
PAYMENTER_GROUP="www-data"

DB_HOST="127.0.0.1"
DB_NAME="paymenter"
DB_USER="paymenter"
DB_PASS=""
DB_REMOTE="no"

DOMAIN=""
WEBSERVER="nginx"
USE_SSL="no"

RUN_APP_INIT="yes"
RUN_ADMIN_WIZARD="yes"

MYSQL_ROOT_PW=""
mysql_root_cmd() {
  if mysql -u root -e "SELECT 1;" >/dev/null 2>&1; then
    mysql -u root -N -B -e "$1"
  else
    if [[ -z "$MYSQL_ROOT_PW" ]]; then
      say "MySQL root password required."
      MYSQL_ROOT_PW="$(ask_hidden_once 'MySQL root password')"
    fi
    mysql -u root -p"$MYSQL_ROOT_PW" -N -B -e "$1"
  fi
}

check_domain_points_to_public_ip() {
  local domain="$1"
  [[ -z "$domain" ]] && return 1

  local public_ip; public_ip="$(curl -fsS https://api.ipify.org || true)"
  if [[ -z "$public_ip" ]]; then
    warn "Could not determine public IP (api.ipify.org). Continuing without DNS check."
    return 0
  fi

  local resolved ips ip matched=1
  resolved="$(getent hosts "$domain" || true)"
  if [[ -z "$resolved" ]]; then
    warn "Domain '$domain' does not resolve right now. SSL issuance may fail."
    return 1
  fi

  ips="$(awk '{print $1}' <<<"$resolved" | sort -u)"
  for ip in $ips; do
    if [[ "$ip" == "$public_ip" ]]; then
      matched=0
      break
    fi
  done

  if (( matched != 0 )); then
    warn "Domain '$domain' resolves to: $(echo "$ips" | paste -sd',' -) ; your public IP: $public_ip"
    return 1
  fi

  return 0
}

ensure_certbot_packages() {
  if [[ "$WEBSERVER" == "nginx" ]]; then
    spin "Install Certbot for Nginx" apt -y install certbot python3-certbot-nginx
  else
    spin "Install Certbot for Apache" apt -y install certbot python3-certbot-apache
  fi
}

main_menu() {
  logo
  echo "Choose an action:"
  echo "  1) Install Paymenter"
  echo "  2) Update (auto) – artisan app:upgrade"
  echo "  3) Update (manual) – fetch latest release + migrate"
  echo "  4) Uninstall Paymenter"
  echo "  5) Webserver only (configure vhost + SSL optional)"
  echo "  6) Status (services)"
  echo "  7) Exit"
  echo
  read -r -p "Your choice [1-7]: " CH
  case "$CH" in
    1) ACTION="install" ;;
    2) ACTION="update-auto" ;;
    3) ACTION="update-manual" ;;
    4) ACTION="uninstall" ;;
    5) ACTION="webserver" ;;
    6) ACTION="status" ;;
    7) exit 0 ;;
    *) echo "Invalid choice."; exit 1 ;;
  esac
}

wizard_config() {
  logo
  say "Welcome to the Paymenter Installer — minimal UI, sweet gradient."
  PAYMENTER_DIR="$(ask 'Install path' "$PAYMENTER_DIR")"
  DOMAIN="$(ask 'Domain (e.g., billing.example.com, empty = later)')"
  local ws; ws="$(ask 'Webserver (nginx/apache)' "$WEBSERVER")"; [[ "$ws" == "apache" || "$ws" == "nginx" ]] || ws="nginx"; WEBSERVER="$ws"
  if [[ -n "$DOMAIN" ]]; then
    ask_yn "Enable SSL (Let’s Encrypt) for $DOMAIN?" "y" && USE_SSL="yes" || USE_SSL="no"
  fi

  say "Database settings:"
  DB_HOST="$(ask 'DB host' "$DB_HOST")"
  DB_NAME="$(ask 'DB name' "$DB_NAME")"
  DB_USER="$(ask 'DB user' "$DB_USER")"
  DB_PASS="$(ask 'DB password (empty = generate)')"
  if [[ -z "$DB_PASS" ]]; then DB_PASS="$(gen_password)"; say "  Generated DB password: $DB_PASS"; fi
  ask_yn "Allow remote DB access for this user? (creates user @%)" "n" && DB_REMOTE="yes" || DB_REMOTE="no"

  ask_yn "Run interactive app init (php artisan app:init) at the end?" "y" && RUN_APP_INIT="yes" || RUN_APP_INIT="no"
  ask_yn "Run interactive admin wizard (php artisan app:user:create) at the very end?" "y" && RUN_ADMIN_WIZARD="yes" || RUN_ADMIN_WIZARD="no"
}

ensure_packages() {
  progress_set 2 "Start"
  spin "Apt update" apt -y update

  if [[ "$OS_ID" == "ubuntu" ]]; then
    spin "Base utilities" apt -y install software-properties-common curl apt-transport-https ca-certificates gnupg lsb-release unzip tar git
    spin "PHP PPA (Ondřej)" add-apt-repository -y ppa:ondrej/php
  else
    spin "Base utilities" apt -y install software-properties-common curl ca-certificates gnupg2 sudo lsb-release apt-transport-https unzip tar git
    if [[ ! -f /etc/apt/sources.list.d/sury-php.list ]]; then
      spin "Sury PHP 8.3 repo" bash -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/sury-php.list'
      spin "Sury key"       bash -c 'curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/sury-keyring.gpg'
    fi
  fi

  spin "MariaDB 10.11 repo" bash -c 'curl -sSL https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | bash -s -- --mariadb-server-version="mariadb-10.11"'
  spin "Apt update (after repos)" apt -y update

  spin "PHP 8.3 + FPM + extensions" apt -y install php8.3 php8.3-{common,cli,gd,mysql,mbstring,bcmath,xml,fpm,curl,zip,intl,redis}
  if [[ "$WEBSERVER" == "nginx" ]]; then
    spin "Nginx + Redis" apt -y install nginx redis-server
  else
    spin "Apache + mod_php + Redis" apt -y install apache2 libapache2-mod-php8.3 redis-server
  fi
  spin "MariaDB server" apt -y install mariadb-server
  spin "Enable PHP-FPM" systemctl enable --now php8.3-fpm

  if ! cmd_exists composer; then
    spin "Install Composer" bash -c 'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer'
  fi

  if [[ "$USE_SSL" == "yes" && -n "$DOMAIN" ]]; then
    ensure_certbot_packages
  fi

  progress_set 20 "Packages ready"
}

download_paymenter() {
  mkdir -p "$PAYMENTER_DIR"
  cd "$PAYMENTER_DIR"
  progress_set 30 "Fetch Paymenter"
  if curl -fsSL -o paymenter.tar.gz https://github.com/paymenter/paymenter/releases/latest/download/paymenter.tar.gz; then
    spin "Extract release" tar -xzf paymenter.tar.gz
    rm -f paymenter.tar.gz
  else
    say "Release tarball unavailable — cloning repository."
    spin "Clone repository" git clone https://github.com/paymenter/paymenter.git .
  fi
  spin "Composer install (prod)" bash -c 'COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader --no-interaction --no-progress'
  spin "Permissions storage/cache" bash -c 'chmod -R 755 storage/* bootstrap/cache/ || true'
  chown -R ${PAYMENTER_USER}:${PAYMENTER_GROUP} "$PAYMENTER_DIR" || true
  progress_set 45 "Sources ready"
}

setup_database() {
  progress_set 55 "Database setup"
  spin "Start MariaDB" systemctl enable --now mariadb

  local ue dbexists
  ue=$(mysql_root_cmd "SELECT COUNT(*) FROM mysql.user WHERE user='${DB_USER}';")
  dbexists=$(mysql_root_cmd "SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='${DB_NAME}';")

  if [[ "$ue" -gt 0 || "$dbexists" -gt 0 ]]; then
    echo
    echo "Detected existing artifacts:"
    [[ "$ue" -gt 0 ]] && echo "  - MySQL user '${DB_USER}' (one or more hosts)"
    [[ "$dbexists" -gt 0 ]] && echo "  - Database '${DB_NAME}'"
    echo
    echo "Choose how to proceed:"
    echo "  [R]ecreate  – drop user & database, then create fresh"
    echo "  [K]eep      – keep existing; ensure privileges; continue"
    echo "  [A]bort     – stop installer"
    read -r -p "Your choice [R/K/A] (default R): " dbchoice
    dbchoice="${dbchoice:-R}"
    case "$dbchoice" in
      R|r)
        say "Dropping old user(s) and database..."
        mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'localhost';" || true
        mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1';" || true
        mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'%';" || true
        mysql_root_cmd "DROP DATABASE IF EXISTS \`${DB_NAME}\`;" || true
        ;;
      K|k)
        say "Keeping existing DB/user; will ensure privileges."
        ;;
      *)
        err "Aborted by user."
        exit 1
        ;;
    esac
  fi

  mysql_root_cmd "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

  if [[ "$DB_REMOTE" == "yes" ]]; then
    mysql_root_cmd "CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';"
    mysql_root_cmd "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%' WITH GRANT OPTION;"
  else
    mysql_root_cmd "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
    mysql_root_cmd "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
    mysql_root_cmd "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost' WITH GRANT OPTION;"
    mysql_root_cmd "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1' WITH GRANT OPTION;"
  fi
  mysql_root_cmd "FLUSH PRIVILEGES;"

  progress_set 65 "Database ready"
}

setup_env_and_app() {
  cd "$PAYMENTER_DIR"
  progress_set 70 ".env and initialisation"

  [[ -f .env ]] || cp .env.example .env

  env_set "APP_ENV" "production"
  env_set "APP_DEBUG" "false"
  env_set "APP_NAME" "Paymenter"

  if [[ -n "$DOMAIN" ]]; then
    local SCHEME="http"; [[ "$USE_SSL" == "yes" ]] && SCHEME="https"
    env_set "APP_URL" "${SCHEME}://${DOMAIN}"
  else
    env_set "APP_URL" "http://localhost"
  fi

  env_set "DB_HOST"     "$DB_HOST"
  env_set "DB_DATABASE" "$DB_NAME"
  env_set "DB_USERNAME" "$DB_USER"
  env_set "DB_PASSWORD" "$DB_PASS"

  env_set "CACHE_DRIVER"         "file"
  env_set "SESSION_DRIVER"       "file"
  env_set "QUEUE_CONNECTION"     "sync"
  env_set "BROADCAST_CONNECTION" "log"
  env_set "FILESYSTEM_DISK"      "local"

  env_set "REDIS_CLIENT" "phpredis"
  env_set "REDIS_HOST"   "127.0.0.1"
  env_set "REDIS_PORT"   "6379"

  spin "optimize:clear" php artisan optimize:clear
  spin "APP_KEY"        php artisan key:generate --force
  spin "storage:link"   php artisan storage:link
  spin "Migrate + seed" php artisan migrate --force --seed

  progress_set 78 "Core ready"
}

run_app_init() {
  cd "$PAYMENTER_DIR" || return 0
  echo
  say "Launching interactive app init (php artisan app:init)..."
  echo "  -> Fill in the company name and the application URL."
  echo
  local ok=0
  if command -v script >/dev/null 2>&1; then
    if script -qfec "php artisan app:init" /dev/null; then ok=1; fi
  else
    if php artisan app:init; then ok=1; fi
  fi
  if (( ok==1 )); then
    echo; say "App init finished."
  else
    if php artisan list --no-ansi 2>>"$LOG_FILE" | grep -q 'app:init'; then
      warn "app:init failed (see log). You can run it later: php artisan app:init"
    else
      warn "Skipping 'app:init' (command not available)."
    fi
  fi
  progress_render
}

setup_cron_and_service() {
  progress_set 85 "Cron + systemd worker"

  local cron_line="* * * * * php ${PAYMENTER_DIR}/artisan schedule:run >> /dev/null 2>&1"
  ( crontab -l 2>/dev/null | grep -v -F "$cron_line" || true; echo "$cron_line" ) | crontab -
  say "Cron added"

  local svc="/etc/systemd/system/paymenter.service"
  if [[ ! -f "$svc" ]]; then
    cat > "$svc" <<EOF
[Unit]
Description=Paymenter Queue Worker
After=network.target

[Service]
User=${PAYMENTER_USER}
Group=${PAYMENTER_GROUP}
WorkingDirectory=${PAYMENTER_DIR}
Restart=always
ExecStart=/usr/bin/php ${PAYMENTER_DIR}/artisan queue:work --sleep=3 --tries=3
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s
StandardOutput=append:/var/log/paymenter-worker.log
StandardError=append:/var/log/paymenter-worker.log

[Install]
WantedBy=multi-user.target
EOF
    spin "Enable paymenter.service" systemctl enable --now paymenter.service
  else
    spin "Restart paymenter.service" systemctl restart paymenter.service
  fi

  spin "Enable Redis" systemctl enable --now redis-server
  progress_set 90 "Services ready"
}


nginx_write_http_only() {
  local sock="$1" conf="/etc/nginx/sites-available/paymenter.conf"
  cat > "$conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN:-_};
    root ${PAYMENTER_DIR}/public;

    index index.php;
    access_log /var/log/nginx/paymenter.access.log;
    error_log  /var/log/nginx/paymenter.error.log;

    # ACME challenge (no redirect)
    location ^~ /.well-known/acme-challenge/ {
        root ${PAYMENTER_DIR}/public;
        default_type "text/plain";
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${sock};
    }
}
EOF
  ln -sf "$conf" /etc/nginx/sites-enabled/paymenter.conf
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true
}

nginx_write_ssl() {
  local sock="$1" conf="/etc/nginx/sites-available/paymenter.conf"
  cat > "$conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    # Keep ACME reachable even with intended redirect
    location ^~ /.well-known/acme-challenge/ {
        root ${PAYMENTER_DIR}/public;
        default_type "text/plain";
    }
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    root ${PAYMENTER_DIR}/public;

    index index.php;
    access_log /var/log/nginx/paymenter.access.log;
    error_log  /var/log/nginx/paymenter.error.log;

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    # Recommended modern TLS bits (sane defaults)
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${sock};
    }
}
EOF
  ln -sf "$conf" /etc/nginx/sites-enabled/paymenter.conf
  rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default 2>/dev/null || true
}

configure_nginx() {
  local sock; sock="$(php_sock_path)"
  nginx_write_http_only "$sock"
  spin "Restart Nginx" systemctl restart nginx
}

configure_nginx_ssl() {
  ensure_certbot_packages

  if ! check_domain_points_to_public_ip "$DOMAIN"; then
    echo
    echo "SSL preflight failed for '$DOMAIN'."
    if ask_yn "Continue with SSL anyway?" "n"; then
      :
    else
      warn "Falling back to HTTP-only vhost."
      USE_SSL="no"
      configure_nginx
      return
    fi
  fi

  local sock; sock="$(php_sock_path)"

  nginx_write_http_only "$sock"
  spin "Reload Nginx (HTTP for ACME)" systemctl reload nginx

  spin "Certbot (webroot)" bash -c "certbot certonly --webroot -w '${PAYMENTER_DIR}/public' -d '${DOMAIN}' -m 'admin@${DOMAIN}' --agree-tos --non-interactive --keep"

  nginx_write_ssl "$sock"
  spin "Restart Nginx (SSL)" systemctl restart nginx

  if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    ( crontab -l 2>/dev/null; echo "0 23 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'" ) | crontab -
  fi
}

apache_write_http_only() {
  local conf="/etc/apache2/sites-available/paymenter.conf"
  cat > "$conf" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN:-localhost}
    DocumentRoot ${PAYMENTER_DIR}/public

    <Directory ${PAYMENTER_DIR}/public>
        AllowOverride All
        Require all granted
    </Directory>

    # ACME challenge webroot
    Alias /.well-known/acme-challenge/ ${PAYMENTER_DIR}/public/.well-known/acme-challenge/
    <Directory ${PAYMENTER_DIR}/public/.well-known/acme-challenge>
        Options None
        AllowOverride None
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/paymenter.error.log
    CustomLog \${APACHE_LOG_DIR}/paymenter.access.log combined
</VirtualHost>
EOF
  a2enmod rewrite headers >/dev/null
  ln -sf "$conf" /etc/apache2/sites-enabled/paymenter.conf
  rm -f /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-available/000-default.conf 2>/dev/null || true
}

apache_write_ssl() {
  local conf="/etc/apache2/sites-available/paymenter.conf"
  cat > "$conf" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
    # Keep ACME reachable even with intended redirect
    Alias /.well-known/acme-challenge/ ${PAYMENTER_DIR}/public/.well-known/acme-challenge/
    <Directory ${PAYMENTER_DIR}/public/.well-known/acme-challenge>
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    Redirect permanent / https://${DOMAIN}/
    ErrorLog \${APACHE_LOG_DIR}/paymenter.error.log
    CustomLog \${APACHE_LOG_DIR}/paymenter.access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName ${DOMAIN}
    DocumentRoot ${PAYMENTER_DIR}/public

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem

    <Directory ${PAYMENTER_DIR}/public>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/paymenter.error.log
    CustomLog \${APACHE_LOG_DIR}/paymenter.access.log combined
</VirtualHost>
EOF
  a2enmod ssl rewrite headers >/dev/null
  ln -sf "$conf" /etc/apache2/sites-enabled/paymenter.conf
  rm -f /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-available/000-default.conf 2>/dev/null || true
}

configure_apache() {
  apache_write_http_only
  spin "Restart Apache" systemctl restart apache2
}

configure_apache_ssl() {
  ensure_certbot_packages
  a2enmod ssl rewrite headers >/dev/null

  if ! check_domain_points_to_public_ip "$DOMAIN"; then
    echo
    echo "SSL preflight failed for '$DOMAIN'."
    if ask_yn "Continue with SSL anyway?" "n"; then
      :
    else
      warn "Falling back to HTTP-only vhost."
      USE_SSL="no"
      configure_apache
      return
    fi
  fi

  apache_write_http_only
  spin "Reload Apache (HTTP for ACME)" systemctl reload apache2

  spin "Certbot (webroot)" bash -c "certbot certonly --webroot -w '${PAYMENTER_DIR}/public' -d '${DOMAIN}' -m 'admin@${DOMAIN}' --agree-tos --non-interactive --keep"

  apache_write_ssl
  spin "Restart Apache (SSL)" systemctl restart apache2

  if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
    ( crontab -l 2>/dev/null; echo "0 23 * * * certbot renew --quiet --deploy-hook 'systemctl reload apache2'" ) | crontab -
  fi
}

webserver_setup() {
  chown -R ${PAYMENTER_USER}:${PAYMENTER_GROUP} "${PAYMENTER_DIR}" || true
  if [[ "$WEBSERVER" == "nginx" ]]; then
    if [[ "$USE_SSL" == "yes" && -n "$DOMAIN" ]]; then configure_nginx_ssl; else configure_nginx; fi
  else
    if [[ "$USE_SSL" == "yes" && -n "$DOMAIN" ]]; then configure_apache_ssl; else configure_apache; fi
  fi
  progress_set 98 "Webserver configured"
}

run_admin_wizard() {
  cd "$PAYMENTER_DIR" || return 0
  echo
  say "Launching admin account wizard (php artisan app:user:create)..."
  echo "  -> Enter first name, last name, email, password and choose role 'admin'."
  echo
  if command -v script >/dev/null 2>&1; then
    script -qfec "php artisan app:user:create" /dev/null || true
  else
    php artisan app:user:create || true
  fi
  echo
  say "Admin wizard finished."
  progress_render
}

post_install() {
  cd "$PAYMENTER_DIR"
  env_set "QUEUE_CONNECTION" "redis"
  spin "Reload config" php artisan config:clear

  progress_set 100 "Finish"
  echo
  say "Installation complete 🎉"
  echo "Path: $PAYMENTER_DIR"
  if [[ -n "$DOMAIN" ]]; then
    echo "URL: $([[ "$USE_SSL" == "yes" ]] && echo "https" || echo "http")://$DOMAIN"
  else
    echo "Web URL: (configure a domain later)"
  fi
  echo "DB: $DB_NAME  /  user: $DB_USER  /  pass: $DB_PASS"
  echo "Worker: systemctl status paymenter"
  echo "Installer log: $LOG_FILE"
}

auto_update() {
  cd "$PAYMENTER_DIR"
  spin "Auto-upgrade (artisan app:upgrade)" php artisan app:upgrade
  chown -R ${PAYMENTER_USER}:${PAYMENTER_GROUP} "${PAYMENTER_DIR}" || true
  say "Auto update finished."
}

manual_update() {
  cd "$PAYMENTER_DIR"
  spin "Maintenance mode (down)" php artisan down
  spin "Fetch latest release" bash -c 'curl -fsSL https://github.com/paymenter/paymenter/releases/latest/download/paymenter.tar.gz | tar -xz'
  spin "Composer install (prod)" composer install --no-dev --optimize-autoloader
  spin "Permissions storage/cache" bash -c 'chmod -R 755 storage/* bootstrap/cache/ || true'
  spin "Migrate + seed" php artisan migrate --force --seed
  spin "Clear caches" bash -c 'php artisan config:clear && php artisan view:clear'
  spin "Maintenance up" php artisan up
  chown -R ${PAYMENTER_USER}:${PAYMENTER_GROUP} "${PAYMENTER_DIR}" || true
  say "Manual update finished."
}

uninstall_flow() {
  logo
  warn "This will remove Paymenter services and optionally its files and database."
  ask_yn "Proceed with uninstall?" "n" || { say "Aborted."; exit 0; }

  if systemctl list-unit-files | grep -q '^paymenter\.service'; then
    spin "Stop paymenter.service" systemctl stop paymenter.service || true
    spin "Disable paymenter.service" systemctl disable paymenter.service || true
    rm -f /etc/systemd/system/paymenter.service
    systemctl daemon-reload || true
  fi

  local cron_line="* * * * * php ${PAYMENTER_DIR}/artisan schedule:run >> /dev/null 2>&1"
  ( crontab -l 2>/dev/null | grep -v -F "$cron_line" || true ) | crontab - || true

  if [[ -f /etc/nginx/sites-available/paymenter.conf ]]; then
    rm -f /etc/nginx/sites-enabled/paymenter.conf /etc/nginx/sites-available/paymenter.conf
    systemctl restart nginx || true
  fi
  if [[ -f /etc/apache2/sites-available/paymenter.conf ]]; then
    rm -f /etc/apache2/sites-enabled/paymenter.conf /etc/apache2/sites-available/paymenter.conf
    systemctl restart apache2 || true
  fi

  if ask_yn "Drop database '$DB_NAME' and MySQL user '$DB_USER'?" "n"; then
    mysql_root_cmd "DROP DATABASE IF EXISTS \`${DB_NAME}\`;" || true
    mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'localhost';" || true
    mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1';" || true
    mysql_root_cmd "DROP USER IF EXISTS '${DB_USER}'@'%';" || true
    mysql_root_cmd "FLUSH PRIVILEGES;" || true
  fi

  if ask_yn "Remove application files at '$PAYMENTER_DIR'?" "n"; then
    rm -rf "$PAYMENTER_DIR"
  fi

  say "Uninstall complete."
}

status_services() {
  echo
  systemctl -q is-active mariadb && echo "MariaDB:            active" || echo "MariaDB:            inactive"
  systemctl -q is-active redis-server && echo "Redis:              active" || echo "Redis:              inactive"
  if systemctl list-unit-files | grep -q '^nginx\.service'; then
    systemctl -q is-active nginx && echo "Nginx:              active" || echo "Nginx:              inactive"
  fi
  if systemctl list-unit-files | grep -q '^apache2\.service'; then
    systemctl -q is-active apache2 && echo "Apache:             active" || echo "Apache:             inactive"
  fi
  systemctl -q is-active paymenter && echo "Paymenter worker:   active" || echo "Paymenter worker:   inactive"
  echo
}

usage() {
  cat <<EOF
Usage: sudo ./paymenter.sh [options]
  --menu            Show interactive menu (default if no option)
  --install         Full installation (wizard)
  --update-auto     Automatic update (artisan app:upgrade)
  --update-manual   Manual update (pull latest release + migrate)
  --webserver       Only webserver configuration (vhost + optional SSL)
  --admin           Run admin account wizard (interactive)
  --status          Show services status
  --uninstall       Uninstall Paymenter (interactive)
  --help            This screen
Installer log: $LOG_FILE
EOF
}

install_flow() {
  wizard_config
  ensure_packages
  download_paymenter
  setup_database
  setup_env_and_app
  if [[ "$RUN_APP_INIT" == "yes" ]]; then
    run_app_init
  fi
  setup_cron_and_service
  webserver_setup
  if [[ "$RUN_ADMIN_WIZARD" == "yes" ]]; then
    run_admin_wizard
  fi
  post_install
}

webserver_flow() {
  logo
  say "Webserver configuration:"
  DOMAIN="$(ask 'Domain (e.g., billing.example.com)' "$DOMAIN")"
  local ws; ws="$(ask 'Webserver (nginx/apache)' "$WEBSERVER")"; [[ "$ws" == "apache" ]] && WEBSERVER="apache" || WEBSERVER="nginx"
  USE_SSL="no"
  if [[ -n "$DOMAIN" ]] && ask_yn "Enable SSL (Let’s Encrypt)?" "y"; then
    USE_SSL="yes"
    ensure_certbot_packages
  fi
  webserver_setup
  say "Webserver configured."
}

main() {
  require_root
  detect_os

  case "${1:-}" in
    --install) ACTION="install" ;;
    --update-auto) ACTION="update-auto" ;;
    --update-manual) ACTION="update-manual" ;;
    --webserver) ACTION="webserver" ;;
    --admin) ACTION="admin" ;;
    --status) ACTION="status" ;;
    --uninstall) ACTION="uninstall" ;;
    --menu|"") main_menu ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac

  case "$ACTION" in
    install) install_flow ;;
    update-auto) auto_update ;;
    update-manual) manual_update ;;
    webserver) webserver_flow ;;
    admin) run_admin_wizard ;;
    status) status_services ;;
    uninstall) uninstall_flow ;;
    *) usage; exit 1 ;;
  esac
}

main "$@"
