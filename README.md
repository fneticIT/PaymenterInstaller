# Paymenter Installer / Updater / Uninstaller (Bash)

**OS:** Ubuntu 20.04/22.04/24.04, Debian 10/11/12  
**Stack:** PHP 8.3-FPM, MariaDB 10.11, Redis, Nginx/Apache, Certbot  
**Log:** `/var/log/paymenter-installer.log`

---

## Quick start

~~~bash
# Download
curl -fsSL -o installer.sh https://raw.githubusercontent.com/fneticIT/PaymenterInstaller/refs/heads/main/installer.sh

chmod +x installer.sh
sudo ./installer.sh --menu
~~~

---

## What the script does

- Installs PHP 8.3 (+ext), MariaDB, Redis, Nginx/Apache, Composer.
- Fetches Paymenter (latest release or git), runs `composer install`, sets perms.
- Creates/updates DB & user (asks what to do if they already exist).
- Builds `.env`, generates app key, runs migrations/seed, links storage.
- Optional interactive:
  - `php artisan app:init`
  - `php artisan app:user:create`
- Adds cron (`* * * * * php artisan schedule:run`) and a systemd queue worker.
- Configures webserver:
  - **Nginx** or **Apache**
  - **SSL (Let’s Encrypt)** if chosen **and** your domain points to this server’s public IP  
    (verified against `https://api.ipify.org`). If it doesn’t match, SSL is skipped—fix DNS, then run `--webserver`.

---

## Modes (CLI)

~~~bash
sudo ./installer.sh --menu            # interactive menu (recommended)
sudo ./installer.sh --install         # full install wizard
sudo ./installer.sh --update-auto     # php artisan app:upgrade
sudo ./installer.sh --update-manual   # fetch latest release + migrate
sudo ./installer.sh --webserver       # (re)create vhost; optional SSL
sudo ./installer.sh --admin           # run app:user:create (interactive)
sudo ./installer.sh --status          # show service status
sudo ./installer.sh --uninstall       # remove service/vhost; optional DB/files
sudo ./installer.sh --help            # usage
~~~

---

## Before enabling SSL

- Create **A/AAAA** record for your domain → this server’s **public IP**.  
- Open **80/tcp** and **443/tcp** in firewall/security group.  
- If MariaDB **root** has a password, have it ready (you’ll be prompted).

---

## Useful commands

**Services**
~~~bash
systemctl status paymenter
systemctl status nginx        # or: systemctl status apache2
systemctl status mariadb
systemctl status redis-server
~~~

**Logs**
~~~bash
tail -f /var/log/paymenter-installer.log
tail -f /var/log/nginx/paymenter.error.log
tail -f /var/log/paymenter-worker.log
~~~

**Artisan (run in /var/www/paymenter)**
~~~bash
php artisan app:init
php artisan app:user:create
~~~

---

## Uninstall (interactive)

~~~bash
sudo ./installer.sh --uninstall
~~~

Removes service, vhost, cron; optionally drops DB/user and deletes files.

---

## Default paths

- App: `/var/www/paymenter`  
- Nginx vhost: `/etc/nginx/sites-available/paymenter.conf`  
- Apache vhost: `/etc/apache2/sites-available/paymenter.conf`  
- Systemd: `/etc/systemd/system/paymenter.service`
