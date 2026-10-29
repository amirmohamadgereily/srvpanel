<div align="center">

# srvpanel

**A lightweight, self-hosted server monitoring dashboard for Ubuntu 24.04**

Live CPU, memory, storage, network and process metrics — in a responsive web panel with Persian and English interface support.

![Platform](https://img.shields.io/badge/platform-Ubuntu%2024.04-E95420?logo=ubuntu&logoColor=white)
![Python](https://img.shields.io/badge/Python-3-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-check%20repository-lightgrey)

</div>

## Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [First login](#first-login)
- [Usage and service management](#usage-and-service-management)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Development and verification](#development-and-verification)
- [Contributing](#contributing)
- [License](#license)

## Overview

`srvpanel` is a small web dashboard for checking the current state of a Linux server. The installer creates a dedicated service account, a Python virtual environment, a systemd unit, and a self-signed TLS certificate. Metrics are sampled by a single background thread and served from a shared in-memory snapshot.

## Features

- Live CPU utilization, per-core usage, load average and CPU temperature when supported by the host.
- RAM and swap utilization.
- Disk capacity and utilization for detected filesystems.
- Network throughput and cumulative received/sent bytes.
- Disk read/write throughput, when counters are available.
- Uptime, operating system, kernel, hostname and established TCP connection count.
- Top processes by CPU and memory use.
- Automatic dashboard refresh without a full page reload.
- Persian (RTL) and English (LTR) dashboard controls.
- Dark and light themes, plus a configurable refresh interval.
- Password hashing, first-login password change, CSRF protection, login throttling and security response headers.
- systemd service with a dedicated unprivileged service account.

> Hardware temperature and some disk I/O metrics depend on kernel, hardware, permissions and available system counters. Unsupported metrics may be unavailable.

## Requirements

- A fresh or existing **Ubuntu 24.04** server.
- Root access for installation.
- Network access to Ubuntu package repositories and Python package index during installation.
- A free TCP port reachable from your client. If UFW is active, the installer adds an allow rule for the selected port.
- Python 3, `venv`, OpenSSL, curl and `iproute2` (installed by the installer).

## Install

Run the installer as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/amirmohamadgereily/srvpanel/main/install.sh)
```

The installer selects a free port automatically. To request a specific port:

```bash
PANEL_PORT=24443 bash <(curl -fsSL https://raw.githubusercontent.com/amirmohamadgereily/srvpanel/main/install.sh)
```

Choose a port that is allowed by your hosting provider's firewall/security group as well as the server firewall. Re-running the installer updates the application files while preserving the existing password and port, unless `PANEL_PORT` is explicitly provided.

To install from a locally downloaded copy:

```bash
chmod +x install.sh
sudo ./install.sh
```

## First login

At the end of a fresh installation, the installer prints the panel URL and a one-time password. Save the password before closing the terminal. You will be required to change it at first login.

The panel uses a self-signed TLS certificate by default, so a browser certificate warning is expected. Only proceed if you trust the server and have verified that you connected to the correct address. For public-facing production use, consider placing the panel behind a properly configured HTTPS reverse proxy and restrict network access.

If the one-time password is lost, generate a replacement:

```bash
sudo srvpanel reset-password
```

This creates a new one-time password and requires it to be changed after login.

## Usage and service management

Open the URL printed by the installer:

```text
https://SERVER_IP:PANEL_PORT/
```

Useful commands:

```bash
# Service status
sudo systemctl status srvpanel --no-pager

# Follow service logs
sudo journalctl -u srvpanel -f

# Recent logs
sudo journalctl -u srvpanel -n 100 --no-pager

# Restart
sudo systemctl restart srvpanel

# Reset login password
sudo srvpanel reset-password
```

To change the port, rerun the installer with `PANEL_PORT` set to the desired unused port. The installer updates the service configuration and adjusts the UFW rule when UFW is active.

### Dashboard controls

- **Language:** switch between Persian and English.
- **Theme:** switch between dark and light appearance.
- **Refresh interval:** choose 2, 3, 5 or 10 seconds. Shorter intervals make more requests from the browser, though metrics are collected by a shared sampler.

The selected language and theme are stored in the current browser's local storage.

## Security notes

- Keep the panel port restricted to trusted IP addresses where possible.
- Use a unique, strong password and change the generated one-time password immediately.
- Do not expose the panel directly to the public internet unless you understand the risks.
- The default certificate is self-signed; it does not provide publicly trusted identity verification.
- The panel is intended for monitoring, not remote command execution.
- The installer requires root for system setup, but the web application runs as the dedicated `srvpanel` system user.
- Keep Ubuntu and Python dependencies updated.

## Troubleshooting

### The service does not start

```bash
sudo systemctl status srvpanel --no-pager
sudo journalctl -u srvpanel -n 100 --no-pager
```

### The panel URL is unreachable

1. Confirm the service is active.
2. Check that the configured TCP port is listening: `sudo ss -ltnp`.
3. Check UFW with `sudo ufw status`.
4. Check the hosting provider's firewall/security group.
5. If you changed the port, use the latest URL and port.

### Login is unavailable or the password is forgotten

```bash
sudo srvpanel reset-password
sudo systemctl restart srvpanel
```

### Some metrics show a dash or zero

Temperature sensors and disk/network counters vary by host and kernel. Virtualized environments may not expose all hardware metrics. Check the host's available counters and the service logs before treating an unavailable value as a fault.

## Uninstall

From the repository directory:

```bash
sudo bash install.sh uninstall
```

The uninstall routine removes the service, application directory, configuration (including TLS material), CLI command, and service account. It also attempts to remove the UFW rule for the configured port. **Back up any configuration you need before uninstalling.**

## Development and verification

The application source is embedded in `install.sh` and written to `/opt/srvpanel/panel.py` during installation. The current project intentionally avoids a separate database and frontend build pipeline.

Before publishing changes, run at least:

```bash
bash -n install.sh
```

The embedded Python application can be extracted and syntax-checked in a development environment. Also test installation, first login, password changes, API authorization, refresh recovery, RTL/LTR rendering, mobile layout and service startup on a disposable Ubuntu 24.04 server. Do not infer a successful end-to-end installation from syntax checks alone.

## Contributing

1. Open an issue describing the problem or proposed change.
2. Keep the installer idempotent and avoid unnecessary dependencies.
3. Preserve existing authentication and service-hardening behavior.
4. Verify shell and Python syntax, and document any test that could not be run.
5. Submit a pull request with a concise summary and test results.

## License

Check the repository's license file or repository metadata before redistributing this project. No license file was included in the ZIP provided for this update, so this README does not assign a license.
