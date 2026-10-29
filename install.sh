#!/usr/bin/env bash
#
# srvpanel installer: lightweight live server resource panel for Ubuntu 24.04
#
# Install : bash <(curl -fsSL https://raw.githubusercontent.com/[GITHUB_USER]/[REPO_NAME]/main/install.sh)
# Update  : run the same command again (password and port are kept)
# Remove  : bash install.sh uninstall
# Env     : PANEL_PORT=<port>  force a specific panel port
#
set -euo pipefail

APP_NAME="srvpanel"
APP_DIR="/opt/srvpanel"
CONF_DIR="/etc/srvpanel"
CONF_FILE="${CONF_DIR}/config.json"
TLS_DIR="${CONF_DIR}/tls"
CERT_FILE="${TLS_DIR}/panel.crt"
KEY_FILE="${TLS_DIR}/panel.key"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
CLI_FILE="/usr/local/bin/srvpanel"
SERVICE_USER="srvpanel"
PY="${APP_DIR}/venv/bin/python"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

PORT=""
SERVER_IP=""
NEW_PASSWORD=""

log() { printf '[srvpanel] %s\n' "$*"; }
die() { printf '[srvpanel] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "This installer must be run as root (try: sudo -i)."
  fi
}

require_ubuntu_2404() {
  if [ ! -r /etc/os-release ]; then
    die "Cannot detect the operating system (/etc/os-release is missing)."
  fi
  # shellcheck source=/dev/null
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
    die "Ubuntu 24.04 is required (detected: ${PRETTY_NAME:-unknown})."
  fi
}

is_ipv4() {
  local re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  [[ "${1:-}" =~ $re ]]
}

is_port() {
  local re='^[0-9]+$'
  [[ "${1:-}" =~ $re ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# Print the port stored in config.json (empty output if unavailable).
read_config_port() {
  python3 - "$CONF_FILE" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        print(json.load(fh).get("port", ""))
except Exception:
    pass
PYEOF
}

ufw_active() {
  local out
  command -v ufw >/dev/null 2>&1 || return 1
  out="$(LC_ALL=C ufw status 2>/dev/null || true)"
  [[ "$out" == "Status: active"* ]]
}

open_firewall() {
  if ufw_active; then
    ufw allow "${1}/tcp" >/dev/null
    log "ufw: opened port ${1}/tcp"
  fi
}

close_firewall() {
  if ufw_active; then
    ufw delete allow "${1}/tcp" >/dev/null 2>&1 || true
  fi
}

port_in_use() {
  ss -H -ltn 2>/dev/null | awk -v p="$1" '{ n = split($4, a, ":"); if (a[n] == p) found = 1 } END { exit found ? 0 : 1 }'
}

pick_port() {
  local p
  for _ in $(seq 1 100); do
    p="$(shuf -i 20000-60000 -n 1)"
    if ! port_in_use "$p"; then
      echo "$p"
      return 0
    fi
  done
  die "Could not find a free port between 20000 and 60000."
}

get_public_ip() {
  local addr url
  for url in "https://api.ipify.org" "https://ipv4.icanhazip.com" "https://ifconfig.me/ip"; do
    addr="$(curl -4 -fsS --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if is_ipv4 "$addr"; then
      echo "$addr"
      return 0
    fi
  done
  addr="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)"
  if is_ipv4 "$addr"; then
    echo "$addr"
    return 0
  fi
  echo "SERVER_IP"
}

uninstall_panel() {
  log "Uninstalling ${APP_NAME}..."
  local old_port=""
  if [ -f "$CONF_FILE" ] && command -v python3 >/dev/null 2>&1; then
    old_port="$(read_config_port)"
  fi
  systemctl disable --now "${APP_NAME}.service" >/dev/null 2>&1 || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl reset-failed "${APP_NAME}.service" >/dev/null 2>&1 || true
  if is_port "$old_port"; then
    close_firewall "$old_port"
  fi
  rm -rf "$APP_DIR" "$CONF_DIR"
  rm -f "$CLI_FILE"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
  fi
  log "Uninstalled."
}

install_packages() {
  log "Installing system packages..."
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv openssl curl ca-certificates iproute2 >/dev/null
}

ensure_user_and_dirs() {
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  install -d -m 755 "$APP_DIR"
  install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$CONF_DIR"
  install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$TLS_DIR"
}

write_app_files() {
  log "Writing panel source..."
  cat > "${APP_DIR}/panel.py" <<'PANEL_PY_EOF'
#!/usr/bin/env python3
"""srvpanel - minimal live server resource panel (Flask + psutil)."""

import hashlib
import hmac
import json
import math
import os
import platform
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
from datetime import timedelta
from functools import wraps

import psutil
from flask import (Flask, abort, g, jsonify, redirect, render_template_string,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

CONFIG_PATH = "/etc/srvpanel/config.json"
SERVICE_USER = "srvpanel"
MIN_PASSWORD_LEN = 8
MAX_FAILS = 5
LOCK_SECONDS = 600
SAMPLE_INTERVAL = 2.0
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

# --------------------------------------------------------------------------
# Config storage (salted hash only, never the plaintext password)
# --------------------------------------------------------------------------


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config(cfg):
    directory = os.path.dirname(CONFIG_PATH)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".config-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh)
        os.chmod(tmp, 0o600)
        try:
            shutil.chown(tmp, user=SERVICE_USER, group=SERVICE_USER)
        except (LookupError, OSError):
            pass
        os.replace(tmp, CONFIG_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def generate_password(length=16):
    return "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))


def pw_fingerprint(cfg):
    return hashlib.sha256(cfg["password_hash"].encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------
# Metrics sampler (single background thread, results cached for all clients)
# --------------------------------------------------------------------------

_state = {"data": None}
_state_lock = threading.Lock()
_FS_SKIP = {"squashfs", "tmpfs", "devtmpfs", "overlay", "iso9660", "ramfs"}
_DISK_PREFIXES = ("sd", "vd", "xvd", "hd", "nvme", "mmcblk")


def _net_totals():
    rx = tx = 0
    for name, c in psutil.net_io_counters(pernic=True).items():
        if name == "lo" or name.startswith(("veth", "docker", "br-")):
            continue
        rx += c.bytes_recv
        tx += c.bytes_sent
    return rx, tx


def _disk_io_totals():
    try:
        counters = psutil.disk_io_counters(perdisk=True)
    except Exception:
        return None
    if not counters:
        return None
    rd = wr = 0
    for name, c in counters.items():
        if name.startswith(_DISK_PREFIXES) and os.path.exists("/sys/block/" + name):
            rd += c.read_bytes
            wr += c.write_bytes
    return rd, wr


def _count_established():
    total = 0
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == "01":
                        total += 1
        except OSError:
            continue
    return total


def _cpu_temp():
    try:
        temps = psutil.sensors_temperatures()
    except (AttributeError, OSError):
        return None
    for key in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz"):
        entries = temps.get(key)
        if entries:
            values = [e.current for e in entries if e.current is not None]
            if values:
                return round(max(values), 1)
    return None


def _disk_list():
    seen = set()
    out = []
    for part in psutil.disk_partitions(all=False):
        if part.fstype in _FS_SKIP or part.device.startswith("/dev/loop"):
            continue
        if part.device in seen:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        if usage.total <= 0:
            continue
        seen.add(part.device)
        out.append({"mount": part.mountpoint, "fstype": part.fstype,
                    "total": usage.total, "used": usage.used,
                    "percent": usage.percent})
    if not out:
        try:
            usage = psutil.disk_usage("/")
            out.append({"mount": "/", "fstype": "-", "total": usage.total,
                        "used": usage.used, "percent": usage.percent})
        except OSError:
            pass
    return out


def _os_name():
    try:
        return platform.freedesktop_os_release().get("PRETTY_NAME") or platform.system()
    except (OSError, AttributeError):
        return platform.system()


def _build_snapshot(ncpu, net, down, up, rd, wr):
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    total = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()

    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        info = p.info
        mem = info.get("memory_info")
        rss = mem.rss if mem else 0
        procs.append({
            "pid": info.get("pid"),
            "name": info.get("name") or "?",
            # Normalised to total CPU capacity so the value never exceeds 100.
            "cpu": round(min((info.get("cpu_percent") or 0.0) / ncpu, 100.0), 1),
            "rss": rss,
            "mem": round(rss * 100.0 / vm.total, 1) if vm.total else 0.0,
        })
    top_cpu = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:5]
    top_mem = sorted(procs, key=lambda x: x["rss"], reverse=True)[:5]

    return {
        "ts": time.time(),
        "cpu": {
            "total": round(total, 1),
            "per_core": [round(x, 1) for x in per_core],
            "load": [round(x, 2) for x in os.getloadavg()],
            "temp": _cpu_temp(),
            "cores": ncpu,
        },
        "mem": {"total": vm.total, "used": vm.total - vm.available,
                "free": vm.available, "percent": round(vm.percent, 1)},
        "swap": {"total": sw.total, "used": sw.used, "free": sw.free,
                 "percent": round(sw.percent, 1)},
        "disks": _disk_list(),
        "disk_io": {"read_speed": rd, "write_speed": wr},
        "net": {"down_speed": down, "up_speed": up, "bytes_recv": net[0],
                "bytes_sent": net[1], "connections": _count_established()},
        "system": {
            "hostname": socket.gethostname(),
            "os": _os_name(),
            "kernel": platform.release(),
            "uptime": int(time.time() - psutil.boot_time()),
            "users": len(psutil.users()),
        },
        "top_cpu": top_cpu,
        "top_mem": top_mem,
    }


def _sampler():
    ncpu = psutil.cpu_count(logical=True) or 1
    # Prime the counters so the first real sample has meaningful deltas.
    psutil.cpu_percent(interval=None, percpu=True)
    psutil.cpu_percent(interval=None)
    for _ in psutil.process_iter(["cpu_percent"]):
        pass
    prev_t = time.monotonic()
    prev_net = _net_totals()
    prev_io = _disk_io_totals()
    time.sleep(1.0)
    while True:
        try:
            now = time.monotonic()
            dt = max(now - prev_t, 0.001)
            net = _net_totals()
            io = _disk_io_totals()
            down = max(net[0] - prev_net[0], 0) / dt
            up = max(net[1] - prev_net[1], 0) / dt
            if io and prev_io:
                rd = max(io[0] - prev_io[0], 0) / dt
                wr = max(io[1] - prev_io[1], 0) / dt
            else:
                rd = wr = 0.0
            prev_t, prev_net, prev_io = now, net, io
            snapshot = _build_snapshot(ncpu, net, down, up, rd, wr)
            with _state_lock:
                _state["data"] = snapshot
        except Exception:
            pass  # keep the sampler alive no matter what
        time.sleep(SAMPLE_INTERVAL)


# --------------------------------------------------------------------------
# Login rate limiting (in-memory; the service runs a single worker process)
# --------------------------------------------------------------------------

_rl = {}
_rl_lock = threading.Lock()


def rl_remaining(ip):
    now = time.time()
    with _rl_lock:
        rec = _rl.get(ip)
        if rec is None:
            return 0
        if rec["until"] > now:
            return int(rec["until"] - now) + 1
        if rec["until"] or now - rec["last"] > LOCK_SECONDS:
            del _rl[ip]
        return 0


def rl_fail(ip):
    now = time.time()
    with _rl_lock:
        if len(_rl) > 5000:
            stale = [k for k, v in _rl.items()
                     if v["until"] < now and now - v["last"] > LOCK_SECONDS]
            for key in stale:
                del _rl[key]
        rec = _rl.setdefault(ip, {"fails": 0, "until": 0.0, "last": now})
        rec["fails"] += 1
        rec["last"] = now
        if rec["fails"] >= MAX_FAILS:
            rec["until"] = now + LOCK_SECONDS


def rl_reset(ip):
    with _rl_lock:
        _rl.pop(ip, None)


def lock_message(seconds):
    return "به دلیل تلاش‌های ناموفق متعدد، ورود از این آدرس به مدت %d دقیقه مسدود است." % max(1, math.ceil(seconds / 60.0))


# --------------------------------------------------------------------------
# Web application
# --------------------------------------------------------------------------

app = Flask(__name__, static_folder=None)
app.config.update(
    SESSION_COOKIE_NAME="srvpanel_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=16 * 1024,
)

CSS = """
:root{--bg:#0d1117;--card:#161b22;--card2:#1c222b;--line:#262d38;--text:#e6edf3;--mute:#8b98a9;--ok:#3ddc97;--warn:#f5b73b;--bad:#ff5d6c;--accent:#58a6ff}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font:14px/1.6 Tahoma,"Segoe UI","Noto Sans Arabic","DejaVu Sans",system-ui,sans-serif}
a{color:var(--accent);text-decoration:none}
.num{direction:ltr;unicode-bidi:isolate;display:inline-block}
.mute{color:var(--mute)}
.top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line);background:var(--card)}
.brand{display:flex;align-items:center;gap:10px}
.brand h1{font-size:17px;margin:0}
.dot{width:10px;height:10px;border-radius:50%;background:var(--bad)}
.dot.on{background:var(--ok)}
.actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.actions form{margin:0}
.btn{display:inline-block;background:var(--card2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:7px 14px;font:inherit;cursor:pointer}
.btn:hover{border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#06101c;width:100%;margin-top:16px;font-weight:bold}
.wrap{max-width:1280px;margin:0 auto;padding:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
.card h2{margin:0 0 10px;font-size:15px;color:var(--mute);font-weight:normal}
.card h2.sub{margin-top:18px}
.big{font-size:28px;font-weight:bold;line-height:1.3}
.big.sm{font-size:20px}
.kv{display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-bottom:1px dashed var(--line)}
.kv:last-child{border-bottom:0}
.kv span:first-child{color:var(--mute)}
.kv.strong span:first-child{color:var(--text)}
.bar{display:block;width:100%;height:8px;border-radius:4px;overflow:hidden;margin:6px 0}
.bar .bg{fill:#262d38}
.bar .fill.ok{fill:var(--ok)}
.bar .fill.warn{fill:var(--warn)}
.bar .fill.bad{fill:var(--bad)}
.chart{direction:ltr}
.spark{display:block;width:100%;height:56px;background:var(--card2);border-radius:8px;margin:8px 0}
.line{stroke-width:1.6;stroke-linejoin:round;vector-effect:non-scaling-stroke}
.line.s0{stroke:var(--accent)}
.line.s1{stroke:var(--ok)}
.legend{display:flex;gap:16px;font-size:12px;color:var(--mute);margin:2px 0 8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-inline-end:5px}
.legend .c0{background:var(--accent)}
.legend .c1{background:var(--ok)}
.cores{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-top:12px}
.core{background:var(--card2);border-radius:8px;padding:6px 8px;font-size:12px}
.core .row{display:flex;justify-content:space-between}
.disk{margin-top:10px}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{color:var(--mute);font-weight:normal;text-align:start;padding:4px 6px;border-bottom:1px solid var(--line)}
.tbl td{padding:5px 6px;border-bottom:1px solid var(--line)}
.tbl td.name{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:right}
.tbl td.ltr{direction:ltr;text-align:right;white-space:nowrap}
.alert{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid}
.alert.err{border-color:var(--bad);color:#ffb3bb;background:#2a1519}
.alert.ok{border-color:var(--ok);color:#b6f2d6;background:#122a20}
.alert.warn{border-color:var(--warn);color:#fbe0a0;background:#2b2412}
.auth{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.auth-card{width:100%;max-width:400px}
.auth-card h1{margin:0 0 14px;font-size:20px}
label{display:block;margin:12px 0 5px;color:var(--mute)}
input[type=password]{width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card2);color:var(--text);font:inherit;direction:ltr;text-align:left}
input:focus{outline:2px solid var(--accent);border-color:transparent}
.auth-links{display:flex;justify-content:space-between;align-items:center;margin-top:16px}
form.inline{display:inline;margin:0}
button.link{background:none;border:0;color:var(--accent);cursor:pointer;font:inherit;padding:0}
@media (max-width:560px){.grid{grid-template-columns:1fr}.big{font-size:24px}.wrap{padding:10px}}
"""

LOGIN_TPL = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>ورود | پنل سرور</title>
<style>{{ css|safe }}</style>
</head>
<body>
<main class="auth">
  <div class="card auth-card">
    <h1>ورود به پنل سرور</h1>
    {% if error %}<div class="alert err">{{ error }}</div>{% endif %}
    <form method="post" action="/login">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <label for="password">رمز عبور</label>
      <input id="password" name="password" type="password" required autofocus autocomplete="current-password">
      <button class="btn primary" type="submit">ورود</button>
    </form>
  </div>
</main>
</body>
</html>"""

CHANGE_TPL = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>تغییر رمز عبور | پنل سرور</title>
<style>{{ css|safe }}</style>
</head>
<body>
<main class="auth">
  <div class="card auth-card">
    <h1>تغییر رمز عبور</h1>
    {% if forced %}<div class="alert warn">رمز عبور فعلی یک‌بار مصرف است. برای ادامه، باید یک رمز عبور جدید تعیین کنید.</div>{% endif %}
    {% if error %}<div class="alert err">{{ error }}</div>{% endif %}
    <form method="post" action="/change-password">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <label for="current">رمز عبور فعلی</label>
      <input id="current" name="current" type="password" required autofocus autocomplete="current-password">
      <label for="new">رمز عبور جدید (حداقل ۸ نویسه)</label>
      <input id="new" name="new" type="password" required minlength="8" autocomplete="new-password">
      <label for="confirm">تکرار رمز عبور جدید</label>
      <input id="confirm" name="confirm" type="password" required minlength="8" autocomplete="new-password">
      <button class="btn primary" type="submit">ذخیره رمز جدید</button>
    </form>
    <div class="auth-links">
      {% if not forced %}<a href="/">بازگشت به داشبورد</a>{% else %}<span></span>{% endif %}
      <form method="post" action="/logout" class="inline">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">
        <button class="link" type="submit">خروج</button>
      </form>
    </div>
  </div>
</main>
</body>
</html>"""

DASH_TPL = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>پنل منابع سرور</title>
<style>{{ css|safe }}</style>
</head>
<body>
<header class="top">
  <div class="brand">
    <span class="dot" id="live"></span>
    <h1>پنل منابع سرور</h1>
    <span class="mute num" id="hostName"></span>
  </div>
  <div class="actions">
    <span class="mute" id="liveText">در حال اتصال…</span>
    <a class="btn" href="/change-password">تغییر رمز عبور</a>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{ csrf }}">
      <button class="btn" type="submit">خروج</button>
    </form>
  </div>
</header>
<div class="wrap">
  {% if notice %}<div class="alert ok">{{ notice }}</div>{% endif %}
  <div class="grid">

    <section class="card">
      <h2>پردازنده (CPU)</h2>
      <div class="big num" id="cpuTotal">—</div>
      <div id="cpuBar"></div>
      <div class="chart" id="cpuSpark"></div>
      <div class="kv"><span>میانگین بار (۱، ۵، ۱۵ دقیقه)</span><span class="num" id="loadAvg">—</span></div>
      <div class="kv"><span>دمای پردازنده</span><span class="num" id="cpuTemp">—</span></div>
      <div class="kv"><span>تعداد هسته‌ها</span><span class="num" id="cpuCount">—</span></div>
      <div class="cores" id="cores"></div>
    </section>

    <section class="card">
      <h2>حافظه (RAM)</h2>
      <div class="big num" id="memPct">—</div>
      <div id="memBar"></div>
      <div class="chart" id="memSpark"></div>
      <div class="kv"><span>استفاده‌شده</span><span class="num" id="memUsed">—</span></div>
      <div class="kv"><span>آزاد</span><span class="num" id="memFree">—</span></div>
      <div class="kv"><span>کل</span><span class="num" id="memTotal">—</span></div>
      <h2 class="sub">حافظه مبادله (Swap)</h2>
      <div class="big sm num" id="swapPct">—</div>
      <div id="swapBar"></div>
      <div class="kv"><span>استفاده‌شده</span><span class="num" id="swapUsed">—</span></div>
      <div class="kv"><span>آزاد</span><span class="num" id="swapFree">—</span></div>
      <div class="kv"><span>کل</span><span class="num" id="swapTotal">—</span></div>
    </section>

    <section class="card">
      <h2>شبکه</h2>
      <div class="kv strong"><span>دریافت (دانلود)</span><span class="big sm num" id="netDown">—</span></div>
      <div class="kv strong"><span>ارسال (آپلود)</span><span class="big sm num" id="netUp">—</span></div>
      <div class="chart" id="netSpark"></div>
      <div class="legend"><span><i class="c0"></i>دریافت</span><span><i class="c1"></i>ارسال</span></div>
      <div class="kv"><span>مجموع دریافت‌شده از زمان بوت</span><span class="num" id="netRx">—</span></div>
      <div class="kv"><span>مجموع ارسال‌شده از زمان بوت</span><span class="num" id="netTx">—</span></div>
      <div class="kv"><span>اتصال‌های فعال</span><span class="num" id="netConn">—</span></div>
    </section>

    <section class="card">
      <h2>دیسک‌ها</h2>
      <div class="kv strong"><span>سرعت خواندن</span><span class="num" id="ioRead">—</span></div>
      <div class="kv strong"><span>سرعت نوشتن</span><span class="num" id="ioWrite">—</span></div>
      <div class="chart" id="ioSpark"></div>
      <div class="legend"><span><i class="c0"></i>خواندن</span><span><i class="c1"></i>نوشتن</span></div>
      <div id="disks"></div>
    </section>

    <section class="card">
      <h2>سیستم</h2>
      <div class="kv"><span>نام میزبان</span><span class="num" id="sysHost">—</span></div>
      <div class="kv"><span>سیستم‌عامل</span><span class="num" id="sysOs">—</span></div>
      <div class="kv"><span>هسته (Kernel)</span><span class="num" id="sysKernel">—</span></div>
      <div class="kv"><span>زمان روشن بودن</span><span id="sysUptime">—</span></div>
      <div class="kv"><span>کاربران واردشده</span><span class="num" id="sysUsers">—</span></div>
    </section>

    <section class="card">
      <h2>پرمصرف‌ترین پردازه‌ها (CPU)</h2>
      <table class="tbl">
        <thead><tr><th>پردازه</th><th>PID</th><th>CPU</th><th>RAM</th></tr></thead>
        <tbody id="topCpu"></tbody>
      </table>
    </section>

    <section class="card">
      <h2>پرمصرف‌ترین پردازه‌ها (RAM)</h2>
      <table class="tbl">
        <thead><tr><th>پردازه</th><th>PID</th><th>CPU</th><th>RAM</th></tr></thead>
        <tbody id="topMem"></tbody>
      </table>
    </section>

  </div>
</div>
<script nonce="{{ nonce }}">{{ js|safe }}</script>
</body>
</html>"""

DASH_JS = r"""
(function () {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  var HIST = 60;

  function $(id) { return document.getElementById(id); }
  function set(id, text) { var e = $(id); if (e) { e.textContent = text; } }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = text; }
    return e;
  }
  function svgEl(tag, attrs) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) {
      if (Object.prototype.hasOwnProperty.call(attrs, k)) { e.setAttribute(k, attrs[k]); }
    }
    return e;
  }

  function fmtBytes(n) {
    if (n === null || n === undefined || isNaN(n)) { return '—'; }
    var u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(n >= 100 ? 0 : (n >= 10 ? 1 : 2))) + ' ' + u[i];
  }
  function fmtSpeed(n) { return fmtBytes(n) + '/s'; }
  function fmtPct(p) { return Number(p).toFixed(1) + '%'; }
  function fmtUptime(s) {
    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    var parts = [];
    if (d) { parts.push(d + ' روز'); }
    if (h || d) { parts.push(h + ' ساعت'); }
    parts.push(m + ' دقیقه');
    return parts.join('، ');
  }

  function level(p) { return p >= 85 ? 'bad' : (p >= 60 ? 'warn' : 'ok'); }

  // Horizontal usage bar drawn with SVG; it fills from the right (RTL).
  function barEl(pct) {
    var p = Math.max(0, Math.min(100, Number(pct) || 0));
    var svg = svgEl('svg', { 'class': 'bar', viewBox: '0 0 100 8', preserveAspectRatio: 'none' });
    svg.appendChild(svgEl('rect', { 'class': 'bg', x: 0, y: 0, width: 100, height: 8 }));
    svg.appendChild(svgEl('rect', { 'class': 'fill ' + level(p), x: (100 - p).toFixed(1), y: 0, width: p.toFixed(1), height: 8 }));
    return svg;
  }
  function setBar(id, pct) {
    var box = $(id);
    clear(box);
    box.appendChild(barEl(pct));
  }

  // Small history chart drawn with SVG polylines.
  function makeSpark(containerId, seriesCount) {
    var box = $(containerId);
    var svg = svgEl('svg', { 'class': 'spark', viewBox: '0 0 120 40', preserveAspectRatio: 'none' });
    var lines = [], hist = [], i;
    for (i = 0; i < seriesCount; i++) {
      var pl = svgEl('polyline', { 'class': 'line s' + i, fill: 'none', points: '' });
      svg.appendChild(pl);
      lines.push(pl);
      hist.push([]);
    }
    box.appendChild(svg);
    return function (values, fixedMax) {
      var max = fixedMax || 0, a, j, h, pts, x, y;
      for (a = 0; a < seriesCount; a++) {
        h = hist[a];
        h.push(Number(values[a]) || 0);
        if (h.length > HIST) { h.shift(); }
        if (!fixedMax) {
          for (j = 0; j < h.length; j++) { if (h[j] > max) { max = h[j]; } }
        }
      }
      if (!max) { max = 1; }
      for (a = 0; a < seriesCount; a++) {
        h = hist[a];
        pts = [];
        for (j = 0; j < h.length; j++) {
          x = ((j + (HIST - h.length)) / (HIST - 1)) * 120;
          y = 38 - (h[j] / max) * 36;
          pts.push(x.toFixed(1) + ',' + y.toFixed(1));
        }
        lines[a].setAttribute('points', pts.join(' '));
      }
    };
  }

  var sparks = {
    cpu: makeSpark('cpuSpark', 1),
    mem: makeSpark('memSpark', 1),
    net: makeSpark('netSpark', 2),
    io: makeSpark('ioSpark', 2)
  };

  function renderCores(list) {
    var box = $('cores'), i, c, row;
    clear(box);
    for (i = 0; i < list.length; i++) {
      c = el('div', 'core');
      row = el('div', 'row');
      row.appendChild(el('span', 'mute', 'هسته ' + (i + 1)));
      row.appendChild(el('span', 'num', list[i].toFixed(0) + '%'));
      c.appendChild(row);
      c.appendChild(barEl(list[i]));
      box.appendChild(c);
    }
  }

  function renderDisks(list) {
    var box = $('disks'), i, d, wrap, head;
    clear(box);
    if (!list.length) {
      box.appendChild(el('div', 'mute', 'فایل‌سیستمی یافت نشد.'));
      return;
    }
    for (i = 0; i < list.length; i++) {
      d = list[i];
      wrap = el('div', 'disk');
      head = el('div', 'kv strong');
      head.appendChild(el('span', 'num', d.mount + ' (' + d.fstype + ')'));
      head.appendChild(el('span', 'num', fmtBytes(d.used) + ' / ' + fmtBytes(d.total) + '  ·  ' + d.percent.toFixed(1) + '%'));
      wrap.appendChild(head);
      wrap.appendChild(barEl(d.percent));
      box.appendChild(wrap);
    }
  }

  function renderProcs(id, list) {
    var tb = $(id), i, p, tr;
    clear(tb);
    for (i = 0; i < list.length; i++) {
      p = list[i];
      tr = el('tr');
      tr.appendChild(el('td', 'name', p.name));
      tr.appendChild(el('td', 'ltr', String(p.pid)));
      tr.appendChild(el('td', 'ltr', p.cpu.toFixed(1) + '%'));
      tr.appendChild(el('td', 'ltr', fmtBytes(p.rss) + ' (' + p.mem.toFixed(1) + '%)'));
      tb.appendChild(tr);
    }
  }

  function setLive(ok) {
    $('live').className = ok ? 'dot on' : 'dot';
    set('liveText', ok ? 'زنده (هر ۲ ثانیه)' : 'قطع ارتباط…');
  }

  function render(d) {
    var c = d.cpu, m = d.mem, s = d.swap, n = d.net, io = d.disk_io, sy = d.system;
    set('hostName', sy.hostname);

    set('cpuTotal', fmtPct(c.total));
    setBar('cpuBar', c.total);
    sparks.cpu([c.total], 100);
    set('loadAvg', c.load.map(function (x) { return x.toFixed(2); }).join(' · '));
    set('cpuTemp', (c.temp === null || c.temp === undefined) ? '—' : c.temp.toFixed(1) + ' °C');
    set('cpuCount', String(c.cores));
    renderCores(c.per_core);

    set('memPct', fmtPct(m.percent));
    setBar('memBar', m.percent);
    sparks.mem([m.percent], 100);
    set('memUsed', fmtBytes(m.used));
    set('memFree', fmtBytes(m.free));
    set('memTotal', fmtBytes(m.total));

    set('swapPct', s.total ? fmtPct(s.percent) : '—');
    setBar('swapBar', s.total ? s.percent : 0);
    set('swapUsed', fmtBytes(s.used));
    set('swapFree', fmtBytes(s.free));
    set('swapTotal', fmtBytes(s.total));

    set('netDown', fmtSpeed(n.down_speed));
    set('netUp', fmtSpeed(n.up_speed));
    sparks.net([n.down_speed, n.up_speed]);
    set('netRx', fmtBytes(n.bytes_recv));
    set('netTx', fmtBytes(n.bytes_sent));
    set('netConn', String(n.connections));

    set('ioRead', fmtSpeed(io.read_speed));
    set('ioWrite', fmtSpeed(io.write_speed));
    sparks.io([io.read_speed, io.write_speed]);
    renderDisks(d.disks);

    set('sysHost', sy.hostname);
    set('sysOs', sy.os);
    set('sysKernel', sy.kernel);
    set('sysUptime', fmtUptime(sy.uptime));
    set('sysUsers', String(sy.users));

    renderProcs('topCpu', d.top_cpu);
    renderProcs('topMem', d.top_mem);
  }

  function poll() {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, 6000);
    fetch('/api/stats', {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: ctl.signal,
      headers: { 'Accept': 'application/json' }
    }).then(function (r) {
      clearTimeout(timer);
      if (r.status === 401) { location.href = '/login'; return null; }
      if (r.status === 403) { location.href = '/change-password'; return null; }
      if (!r.ok) { throw new Error('http ' + r.status); }
      return r.json();
    }).then(function (d) {
      if (d) { render(d); setLive(true); }
    }).catch(function () {
      clearTimeout(timer);
      setLive(false);
    }).then(function () {
      setTimeout(poll, 2000);
    });
  }

  poll();
})();
"""


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    return session["csrf"]


def csrf_ok():
    expected = session.get("csrf", "")
    given = request.form.get("csrf_token", "")
    return bool(expected) and hmac.compare_digest(expected.encode("utf-8"), given.encode("utf-8"))


def client_ip():
    return request.remote_addr or "unknown"


def render(tpl, **ctx):
    return render_template_string(tpl, css=CSS, nonce=g.nonce, csrf=csrf_token(), **ctx)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            if request.path.startswith("/api/"):
                return jsonify(error="unauthorized"), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def guard():
    g.nonce = secrets.token_urlsafe(16)
    try:
        g.cfg = load_config()
    except (OSError, ValueError):
        return "Configuration unavailable.", 500
    if session.get("auth"):
        if session.get("pwv") != pw_fingerprint(g.cfg):
            # Password was changed or reset elsewhere: drop this session.
            session.clear()
        elif g.cfg.get("must_change") and request.endpoint not in ("change_password", "logout"):
            if request.path.startswith("/api/"):
                return jsonify(error="password_change_required"), 403
            return redirect(url_for("change_password"))
    return None


@app.after_request
def security_headers(resp):
    nonce = getattr(g, "nonce", "")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'nonce-%s'; style-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'" % nonce
    )
    return resp


@app.errorhandler(400)
def bad_request(_err):
    return ('<!doctype html><meta charset="utf-8"><body dir="rtl">'
            'درخواست نامعتبر است. <a href="/login">بازگشت</a></body>'), 400


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        if not csrf_ok():
            abort(400)
        ip = client_ip()
        wait = rl_remaining(ip)
        if wait:
            error = lock_message(wait)
        else:
            password = request.form.get("password", "")
            if check_password_hash(g.cfg["password_hash"], password):
                rl_reset(ip)
                session.clear()
                session["auth"] = True
                session["pwv"] = pw_fingerprint(g.cfg)
                session["csrf"] = secrets.token_hex(32)
                session.permanent = True
                if g.cfg.get("must_change"):
                    return redirect(url_for("change_password"))
                return redirect(url_for("index"))
            rl_fail(ip)
            wait = rl_remaining(ip)
            error = lock_message(wait) if wait else "رمز عبور نادرست است."
    return render(LOGIN_TPL, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    if not csrf_ok():
        abort(400)
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    error = None
    if request.method == "POST":
        if not csrf_ok():
            abort(400)
        ip = client_ip()
        wait = rl_remaining(ip)
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if wait:
            error = lock_message(wait)
        elif not check_password_hash(g.cfg["password_hash"], current):
            rl_fail(ip)
            error = "رمز عبور فعلی نادرست است."
        elif len(new) < MIN_PASSWORD_LEN:
            error = "رمز عبور جدید باید حداقل ۸ نویسه باشد."
        elif new != confirm:
            error = "تکرار رمز عبور جدید با رمز جدید یکسان نیست."
        elif new == current:
            error = "رمز عبور جدید باید با رمز فعلی متفاوت باشد."
        else:
            cfg = dict(g.cfg)
            cfg["password_hash"] = generate_password_hash(new, method="scrypt")
            cfg["must_change"] = False
            save_config(cfg)
            rl_reset(ip)
            session["pwv"] = pw_fingerprint(cfg)
            session["csrf"] = secrets.token_hex(32)
            session["notice"] = "رمز عبور با موفقیت تغییر کرد."
            return redirect(url_for("index"))
    return render(CHANGE_TPL, error=error, forced=bool(g.cfg.get("must_change")))


@app.route("/")
@login_required
def index():
    notice = session.pop("notice", None)
    return render(DASH_TPL, notice=notice, js=DASH_JS)


@app.route("/api/stats")
@login_required
def api_stats():
    with _state_lock:
        data = _state["data"]
    if data is None:
        return jsonify(error="warming_up"), 503
    return jsonify(data)


# --------------------------------------------------------------------------
# Command line helpers (used by the installer and the `srvpanel` command)
# --------------------------------------------------------------------------


def cmd_reset_password(raw):
    try:
        cfg = load_config()
    except FileNotFoundError:
        cfg = {}
    password = generate_password()
    cfg["password_hash"] = generate_password_hash(password, method="scrypt")
    cfg["must_change"] = True
    cfg.setdefault("secret_key", secrets.token_hex(32))
    save_config(cfg)
    if raw:
        print(password)
    else:
        print("")
        print("=" * 56)
        print("  New one-time password:  " + password)
        if cfg.get("port"):
            print("  Panel port:             %s" % cfg["port"])
        print("  You must set a new password at the first login.")
        print("=" * 56)
        print("")
    return 0


def cmd_set_port(port):
    cfg = load_config()
    cfg["port"] = int(port)
    save_config(cfg)
    return 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    try:
        if cmd == "reset-password":
            return cmd_reset_password("--raw" in argv[2:])
        if cmd == "set-port" and len(argv) == 3 and argv[2].isdigit():
            return cmd_set_port(argv[2])
    except (OSError, ValueError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    print("Usage: srvpanel reset-password", file=sys.stderr)
    return 2


def _boot():
    app.secret_key = load_config()["secret_key"]
    threading.Thread(target=_sampler, name="sampler", daemon=True).start()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
else:
    _boot()
PANEL_PY_EOF
  chmod 644 "${APP_DIR}/panel.py"

  cat > "$CLI_FILE" <<'CLI_EOF'
#!/usr/bin/env bash
# srvpanel command line helper: srvpanel reset-password
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "srvpanel: please run as root." >&2
  exit 1
fi
exec /opt/srvpanel/venv/bin/python /opt/srvpanel/panel.py "$@"
CLI_EOF
  chmod 755 "$CLI_FILE"
}

setup_venv() {
  log "Creating Python virtual environment..."
  if [ ! -x "$PY" ]; then
    python3 -m venv "${APP_DIR}/venv"
  fi
  log "Installing Python packages (Flask, psutil, gunicorn)..."
  "${APP_DIR}/venv/bin/pip" install --quiet --disable-pip-version-check flask psutil gunicorn
  "$PY" -m py_compile "${APP_DIR}/panel.py"
}

ensure_tls() {
  if [ -s "$CERT_FILE" ] && [ -s "$KEY_FILE" ]; then
    return 0
  fi
  log "Generating self-signed TLS certificate..."
  local san="DNS:localhost"
  if is_ipv4 "$SERVER_IP"; then
    san="${san},IP:${SERVER_IP}"
  fi
  if ! openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
      -keyout "$KEY_FILE" -out "$CERT_FILE" \
      -subj "/CN=srvpanel" -addext "subjectAltName=${san}" 2>/dev/null; then
    die "Failed to generate the TLS certificate."
  fi
  chown "${SERVICE_USER}:${SERVICE_USER}" "$KEY_FILE" "$CERT_FILE"
  chmod 600 "$KEY_FILE"
  chmod 644 "$CERT_FILE"
}

choose_port() {
  local existing=""
  if [ -f "$CONF_FILE" ]; then
    existing="$(read_config_port)"
  fi
  if ! is_port "$existing"; then
    existing=""
  fi

  # The service is stopped here, so a port that is still busy belongs to someone else.
  if [ -n "${PANEL_PORT:-}" ]; then
    is_port "$PANEL_PORT" || die "PANEL_PORT must be a number between 1 and 65535."
    PORT="$PANEL_PORT"
    if port_in_use "$PORT"; then
      die "Port ${PORT} is already in use by another process."
    fi
  elif [ -n "$existing" ]; then
    PORT="$existing"
    if port_in_use "$PORT"; then
      die "Port ${PORT} is already in use by another process. Re-run with PANEL_PORT=<new port>."
    fi
  else
    PORT="$(pick_port)"
  fi

  if [ -n "$existing" ] && [ "$existing" != "$PORT" ]; then
    close_firewall "$existing"
  fi
}

init_config() {
  if [ ! -s "$CONF_FILE" ]; then
    NEW_PASSWORD="$("$PY" "${APP_DIR}/panel.py" reset-password --raw)"
  fi
  "$PY" "${APP_DIR}/panel.py" set-port "$PORT"
  chown "${SERVICE_USER}:${SERVICE_USER}" "$CONF_FILE"
  chmod 600 "$CONF_FILE"
}

write_unit() {
  cat > "$SERVICE_FILE" <<UNIT_EOF
[Unit]
Description=Server resource panel (srvpanel)
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/gunicorn --chdir ${APP_DIR} --worker-class gthread --workers 1 --threads 4 --timeout 30 --bind 0.0.0.0:${PORT} --certfile ${CERT_FILE} --keyfile ${KEY_FILE} panel:app
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT_EOF
  chmod 644 "$SERVICE_FILE"
}

wait_for_panel() {
  local code=""
  for _ in $(seq 1 20); do
    code="$(curl -ks -o /dev/null -w '%{http_code}' --max-time 3 "https://127.0.0.1:${PORT}/login" || true)"
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep 1
  done
  journalctl -u "${APP_NAME}.service" -n 30 --no-pager >&2 || true
  die "The panel did not start correctly."
}

print_summary() {
  local bold="" green="" reset=""
  if [ -t 1 ]; then
    bold=$'\033[1m'
    green=$'\033[1;32m'
    reset=$'\033[0m'
  fi
  echo
  printf '%s\n' "${green}==============================================================${reset}"
  printf '%s\n' "${green}  Server panel is ready${reset}"
  printf '%s\n' "${green}==============================================================${reset}"
  printf '  %sPanel URL%s : https://%s:%s/\n' "$bold" "$reset" "$SERVER_IP" "$PORT"
  if [ -n "$NEW_PASSWORD" ]; then
    printf '  %sPassword%s  : %s%s%s\n' "$bold" "$reset" "$green" "$NEW_PASSWORD" "$reset"
    echo
    echo "  This one-time password is shown ONLY NOW and is not stored."
    echo "  You will be asked to set a new password at the first login."
  else
    printf '  %sPassword%s  : (unchanged - existing password kept)\n' "$bold" "$reset"
    echo
    echo "  Forgot it? Run:  srvpanel reset-password"
  fi
  echo "  The browser will warn about the self-signed certificate: accept it."
  printf '%s\n' "${green}==============================================================${reset}"
  echo
}

install_panel() {
  install_packages
  ensure_user_and_dirs
  write_app_files
  setup_venv
  SERVER_IP="$(get_public_ip)"
  ensure_tls

  systemctl stop "${APP_NAME}.service" >/dev/null 2>&1 || true
  choose_port
  init_config
  write_unit
  open_firewall "$PORT"

  systemctl daemon-reload
  systemctl enable "${APP_NAME}.service" >/dev/null 2>&1
  systemctl restart "${APP_NAME}.service"
  wait_for_panel
  systemctl is-active --quiet "${APP_NAME}.service" || die "The ${APP_NAME} service is not active."
  print_summary
}

main() {
  require_root
  require_ubuntu_2404
  case "${1:-install}" in
    install) install_panel ;;
    uninstall) uninstall_panel ;;
    *) die "Usage: bash install.sh [install|uninstall]" ;;
  esac
}

main "$@"
