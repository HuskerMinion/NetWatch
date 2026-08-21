#!/usr/bin/env python3
"""
NetWatch agent — reports which PROCESS owns each outbound connection.

Why this exists
---------------
NetWatch watches a mirrored switch port, so it sees every device on the LAN but
can never see which *program* opened a socket — that information only exists on
the machine itself. Run this agent on a PC you care about and NetWatch will
label that machine's flows with process names, while every other device on the
network keeps working exactly as before.

It is deliberately small: pure Python 3 standard library, no installs, no
listening socket, no admin rights needed for its own connections (see the note
on other users' processes below). It only ever sends outward, to the NetWatch
box you point it at.

What it sends
-------------
For each established connection to a PUBLIC address:

    {"rem": "140.82.121.4", "port": 443, "proc": "chrome.exe", "pid": 8123}

plus the machine's hostname and OS. Nothing else — no local addresses, no LAN
traffic, no command lines, no arguments, no file paths.

Deploying it on a machine
-------------------------
One command. It tests the connection first, saves the settings, and only then
registers itself to start automatically:

    python netwatch_agent.py --install --server 192.168.34.76 --token SECRET

If the token is wrong or NetWatch is unreachable you find out immediately,
instead of it silently doing nothing at every logon. Afterwards:

    python netwatch_agent.py --status      show settings + autostart + test
    python netwatch_agent.py --uninstall   remove autostart (settings kept)
    python netwatch_agent.py               run in the foreground
    python netwatch_agent.py --once        send one report and exit

Autostart is per-user and needs no administrator rights:
  Windows   a Scheduled Task ("NetWatch Agent") running at logon via pythonw,
            so no console window ever appears. Creating that task is a
            privileged operation on many machines; if it is refused with
            "Access is denied" the agent falls back to the per-user Run key
            (HKCU\...\CurrentVersion\Run), which needs no admin and behaves
            the same. Either way --status says which one is in use.
  Linux     a systemd *user* service. For it to run without you being logged
            in:  sudo loginctl enable-linger $USER
  macOS     a LaunchAgent in ~/Library/LaunchAgents.

Settings are stored in netwatch_agent.conf beside this script (chmod 600 where
the OS supports it) rather than on the command line, so the token is not on
display in Task Scheduler or `ps`.

On the NetWatch side, add to netwatch.conf:

    {"agent_token": "SECRET"}

and restart NetWatch. Without that key the /agent endpoint refuses everything,
so an unconfigured NetWatch cannot be fed data by anyone.

Platform notes
--------------
  Linux    reads /proc/net/tcp* and matches socket inodes to /proc/<pid>/fd.
           Sockets owned by OTHER users are only attributable when run as root;
           without root you still get your own processes.
  Windows  shells out to `netstat -ano` and `tasklist`. No admin needed.
  macOS    uses `lsof -i -nP`. No admin needed for your own processes.

MIT © 2026 huskerminion
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 10


# ---------------------------------------------------------------------------
# Address helpers
# ---------------------------------------------------------------------------

def _is_public(ip):
    """True for a globally routable address. Kept dependency-free and
    deliberately conservative — anything we can't parse is treated as private
    and therefore never reported."""
    if not ip:
        return False
    if ":" in ip:                                  # IPv6
        low = ip.lower()
        if low in ("::", "::1") or low.startswith(("fe80", "fc", "fd", "ff")):
            return False
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a in (0, 10, 127):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:                # CGNAT / Tailscale
        return False
    if a >= 224:                                   # multicast + reserved
        return False
    return True


# ---------------------------------------------------------------------------
# Linux: /proc/net/tcp + /proc/<pid>/fd
# ---------------------------------------------------------------------------

def _hex_to_ip(h):
    if len(h) == 8:                                # IPv4, little-endian hex
        b = bytes.fromhex(h)
        return "%d.%d.%d.%d" % (b[3], b[2], b[1], b[0])
    if len(h) == 32:                               # IPv6, 4 little-endian words
        words = [h[i:i + 8] for i in range(0, 32, 8)]
        raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        return socket.inet_ntop(socket.AF_INET6, raw)
    return ""


def _linux_sockets():
    """[(remote_ip, remote_port, inode)] for established connections."""
    out = []
    for name in ("tcp", "tcp6", "udp", "udp6"):
        path = "/proc/net/" + name
        try:
            with open(path) as fh:
                next(fh, None)                     # header
                for line in fh:
                    f = line.split()
                    if len(f) < 10:
                        continue
                    rem = f[2]
                    if ":" not in rem:
                        continue
                    ip_h, port_h = rem.rsplit(":", 1)
                    ip = _hex_to_ip(ip_h)
                    try:
                        port = int(port_h, 16)
                    except ValueError:
                        continue
                    if not port or not _is_public(ip):
                        continue
                    out.append((ip, port, f[9]))
        except (OSError, StopIteration):
            continue
    return out


def _linux_inode_map():
    """socket inode -> process name, for every process we're allowed to read."""
    m = {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return m
    for pid in pids:
        fd_dir = "/proc/%s/fd" % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue                               # not ours / already gone
        name = None
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            if name is None:
                try:
                    with open("/proc/%s/comm" % pid) as fh:
                        name = fh.read().strip()
                except OSError:
                    name = "pid " + pid
            m[target[8:-1]] = (name, int(pid))
    return m


def collect_linux():
    inodes = _linux_inode_map()
    conns = []
    for ip, port, inode in _linux_sockets():
        hit = inodes.get(inode)
        if not hit:
            continue                               # owned by another user
        conns.append({"rem": ip, "port": port, "proc": hit[0], "pid": hit[1]})
    return conns


# ---------------------------------------------------------------------------
# Windows: netstat -ano + tasklist
# ---------------------------------------------------------------------------

# On Windows, spawning netstat/tasklist normally flashes a console window each
# time. That is invisible when you run the agent in a terminal, but running it
# in the background (pythonw, Task Scheduler) would blink a window every cycle.
_NO_WINDOW = (getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
              if sys.platform.startswith("win") else 0)


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                              shell=False, creationflags=_NO_WINDOW).stdout
    except Exception:
        return ""


def _windows_pid_names():
    names = {}
    for line in _run(["tasklist", "/fo", "csv", "/nh"]).splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) < 2:
            continue
        try:
            names[int(parts[1])] = parts[0].lstrip('"')
        except ValueError:
            continue
    return names


def collect_windows():
    names = _windows_pid_names()
    conns = []
    for line in _run(["netstat", "-ano"]).splitlines():
        f = line.split()
        if len(f) < 4 or f[0] not in ("TCP", "UDP"):
            continue
        remote, pid_s = f[2], f[-1]
        if remote.startswith("["):                 # [::ffff:1.2.3.4]:443
            ip, _, port_s = remote.rpartition("]:")
            ip = ip.lstrip("[")
        else:
            ip, _, port_s = remote.rpartition(":")
        try:
            port, pid = int(port_s), int(pid_s)
        except ValueError:
            continue
        if not _is_public(ip):
            continue
        conns.append({"rem": ip, "port": port,
                      "proc": names.get(pid, "pid %d" % pid), "pid": pid})
    return conns


# ---------------------------------------------------------------------------
# macOS: lsof
# ---------------------------------------------------------------------------

def collect_macos():
    conns = []
    for line in _run(["lsof", "-i", "-nP"]).splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        name, pid_s, endpoint = f[0], f[1], f[8]
        if "->" not in endpoint:
            continue
        remote = endpoint.split("->")[1]
        if remote.startswith("["):
            ip, _, port_s = remote.rpartition("]:")
            ip = ip.lstrip("[")
        else:
            ip, _, port_s = remote.rpartition(":")
        try:
            port, pid = int(port_s), int(pid_s)
        except ValueError:
            continue
        if not _is_public(ip):
            continue
        conns.append({"rem": ip, "port": port, "proc": name, "pid": pid})
    return conns


def collect():
    plat = sys.platform
    if plat.startswith("linux"):
        return collect_linux()
    if plat.startswith("win"):
        return collect_windows()
    if plat == "darwin":
        return collect_macos()
    raise SystemExit("unsupported platform: %s" % plat)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def dedupe(conns, limit=2000):
    """One entry per (remote, port, process) — a browser with 40 sockets to one
    CDN should cost one line, not forty."""
    seen = {}
    for c in conns:
        seen[(c["rem"], c["port"], c["proc"])] = c
    return list(seen.values())[:limit]


def send(server, port, token, conns, verbose=False):
    payload = json.dumps({"host": socket.gethostname(),
                          "os": platform.system(),
                          "conns": conns}).encode("utf-8")
    url = "http://%s:%d/agent" % (server, port)
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-NetWatch", "1")              # CSRF guard NetWatch requires
    req.add_header("X-NetWatch-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
        if verbose:
            print("sent %d mapping(s); NetWatch accepted %d as device %s"
                  % (len(conns), body.get("accepted", 0), body.get("dev", "?")))
        return True
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        print("NetWatch refused the report (HTTP %d): %s" % (e.code, detail),
              file=sys.stderr)
    except Exception as e:
        print("could not reach NetWatch at %s (%s)" % (url, e), file=sys.stderr)
    return False


# ---------------------------------------------------------------------------
# Configuration file
# ---------------------------------------------------------------------------
# Settings live beside the script so the token is not sitting in a command line
# (visible in Task Scheduler, `ps`, and to anything reading process arguments),
# and so the server or token can be changed later without re-registering the
# autostart entry.

CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "netwatch_agent.conf")


def load_conf():
    try:
        with open(CONF_FILE, encoding="utf-8") as fh:
            c = json.load(fh)
        return c if isinstance(c, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        print("could not read %s (%s); ignoring it" % (CONF_FILE, e),
              file=sys.stderr)
        return {}


def save_conf(conf):
    tmp = CONF_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(conf, fh, indent=2, sort_keys=True)
    os.replace(tmp, CONF_FILE)
    try:                              # the token is in here: owner-only on POSIX
        os.chmod(CONF_FILE, 0o600)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Autostart registration
# ---------------------------------------------------------------------------

TASK_NAME = "NetWatch Agent"
SERVICE_NAME = "netwatch-agent"


def _pythonw():
    """The windowless interpreter on Windows, so no console flashes at logon."""
    exe = sys.executable or "python"
    if os.name == "nt":
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _script():
    return os.path.abspath(__file__)


RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
_DETACHED = 0x00000008 | 0x00000200      # DETACHED_PROCESS | NEW_PROCESS_GROUP


def _launch_detached():
    """Start the agent now, with no console and no parent to outlive."""
    try:
        subprocess.Popen([_pythonw(), _script()],
                         creationflags=_DETACHED if os.name == "nt" else 0,
                         close_fds=True)
        return True
    except Exception:
        return False


def _reg_install():
    """Per-user Run key. Needs no administrator rights, which is the point:
    schtasks /Create registers a logon trigger and Windows treats that as
    privileged on many machines, so a normal user gets 'Access is denied'."""
    val = '"%s" "%s"' % (_pythonw(), _script())
    r = subprocess.run(["reg", "add", RUN_KEY, "/v", TASK_NAME, "/t", "REG_SZ",
                        "/d", val, "/f"],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def _reg_present():
    r = subprocess.run(["reg", "query", RUN_KEY, "/v", TASK_NAME],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
    return r.returncode == 0


def _task_present():
    r = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
    return r.returncode == 0


def install_windows():
    cmd = '"%s" "%s"' % (_pythonw(), _script())
    r = subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME, "/TR", cmd,
                        "/SC", "ONLOGON", "/F"],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
    if r.returncode == 0:
        # Only one autostart mechanism at a time. A machine that once fell back
        # to the Run key and later gets an elevated install would otherwise run
        # two agents in parallel — harmless (the reports are identical) but
        # pointless, and confusing when --status lists both.
        if _reg_present():
            subprocess.run(["reg", "delete", RUN_KEY, "/v", TASK_NAME, "/f"],
                           capture_output=True, text=True,
                           creationflags=_NO_WINDOW)
        # An ONLOGON task does not run when created, so start it now too —
        # otherwise the agent idles until the next logon and the process badge
        # quietly expires 15 minutes after the install-time test report.
        run = subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME],
                             capture_output=True, text=True,
                             creationflags=_NO_WINDOW)
        started = run.returncode == 0 or _launch_detached()
        return True, ("registered scheduled task %r — starts at every logon.\n"
                      "  %s" % (TASK_NAME,
                                "Started it now, so it is already reporting."
                                if started else
                                "Start it with:  schtasks /Run /TN \"%s\""
                                % TASK_NAME))

    # Scheduled task refused (usually "Access is denied" — that call wants
    # elevation). Fall back to the per-user Run key, which does not.
    task_err = (r.stderr or r.stdout).strip()
    if _task_present():        # a task from an earlier elevated install
        subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                       capture_output=True, text=True, creationflags=_NO_WINDOW)
    ok, err = _reg_install()
    if not ok:
        return False, ("scheduled task failed (%s) and the per-user Run key "
                       "also failed (%s)" % (task_err, err))
    started = _launch_detached()
    return True, ("scheduled task needed admin (%s),\n"
                  "  so it was registered under the per-user Run key instead — "
                  "starts at every logon, no admin needed.\n"
                  "  %s" % (task_err,
                           "Started it now, so it is already reporting."
                           if started else
                           "It will start at your next logon."))


def uninstall_windows():
    done = []
    if _task_present():
        r = subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                           capture_output=True, text=True,
                           creationflags=_NO_WINDOW)
        done.append("scheduled task removed" if r.returncode == 0
                    else "scheduled task NOT removed (%s)"
                         % (r.stderr or r.stdout).strip())
    if _reg_present():
        r = subprocess.run(["reg", "delete", RUN_KEY, "/v", TASK_NAME, "/f"],
                           capture_output=True, text=True,
                           creationflags=_NO_WINDOW)
        done.append("Run key removed" if r.returncode == 0
                    else "Run key NOT removed (%s)" % (r.stderr or r.stdout).strip())
    return True, ("; ".join(done) if done else "nothing was registered")


UNIT = """[Unit]
Description=NetWatch agent (reports socket->process mappings)
After=network-online.target

[Service]
ExecStart=%s %s
Restart=always
RestartSec=20

[Install]
WantedBy=default.target
"""


def install_systemd():
    d = os.path.expanduser("~/.config/systemd/user")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, SERVICE_NAME + ".service")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(UNIT % (sys.executable or "/usr/bin/python3", _script()))
    for cmd in (["systemctl", "--user", "daemon-reload"],
                ["systemctl", "--user", "enable", "--now", SERVICE_NAME]):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return False, "%s failed: %s" % (" ".join(cmd),
                                             (r.stderr or r.stdout).strip())
    return True, ("installed user service %r.\n"
                  "  Logs:  journalctl --user -u %s -f\n"
                  "  To keep it running when you are logged out:  "
                  "sudo loginctl enable-linger %s"
                  % (SERVICE_NAME, SERVICE_NAME, os.environ.get("USER", "$USER")))


def uninstall_systemd():
    subprocess.run(["systemctl", "--user", "disable", "--now", SERVICE_NAME],
                   capture_output=True, text=True)
    path = os.path.expanduser("~/.config/systemd/user/%s.service" % SERVICE_NAME)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    subprocess.run(["systemctl", "--user", "daemon-reload"],
                   capture_output=True, text=True)
    return True, "removed user service"


PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.huskerminion.netwatch-agent</string>
  <key>ProgramArguments</key><array><string>%s</string><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
"""


def _plist_path():
    return os.path.expanduser(
        "~/Library/LaunchAgents/com.huskerminion.netwatch-agent.plist")


def install_launchd():
    path = _plist_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(PLIST % (sys.executable or "/usr/bin/python3", _script()))
    subprocess.run(["launchctl", "unload", path], capture_output=True, text=True)
    r = subprocess.run(["launchctl", "load", path], capture_output=True, text=True)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()
    return True, "installed LaunchAgent — starts at login"


def uninstall_launchd():
    path = _plist_path()
    subprocess.run(["launchctl", "unload", path], capture_output=True, text=True)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return True, "removed LaunchAgent"


def autostart(action):
    """action is 'install' or 'uninstall'. Returns (ok, message)."""
    table = {
        "nt": (install_windows, uninstall_windows),
        "linux": (install_systemd, uninstall_systemd),
        "darwin": (install_launchd, uninstall_launchd),
    }
    key = "nt" if os.name == "nt" else (
        "linux" if sys.platform.startswith("linux") else
        "darwin" if sys.platform == "darwin" else None)
    if key is None:
        return False, "no autostart method known for %s" % sys.platform
    fn = table[key][0 if action == "install" else 1]
    try:
        return fn()
    except FileNotFoundError as e:
        return False, "%s — is the tool available on PATH?" % e
    except Exception as e:
        return False, str(e)


def do_install(server, port, token, interval):
    """Prove the settings work, save them, then register autostart. Testing
    first matters: a wrong token or an unreachable server is far easier to
    understand now than as a silent no-op at every logon."""
    print("NetWatch agent setup")
    print("  server : %s:%d" % (server, port))
    print("  script : %s" % _script())
    print("\n1. testing the connection...")
    try:
        conns = dedupe(collect())
    except Exception as e:
        print("   FAILED to read this machine's sockets: %s" % e)
        return 1
    print("   found %d connection(s) to public addresses" % len(conns))
    if not send(server, port, token, conns, verbose=True):
        print("\n   Setup stopped — nothing was installed.")
        print("   Check that NetWatch is running, that agent_token in its")
        print("   netwatch.conf matches, and that the config file is valid JSON")
        print("   (python3 -m json.tool /opt/netwatch/netwatch.conf).")
        return 1
    print("\n2. saving settings to %s" % CONF_FILE)
    save_conf({"server": server, "port": port, "token": token,
               "interval": interval})
    print("\n3. registering autostart...")
    ok, msg = autostart("install")
    print("   " + ("" if ok else "FAILED: ") + msg)
    if not ok:
        print("\n   Settings were saved, so you can still start it by hand:")
        print("     python %s" % _script())
        return 1
    print("\nDone. This machine's flows will show process names in NetWatch.")
    print("  Check it is reporting:  python %s --status" % os.path.basename(_script()))
    print("  Or open http://%s:%d/data and look for this machine under \"agents\"."
          % (server, port))
    print("  Note: NetWatch forgets a machine's process names %d minutes after"
          % (900 // 60))
    print("  its agent stops reporting, so the badge disappearing means the")
    print("  agent stopped — not that something is misconfigured.")
    return 0


def do_status():
    c = load_conf()
    print("config file : %s" % (CONF_FILE if c else CONF_FILE + "  (missing)"))
    if c:
        print("  server    : %s:%s" % (c.get("server"), c.get("port", 8339)))
        print("  token     : %s" % ("set (%d chars)" % len(str(c.get("token", "")))
                                    if c.get("token") else "MISSING"))
        print("  interval  : %ss" % c.get("interval", 15))
    print("collector   : %s" % ("/proc" if sys.platform.startswith("linux") else
                                "netstat + tasklist" if os.name == "nt" else "lsof"))
    if os.name == "nt":
        where = []
        if _task_present():
            where.append("scheduled task")
        if _reg_present():
            where.append("per-user Run key")
        print("autostart   : %s" % (", ".join(where) if where else "not registered"))
    elif sys.platform.startswith("linux"):
        r = subprocess.run(["systemctl", "--user", "is-enabled", SERVICE_NAME],
                           capture_output=True, text=True)
        print("autostart   : %s" % (r.stdout.strip() or "not registered"))
    elif sys.platform == "darwin":
        print("autostart   : %s" % ("registered" if os.path.exists(_plist_path())
                                    else "not registered"))
    if c.get("server") and c.get("token"):
        print("\ntesting a single report...")
        try:
            send(c["server"], int(c.get("port", 8339)), c["token"],
                 dedupe(collect()), verbose=True)
        except Exception as e:
            print("  failed: %s" % e)
    return 0


def main():
    conf = load_conf()
    ap = argparse.ArgumentParser(
        description="Report this machine's socket->process table to NetWatch.",
        epilog="Typical setup on a new machine:  "
               "python netwatch_agent.py --install --server 192.168.1.50 "
               "--token YOUR-TOKEN")
    ap.add_argument("--server", default=conf.get("server"),
                    help="NetWatch host/IP (saved after --install)")
    ap.add_argument("--port", type=int, default=int(conf.get("port", 8339)))
    ap.add_argument("--token", default=conf.get("token"),
                    help="must match agent_token in netwatch.conf")
    ap.add_argument("--interval", type=float,
                    default=float(conf.get("interval", 15.0)))
    ap.add_argument("--once", action="store_true",
                    help="send one report and exit")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--install", action="store_true",
                    help="test, save settings, and start automatically at login")
    ap.add_argument("--uninstall", action="store_true",
                    help="remove the autostart entry (settings are kept)")
    ap.add_argument("--status", action="store_true",
                    help="show settings, autostart state, and test a report")
    args = ap.parse_args()

    if args.status:
        return do_status()
    if args.uninstall:
        ok, msg = autostart("uninstall")
        print(("" if ok else "FAILED: ") + msg)
        return 0 if ok else 1
    if args.install:
        if not args.server or not args.token:
            ap.error("--install needs --server and --token the first time")
        return do_install(args.server, args.port, args.token, args.interval)

    if not args.server or not args.token:
        ap.error("no settings found — run with --install --server HOST "
                 "--token TOKEN first, or pass --server/--token explicitly")

    if not args.quiet:
        print("NetWatch agent -> %s:%d every %gs (Ctrl+C to stop)"
              % (args.server, args.port, args.interval))
        if sys.platform.startswith("linux") and os.geteuid() != 0:
            print("  note: not running as root — only your own processes will "
                  "be attributed")
    while True:
        try:
            conns = dedupe(collect())
        except Exception as e:
            print("collection failed (%s)" % e, file=sys.stderr)
            conns = []
        if conns:
            send(args.server, args.port, args.token, conns,
                 verbose=not args.quiet)
        elif not args.quiet:
            print("no public connections right now")
        if args.once:
            return 0
        try:
            time.sleep(max(3.0, args.interval))
        except KeyboardInterrupt:
            print("\nagent stopped.")
            return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
