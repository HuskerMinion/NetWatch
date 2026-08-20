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

Usage
-----
    python3 netwatch_agent.py --server 192.168.34.50 --token SECRET

    --server    IP or hostname of the machine running NetWatch (required)
    --port      NetWatch port (default 8339)
    --token     must match "agent_token" in netwatch.conf (required)
    --interval  seconds between reports (default 15)
    --once      send a single report and exit (useful for testing)

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

def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                              shell=False).stdout
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


def main():
    ap = argparse.ArgumentParser(
        description="Report this machine's socket->process table to NetWatch.")
    ap.add_argument("--server", required=True, help="NetWatch host/IP")
    ap.add_argument("--port", type=int, default=8339)
    ap.add_argument("--token", required=True,
                    help="must match agent_token in netwatch.conf")
    ap.add_argument("--interval", type=float, default=15.0)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

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
            return
        try:
            time.sleep(max(3.0, args.interval))
        except KeyboardInterrupt:
            print("\nagent stopped.")
            return


if __name__ == "__main__":
    main()
