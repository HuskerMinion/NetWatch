#!/usr/bin/env python3
"""
NetWatch — a live, network-wide world map of every device's connections.

This is the "precise" companion to netmap.py. Instead of reading one computer's
sockets, it sniffs a MIRRORED switch port (SPAN/port-mirror) and sees the real
outbound connections of every device on your LAN — phones, TVs, IoT and all —
with the true remote IP, the destination port, and (for TLS-over-TCP) usually
the site's hostname pulled from the connection's SNI. It then geolocates each
remote endpoint and plots it, colored by which local device is responsible.

Designed to run on a small always-on Linux box (e.g. a Raspberry Pi) whose
wired NIC is plugged into the switch's monitor port, using a second interface
(Wi-Fi) for its normal network access. Requires root (raw packet capture).

Quick start (on the capture Pi):
    sudo python3 netwatch.py --iface eth0
    # then open http://<this-pi-ip>:8339 from any browser on your LAN

Try the UI without a mirror or root:
    python3 netwatch.py --demo

Options:
    --iface NAME     capture interface wired to the mirror port  (default eth0)
    --port N         web server port                              (default 8339)
    --host ADDR      web bind address                     (default 0.0.0.0/LAN)
    --home LAT,LON   set the map's home location manually (skips self-geolocate)
    --no-browser     never try to open a browser (default on a headless Pi)
    --demo           synthesize fake traffic to preview the UI (no root needed)

Privacy: only packet HEADERS are parsed (addresses, ports, TLS SNI hostnames).
No payloads are stored. The only data leaving the box is the set of remote IPs
sent to ip-api.com for geolocation, cached locally in netwatch_geo_cache.json.
"""

import argparse
import ipaddress
import json
import os
import smtplib
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.request
import webbrowser
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------------
# Configuration / shared state
# ----------------------------------------------------------------------------

DEFAULT_PORT = 8339
GEO_BATCH_URL = ("http://ip-api.com/batch?fields=status,message,country,"
                 "countryCode,regionName,city,lat,lon,isp,org,query")
GEO_SELF_URL = ("http://ip-api.com/json/?fields=status,country,countryCode,"
                "regionName,city,lat,lon,query")
CACHE_FILE = os.path.join(HERE, "netwatch_geo_cache.json")
DB_FILE = os.path.join(HERE, "netwatch.db")
CONF_FILE = os.path.join(HERE, "netwatch.conf")
THREAT_CACHE = os.path.join(HERE, "netwatch_threat_cache.json")

STALE_AFTER = 10       # seconds since last packet -> flow shown as fading
DROP_AFTER = 120       # seconds since last packet -> flow removed
GEO_RETRY = 60
CACHE_SAVE_EVERY = 30
CAP_BYTES = 512        # bytes captured per frame (enough for headers + most SNI)
THREAT_REFRESH = 6 * 3600
DB_FLUSH_EVERY = 20
RETAIN_DAYS = 30
MAX_ALERTS = 300

# Public resolvers commonly hardcoded by devices to bypass a local DNS filter.
DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
           "149.112.112.112", "208.67.222.222", "208.67.220.220",
           "2606:4700:4700::1111", "2606:4700:4700::1001",
           "2001:4860:4860::8888", "2001:4860:4860::8844"}
DOH_HOSTS = ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
             "dns.quad9.net", "doh.opendns.com", "dns.adguard.com",
             "chrome.cloudflare-dns.com", "dns.nextdns.io")

# Threat blocklist sources (plain-text IP / CIDR lists).
THREAT_SOURCES = {
    "tor": "https://check.torproject.org/torbulkexitlist",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/"
               "master/firehol_level1.netset",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
}

LOCK = threading.Lock()
FLOWS = {}      # (dev,rem) -> {dev,rem,proto,ports:set,first,last,pkts,up,down,host}
GEO = {}        # ip -> {status, ts, ...}
DEV_NAMES = {}  # lan_ip -> hostname
IPDOMAIN = {}   # public_ip -> domain (learned from sniffed DNS answers)
BYPASS = {}     # dev_ip -> {"type": set(), "last": ts, "detail": str}
SEEN = {"dev_country": set(), "dev_rem": set()}   # baselines loaded from DB
ALERTS = []     # recent alert dicts (also persisted)
THREAT = {"exact": set(), "nets": [], "loaded": 0, "ts": 0, "error": None}
HOME = None
GEO_STATE = "waiting"
CAP_STATE = {"iface": "", "pkts": 0, "pps": 0.0, "drops": 0, "error": None,
             "demo": False}
START_TS = time.time()
CONF = {}       # loaded from netwatch.conf (alert channels, pihole ip, etc.)
PIHOLE_IPS = set()

# LAN / private ranges (source side of an outbound flow)
_PRIV = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fc00::/7", "fe80::/10")]


def is_private_lan(a):
    return any(a in n for n in _PRIV)


def classify(src, dst):
    """Return (device, remote, direction) for LAN<->public traffic, else None."""
    try:
        sa, da = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    except ValueError:
        return None
    if is_private_lan(sa) and da.is_global and not da.is_multicast:
        return src, dst, "out"
    if is_private_lan(da) and sa.is_global and not sa.is_multicast:
        return dst, src, "in"
    return None


# ----------------------------------------------------------------------------
# Packet parsing (Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP)
# ----------------------------------------------------------------------------

def parse_frame(buf, n):
    """Parse a raw L2 frame -> dict (src,dst,proto,sport,dport,flags,payload,plen)
    or None. Direction/flow classification is done by the caller."""
    if n < 34:
        return None
    etype = (buf[12] << 8) | buf[13]
    l3 = 14
    if etype == 0x8100:                      # 802.1Q VLAN tag
        if n < 38:
            return None
        etype = (buf[16] << 8) | buf[17]
        l3 = 18

    if etype == 0x0800:                      # IPv4
        if n < l3 + 20:
            return None
        ihl = (buf[l3] & 0x0f) * 4
        proto = buf[l3 + 9]
        plen = (buf[l3 + 2] << 8) | buf[l3 + 3]        # total length (whole pkt)
        src = socket.inet_ntop(socket.AF_INET, buf[l3 + 12:l3 + 16])
        dst = socket.inet_ntop(socket.AF_INET, buf[l3 + 16:l3 + 20])
        l4 = l3 + ihl
    elif etype == 0x86DD:                     # IPv6 (no ext-header walking)
        if n < l3 + 40:
            return None
        proto = buf[l3 + 6]
        plen = ((buf[l3 + 4] << 8) | buf[l3 + 5]) + 40
        src = socket.inet_ntop(socket.AF_INET6, buf[l3 + 8:l3 + 24])
        dst = socket.inet_ntop(socket.AF_INET6, buf[l3 + 24:l3 + 40])
        l4 = l3 + 40
    else:
        return None

    if proto == 6:                            # TCP
        if n < l4 + 20:
            return None
        sport = (buf[l4] << 8) | buf[l4 + 1]
        dport = (buf[l4 + 2] << 8) | buf[l4 + 3]
        flags = buf[l4 + 13]
        payload = l4 + (buf[l4 + 12] >> 4) * 4
        pname = "tcp"
    elif proto == 17:                         # UDP
        if n < l4 + 8:
            return None
        sport = (buf[l4] << 8) | buf[l4 + 1]
        dport = (buf[l4 + 2] << 8) | buf[l4 + 3]
        flags = 0
        payload = l4 + 8
        pname = "udp"
    else:
        return None

    return {"src": src, "dst": dst, "proto": pname, "sport": sport,
            "dport": dport, "flags": flags, "payload": payload, "plen": plen}


def parse_dns_answers(buf, n, off):
    """Parse A/AAAA answers from a DNS response payload -> [(ip, qname), ...]."""
    out = []
    try:
        if off + 12 > n:
            return out
        qd = (buf[off + 4] << 8) | buf[off + 5]
        an = (buf[off + 6] << 8) | buf[off + 7]
        if an == 0:
            return out
        p = off + 12

        def read_name(p):
            labels = []
            hops = 0
            while p < n and hops < 20:
                ln = buf[p]
                if ln == 0:
                    p += 1
                    break
                if ln & 0xc0 == 0xc0:            # compression pointer
                    p += 2
                    break
                p += 1
                if p + ln > n:
                    break
                labels.append(buf[p:p + ln].decode("ascii", "ignore"))
                p += ln
            return ".".join(labels), p

        qname = ""
        for _ in range(qd):
            qname, p = read_name(p)
            p += 4                              # qtype + qclass
        for _ in range(an):
            if p + 2 <= n and buf[p] & 0xc0 == 0xc0:
                p += 2
            else:
                _, p = read_name(p)
            if p + 10 > n:
                break
            rtype = (buf[p] << 8) | buf[p + 1]
            rdlen = (buf[p + 8] << 8) | buf[p + 9]
            rdata = p + 10
            if rdata + rdlen > n:
                break
            if rtype == 1 and rdlen == 4:
                out.append((socket.inet_ntop(socket.AF_INET,
                            bytes(buf[rdata:rdata + 4])), qname))
            elif rtype == 28 and rdlen == 16:
                out.append((socket.inet_ntop(socket.AF_INET6,
                            bytes(buf[rdata:rdata + 16])), qname))
            p = rdata + rdlen
    except Exception:
        return out
    return out


def parse_sni(buf, n, off):
    """Best-effort SNI hostname from a TLS ClientHello starting at `off`."""
    try:
        if off + 6 > n or buf[off] != 0x16 or buf[off + 1] != 0x03:
            return None
        if buf[off + 5] != 0x01:              # handshake type = ClientHello
            return None
        p = off + 5 + 4                       # skip record hdr(5) + hs type/len(4)
        p += 2 + 32                           # client version + random
        if p + 1 > n:
            return None
        p += 1 + buf[p]                       # session id
        if p + 2 > n:
            return None
        p += 2 + ((buf[p] << 8) | buf[p + 1])  # cipher suites
        if p + 1 > n:
            return None
        p += 1 + buf[p]                       # compression methods
        if p + 2 > n:
            return None
        ext_end = p + 2 + ((buf[p] << 8) | buf[p + 1])
        p += 2
        while p + 4 <= n and p + 4 <= ext_end:
            etype = (buf[p] << 8) | buf[p + 1]
            elen = (buf[p + 2] << 8) | buf[p + 3]
            p += 4
            if etype == 0x0000:               # server_name extension
                # server_name_list(2) name_type(1) name_len(2) name
                if p + 5 > n:
                    return None
                nlen = (buf[p + 3] << 8) | buf[p + 4]
                start = p + 5
                if start + nlen > n:
                    return None
                host = buf[start:start + nlen].decode("idna", "ignore") \
                    if False else buf[start:start + nlen].decode("ascii", "ignore")
                return host or None
            p += elen
    except Exception:
        return None
    return None


# ----------------------------------------------------------------------------
# Capture
# ----------------------------------------------------------------------------

def _record(dev, rem, proto, port, up=0, down=0, host=None):
    """Merge a single observation into FLOWS (used by demo + tests)."""
    now = time.time()
    _merge_flow((dev, rem), {"proto": proto, "ports": {port}, "pkts": 1,
                             "up": up, "down": down, "host": host,
                             "last": now}, now)


def _merge_flow(key, ent, now):
    f = FLOWS.get(key)
    if f is None:
        FLOWS[key] = {"dev": key[0], "rem": key[1], "proto": ent["proto"],
                      "ports": set(ent["ports"]), "first": now,
                      "last": ent["last"], "pkts": ent["pkts"],
                      "up": ent["up"], "down": ent["down"], "host": ent.get("host")}
    else:
        f["last"] = max(f["last"], ent["last"])
        f["pkts"] += ent["pkts"]
        f["up"] += ent["up"]
        f["down"] += ent["down"]
        f["ports"].update(ent["ports"])
        if ent["proto"] == "tcp":
            f["proto"] = "tcp"
        if ent.get("host") and not f.get("host"):
            f["host"] = ent["host"]


def _mark_bypass(dev, kind, detail):
    b = BYPASS.get(dev)
    if not b:
        b = {"types": set(), "last": 0, "detail": ""}
        BYPASS[dev] = b
    b["types"].add(kind)
    b["last"] = time.time()
    b["detail"] = detail


def capture_loop(iface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(0x0003))
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        s.bind((iface, 0))
        # Enable promiscuous mode so the NIC accepts mirrored frames that are
        # not addressed to its own MAC (essential on a mirror/monitor port).
        try:
            SOL_PACKET, ADD_MEMBERSHIP, MR_PROMISC = 263, 1, 1
            idx = socket.if_nametoindex(iface)
            mreq = struct.pack("iHH8s", idx, MR_PROMISC, 0, b"")
            s.setsockopt(SOL_PACKET, ADD_MEMBERSHIP, mreq)
        except OSError as e:
            print("  warning: could not enable promiscuous mode (%s); "
                  "you may only see this box's own traffic" % e)
    except PermissionError:
        CAP_STATE["error"] = "permission denied (run with sudo)"
        return
    except OSError as e:
        CAP_STATE["error"] = "cannot open %s: %s" % (iface, e)
        return

    CAP_STATE["iface"] = iface
    CAP_STATE["error"] = None
    buf = bytearray(CAP_BYTES)
    acc = {}                      # local accumulator flushed under lock
    dns_new = {}                  # ip -> domain, learned this window
    bypass_new = []               # (dev, kind, detail)
    count = 0
    win_start = time.time()
    win_count = 0
    last_flush = win_start

    def flush(now):
        if acc or dns_new or bypass_new:
            with LOCK:
                for k, e in acc.items():
                    _merge_flow(k, e, e["last"])
                for ip, dom in dns_new.items():
                    if ip not in IPDOMAIN:
                        IPDOMAIN[ip] = dom
                for dev, kind, detail in bypass_new:
                    _mark_bypass(dev, kind, detail)
            acc.clear(); dns_new.clear(); bypass_new.clear()

    while True:
        try:
            n = s.recv_into(buf, CAP_BYTES)
        except OSError:
            continue
        count += 1
        win_count += 1
        pk = parse_frame(buf, n)
        if not pk:
            pass
        else:
            now = time.time()
            # --- DNS learning + plaintext-DNS bypass ---
            if pk["sport"] == 53:                      # a DNS response
                for ip, qname in parse_dns_answers(buf, n, pk["payload"]):
                    try:
                        if ipaddress.ip_address(ip).is_global and qname:
                            dns_new[ip] = qname.lower().rstrip(".")
                    except ValueError:
                        pass
            elif pk["dport"] == 53:                    # a DNS query
                try:
                    sa = ipaddress.ip_address(pk["src"])
                    da = ipaddress.ip_address(pk["dst"])
                    if is_private_lan(sa) and (da.is_global
                            and pk["dst"] not in PIHOLE_IPS):
                        bypass_new.append((pk["src"], "plaintext-dns", pk["dst"]))
                except ValueError:
                    pass

            c = classify(pk["src"], pk["dst"])
            if c:
                dev, rem, direction = c
                port = pk["dport"] if direction == "out" else pk["sport"]
                host = None
                if (direction == "out" and pk["proto"] == "tcp"
                        and pk["dport"] == 443 and pk["payload"] < n
                        and buf[pk["payload"]] == 0x16):
                    host = parse_sni(buf, n, pk["payload"])
                if rem in DOH_IPS or (host and host.lower() in DOH_HOSTS):
                    bypass_new.append((dev, "doh", host or rem))
                e = acc.get((dev, rem))
                if e is None:
                    e = {"proto": pk["proto"], "ports": {port}, "pkts": 0,
                         "up": 0, "down": 0, "host": host, "last": now}
                    acc[(dev, rem)] = e
                e["pkts"] += 1
                e["ports"].add(port)
                if direction == "out":
                    e["up"] += pk["plen"]
                else:
                    e["down"] += pk["plen"]
                if pk["proto"] == "tcp":
                    e["proto"] = "tcp"
                if host and not e["host"]:
                    e["host"] = host

        now = time.time()
        if count % 2000 == 0 or now - last_flush > 1.0 or len(acc) > 4000:
            flush(now)
            last_flush = now
            dt = now - win_start
            if dt >= 1:
                CAP_STATE["pps"] = round(win_count / dt, 1)
                win_start, win_count = now, 0
            CAP_STATE["pkts"] = count
            try:                       # kernel drop counter (PACKET_STATISTICS)
                st = s.getsockopt(263, 6, 8)   # SOL_PACKET, PACKET_STATISTICS
                CAP_STATE["drops"] = struct.unpack("II", st)[1]
            except Exception:
                pass
            _prune(now)


def _prune(now):
    with LOCK:
        for k in [k for k, f in FLOWS.items() if now - f["last"] > DROP_AFTER]:
            del FLOWS[k]


# ----------------------------------------------------------------------------
# Demo mode (no root; synthesize plausible flows to preview the UI)
# ----------------------------------------------------------------------------

def demo_loop():
    CAP_STATE["demo"] = True
    CAP_STATE["iface"] = "demo"
    devices = ["192.168.1.20", "192.168.1.31", "192.168.1.44", "192.168.1.57",
               "192.168.1.66"]
    dnames = {"192.168.1.20": "terry-pc", "192.168.1.31": "living-room-tv",
              "192.168.1.44": "pixel-phone", "192.168.1.57": "ring-doorbell",
              "192.168.1.66": "echo-dot"}
    remotes = [
        ("8.8.8.8", "dns.google", 443), ("140.82.113.3", "github.com", 443),
        ("104.16.132.229", "cloudflare.com", 443),
        ("52.94.236.248", "aws.amazon.com", 443),
        ("31.13.71.36", "graph.facebook.com", 443),
        ("120.52.22.96", "tvplus-eu.samsung.com", 443),
        ("203.0.113.9", "device-metrics-us.amazon.com", 443),
        ("185.60.216.35", "whatsapp.net", 443),
        ("77.88.8.8", "yandex.ru", 443), ("101.6.6.6", "tuna.tsinghua.cn", 443)]
    with LOCK:
        DEV_NAMES.update(dnames)
        # Demo a threat hit and a DNS-bypass so those features are visible.
        THREAT["exact"].add("77.88.8.8"); THREAT["loaded"] = 1
        THREAT["ts"] = START_TS
    i = 0
    # deterministic pseudo-random without Math.random/time-seed issues
    while True:
        i += 1
        dev = devices[(i * 7) % len(devices)]
        rem, host, port = remotes[(i * 3) % len(remotes)]
        up = 200 + (i * 37) % 1400
        down = up * (3 + (i % 6))
        _record(dev, rem, "tcp", port, up=up, down=down, host=host)
        if rem == "8.8.8.8":                       # echo-dot doing its own DoH
            with LOCK:
                _mark_bypass(dev, "doh", "dns.google")
        CAP_STATE["pkts"] = i
        CAP_STATE["pps"] = 12.0
        time.sleep(0.35)


# ----------------------------------------------------------------------------
# Reverse DNS for LAN device names (best effort, via the network's resolver)
# ----------------------------------------------------------------------------

def name_worker():
    while True:
        with LOCK:
            unknown = list({f["dev"] for f in FLOWS.values()} - set(DEV_NAMES))
        for ip in unknown:
            name = None
            try:
                name = socket.gethostbyaddr(ip)[0].split(".")[0]
            except Exception:
                name = None
            with LOCK:
                DEV_NAMES[ip] = name or ""
        time.sleep(5)


# ----------------------------------------------------------------------------
# Geolocation (ip-api batch, disk-cached) — shared design with netmap.py
# ----------------------------------------------------------------------------

def _load_cache():
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for ip, g in data.items():
            if isinstance(g, dict) and g.get("status") == "ok":
                GEO[ip] = g
        print("  loaded %d cached IP locations" % len(GEO))
    except Exception:
        pass


def _save_cache():
    try:
        with LOCK:
            ok = {ip: g for ip, g in GEO.items() if g.get("status") == "ok"}
        if not ok:
            return          # never clobber a good cache with an empty one
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(ok, f)
    except Exception:
        pass


def _http_json(url, payload=None, timeout=12):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "netwatch/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def geolocate_home():
    global HOME, GEO_STATE
    try:
        r = _http_json(GEO_SELF_URL)
        if r.get("status") == "success":
            HOME = {"lat": r["lat"], "lon": r["lon"], "city": r.get("city", ""),
                    "country": r.get("country", ""),
                    "countryCode": r.get("countryCode", "")}
            GEO_STATE = "ok"
            print("  home location: %s, %s" % (HOME["city"], HOME["country"]))
    except Exception:
        GEO_STATE = "offline"


def geo_worker():
    global GEO_STATE
    last_save = time.time()
    if HOME is None:
        geolocate_home()
    while True:
        now = time.time()
        with LOCK:
            pending = [ip for ip in {f["rem"] for f in FLOWS.values()}
                       if ip not in GEO
                       or (GEO[ip].get("status") == "fail"
                           and now - GEO[ip].get("ts", 0) > GEO_RETRY)]
            for ip in pending:
                GEO[ip] = {"status": "pending", "ts": now}
        if pending:
            for i in range(0, len(pending), 100):
                batch = pending[i:i + 100]
                try:
                    results = _http_json(GEO_BATCH_URL, payload=batch)
                    GEO_STATE = "ok"
                    with LOCK:
                        for r in results:
                            ip = r.get("query")
                            if not ip:
                                continue
                            if r.get("status") == "success":
                                GEO[ip] = {"status": "ok", "ts": now,
                                    "lat": r["lat"], "lon": r["lon"],
                                    "city": r.get("city", ""),
                                    "region": r.get("regionName", ""),
                                    "country": r.get("country", ""),
                                    "countryCode": r.get("countryCode", ""),
                                    "isp": r.get("isp", ""), "org": r.get("org", "")}
                            else:
                                GEO[ip] = {"status": "fail", "ts": now}
                except Exception:
                    GEO_STATE = "offline"
                    with LOCK:
                        for ip in batch:
                            GEO[ip] = {"status": "fail", "ts": now}
                time.sleep(1.6)
            if HOME is None:
                geolocate_home()
        if now - last_save > CACHE_SAVE_EVERY:
            _save_cache()
            last_save = now
        time.sleep(3)


# ----------------------------------------------------------------------------
# Config file (alert channels, Pi-hole IPs, thresholds) — netwatch.conf (JSON)
# ----------------------------------------------------------------------------

def load_config():
    global CONF, PIHOLE_IPS
    cfg = {}
    try:
        with open(CONF_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        print("  loaded config from %s" % CONF_FILE)
    except FileNotFoundError:
        pass
    except Exception as e:
        print("  config error (%s); using defaults" % e)
    CONF = cfg
    PIHOLE_IPS = set(cfg.get("pihole_ips", []))


# ----------------------------------------------------------------------------
# Threat intelligence (public blocklists -> flag remote IPs)
# ----------------------------------------------------------------------------

def _parse_netset(text):
    exact, nets = set(), []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            if "/" in token:
                nets.append(ipaddress.ip_network(token, strict=False))
            else:
                ipaddress.ip_address(token)
                exact.add(token)
        except ValueError:
            continue
    return exact, nets


def _http_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def threat_worker():
    # Try disk cache first for an instant start.
    try:
        with open(THREAT_CACHE, "r", encoding="utf-8") as f:
            c = json.load(f)
        with LOCK:
            THREAT["exact"] = set(c.get("exact", []))
            THREAT["nets"] = [ipaddress.ip_network(x) for x in c.get("nets", [])]
            THREAT["loaded"] = len(THREAT["exact"]) + len(THREAT["nets"])
            THREAT["ts"] = c.get("ts", 0)
    except Exception:
        pass
    while True:
        exact, nets, srcs_ok = set(), [], 0
        for name, url in THREAT_SOURCES.items():
            try:
                e, nn = _parse_netset(_http_text(url))
                exact |= e
                nets += nn
                srcs_ok += 1
            except Exception:
                pass
        if srcs_ok:
            with LOCK:
                THREAT["exact"] = exact
                THREAT["nets"] = nets
                THREAT["loaded"] = len(exact) + len(nets)
                THREAT["ts"] = time.time()
                THREAT["error"] = None
            try:
                with open(THREAT_CACHE, "w", encoding="utf-8") as f:
                    json.dump({"exact": sorted(exact),
                               "nets": [str(x) for x in nets],
                               "ts": THREAT["ts"]}, f)
            except Exception:
                pass
        else:
            with LOCK:
                THREAT["error"] = "could not fetch blocklists"
        time.sleep(THREAT_REFRESH)


_threat_verdict = {}     # ip -> list-name or "" (memoised)


def threat_match(ip):
    v = _threat_verdict.get(ip)
    if v is not None:
        return v or None
    with LOCK:
        exact = THREAT["exact"]
        nets = THREAT["nets"]
    hit = ""
    if ip in exact:
        hit = "blocklist"
    else:
        try:
            a = ipaddress.ip_address(ip)
            for net in nets:
                if a in net:
                    hit = "blocklist"
                    break
        except ValueError:
            pass
    _threat_verdict[ip] = hit
    return hit or None


# ----------------------------------------------------------------------------
# History (SQLite: sessions + seen baselines + alerts)
# ----------------------------------------------------------------------------

def db_connect():
    con = sqlite3.connect(DB_FILE, timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS sessions(
        dev TEXT, dev_name TEXT, rem TEXT, host TEXT, country TEXT, cc TEXT,
        first REAL, last REAL, up INTEGER, down INTEGER, threat TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_sess_last ON sessions(last)")
    con.execute("CREATE INDEX IF NOT EXISTS ix_sess_dev ON sessions(dev)")
    con.execute("""CREATE TABLE IF NOT EXISTS seen(
        kind TEXT, a TEXT, b TEXT, first REAL, PRIMARY KEY(kind,a,b))""")
    con.execute("""CREATE TABLE IF NOT EXISTS alerts(
        ts REAL, level TEXT, kind TEXT, dev TEXT, dev_name TEXT,
        rem TEXT, host TEXT, msg TEXT)""")
    con.commit()
    return con


def db_load_baselines(con):
    with LOCK:
        for kind, a, b in con.execute("SELECT kind,a,b FROM seen"):
            if kind == "dev_country":
                SEEN["dev_country"].add((a, b))
            elif kind == "dev_rem":
                SEEN["dev_rem"].add((a, b))
        for row in con.execute(
                "SELECT ts,level,kind,dev,dev_name,rem,host,msg FROM alerts "
                "ORDER BY ts DESC LIMIT ?", (MAX_ALERTS,)):
            ALERTS.append({"ts": row[0], "level": row[1], "kind": row[2],
                           "dev": row[3], "dev_name": row[4], "rem": row[5],
                           "host": row[6], "msg": row[7]})
        ALERTS.reverse()
    print("  history: %d known (device,country) pairs, %d alerts"
          % (len(SEEN["dev_country"]), len(ALERTS)))


def db_worker():
    try:
        con = db_connect()
        db_load_baselines(con)
    except Exception as e:
        print("  history disabled (%s)" % e)
        return
    last_prune = 0
    while True:
        time.sleep(DB_FLUSH_EVERY)
        now = time.time()
        with LOCK:
            rows = []
            for f in FLOWS.values():
                g = GEO.get(f["rem"])
                gg = g if (g and g.get("status") == "ok") else {}
                rows.append((f["dev"], DEV_NAMES.get(f["dev"], ""), f["rem"],
                             f.get("host") or IPDOMAIN.get(f["rem"], ""),
                             gg.get("country", ""), gg.get("countryCode", ""),
                             f["first"], f["last"], f["up"], f["down"],
                             threat_match(f["rem"]) or ""))
            pending = list(_alert_persist_q)
            _alert_persist_q.clear()
        try:
            # Keep one row per (dev,rem,first) session, updated in place.
            for r in rows:
                con.execute(
                    "DELETE FROM sessions WHERE dev=? AND rem=? AND first=?",
                    (r[0], r[2], r[6]))
                con.execute(
                    "INSERT INTO sessions(dev,dev_name,rem,host,country,cc,"
                    "first,last,up,down,threat) VALUES(?,?,?,?,?,?,?,?,?,?,?)", r)
            for a in pending:
                con.execute(
                    "INSERT INTO alerts(ts,level,kind,dev,dev_name,rem,host,msg)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (a["ts"], a["level"], a["kind"], a["dev"], a["dev_name"],
                     a["rem"], a["host"], a["msg"]))
            if now - last_prune > 3600:
                cutoff = now - RETAIN_DAYS * 86400
                con.execute("DELETE FROM sessions WHERE last < ?", (cutoff,))
                con.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
                last_prune = now
            con.commit()
        except Exception as e:
            print("  history write error: %s" % e)


def db_history(since, dev=None, limit=500):
    try:
        con = db_connect()
        q = ("SELECT dev,dev_name,rem,host,country,cc,first,last,up,down,threat "
             "FROM sessions WHERE last >= ?")
        args = [since]
        if dev:
            q += " AND dev = ?"
            args.append(dev)
        q += " ORDER BY last DESC LIMIT ?"
        args.append(limit)
        rows = con.execute(q, args).fetchall()
        con.close()
        cols = ["dev", "dev_name", "rem", "host", "country", "cc", "first",
                "last", "up", "down", "threat"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception:
        return []


# ----------------------------------------------------------------------------
# Alert engine + notifications
# ----------------------------------------------------------------------------

_alert_persist_q = []     # alerts waiting to be written by db_worker
_alert_dedup = set()      # (kind, dev, key) already alerted this run


def _emit_alert(level, kind, dev, rem, host, msg):
    now = time.time()
    a = {"ts": now, "level": level, "kind": kind, "dev": dev,
         "dev_name": DEV_NAMES.get(dev, ""), "rem": rem, "host": host, "msg": msg}
    with LOCK:
        ALERTS.append(a)
        del ALERTS[:-MAX_ALERTS]
        _alert_persist_q.append(a)
    threading.Thread(target=notify, args=(a,), daemon=True).start()


def alert_worker():
    warmup = float(CONF.get("learn_minutes", 15)) * 60
    while True:
        time.sleep(4)
        now = time.time()
        learning = (now - START_TS) < warmup
        with LOCK:
            flows = list(FLOWS.values())
            geo = dict(GEO)
            names = dict(DEV_NAMES)
            bypass = {d: dict(v, types=set(v["types"])) for d, v in BYPASS.items()}
        for f in flows:
            dev, rem = f["dev"], f["rem"]
            host = f.get("host") or IPDOMAIN.get(rem, "")
            g = geo.get(rem)
            cc = g.get("countryCode") if (g and g.get("status") == "ok") else None
            # threat match (always alert, even in warmup)
            if threat_match(rem):
                _fire("threat", dev, rem, host, cc, names, learning=False,
                      msg="talked to flagged IP %s%s" % (rem, " (" + host + ")" if host else ""))
            # new destination for this device
            _fire("dev_rem", dev, rem, host, cc, names, learning,
                  msg="new destination %s%s" % (host or rem, ""))
            # new country for this device
            if cc:
                _fire("dev_country", dev, cc, host, cc, names, learning,
                      msg="first connection to %s" % (g.get("country") or cc))
        # bypass alerts
        for dev, b in bypass.items():
            for t in b["types"]:
                _fire("bypass_" + t, dev, b.get("detail", ""), "", None, names,
                      learning,
                      msg=("device using its own %s (%s), bypassing your Pi-hole"
                           % ("encrypted DNS/DoH" if t == "doh" else "external DNS",
                              b.get("detail", ""))))


def _fire(kind, dev, key, host, cc, names, learning, msg):
    """key is rem for dev_rem/threat, cc for dev_country, detail for bypass."""
    rem_field = ""
    if kind == "dev_rem":
        with LOCK:
            known = (dev, key) in SEEN["dev_rem"]
            SEEN["dev_rem"].add((dev, key))
        _remember("dev_rem", dev, key)
        # Per-destination "new IP/host" alerts are noisy (CDNs rotate constantly),
        # so they are opt-in. New-country, threat and bypass stay on by default.
        if known or learning or not CONF.get("alert_new_dest", False):
            return
        level, rem_field = "info", key
    elif kind == "dev_country":
        with LOCK:
            known = (dev, key) in SEEN["dev_country"]
            SEEN["dev_country"].add((dev, key))
        _remember("dev_country", dev, key)
        if known or learning:
            return
        level = "notice"
    elif kind == "threat":
        level, rem_field = "critical", key
    elif kind.startswith("bypass_"):
        if learning:
            return
        level = "warning"
    else:
        return
    dd = (kind, dev, key)
    if dd in _alert_dedup:
        return
    _alert_dedup.add(dd)
    _emit_alert(level, kind, dev, rem_field, host, msg)


_seen_persist = []


def _remember(kind, a, b):
    with LOCK:
        _seen_persist.append((kind, a, b, time.time()))


def seen_writer():
    while True:
        time.sleep(10)
        with LOCK:
            if not _seen_persist:
                continue
            batch = _seen_persist[:]
            del _seen_persist[:]
        try:
            con = db_connect()
            con.executemany("INSERT OR IGNORE INTO seen(kind,a,b,first) "
                            "VALUES(?,?,?,?)", batch)
            con.commit()
            con.close()
        except Exception:
            pass


def notify(a):
    ch = CONF.get("notify", {})
    line = "[%s] %s%s: %s" % (a["level"].upper(),
                              a["dev_name"] or a["dev"],
                              "", a["msg"])
    # ntfy
    try:
        topic = ch.get("ntfy_url")
        if topic:
            req = urllib.request.Request(topic, data=line.encode(),
                headers={"Title": "NetWatch %s" % a["kind"],
                         "Priority": "high" if a["level"] in ("critical", "warning") else "default"})
            urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass
    # generic webhook (JSON)
    try:
        hook = ch.get("webhook_url")
        if hook:
            req = urllib.request.Request(hook, data=json.dumps(a).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass
    # email
    try:
        em = ch.get("email")
        if em and a["level"] in em.get("levels", ["critical", "warning", "notice"]):
            msg = EmailMessage()
            msg["From"] = em["from"]
            msg["To"] = em["to"]
            msg["Subject"] = "NetWatch alert: %s" % a["kind"]
            msg.set_content(line)
            with smtplib.SMTP(em["smtp_host"], int(em.get("smtp_port", 587)),
                              timeout=12) as s:
                s.starttls()
                if em.get("username"):
                    s.login(em["username"], em["password"])
                s.send_message(msg)
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Snapshot for the web UI
# ----------------------------------------------------------------------------

def snapshot():
    now = time.time()
    with LOCK:
        flows = [dict(f, ports=sorted(f["ports"])) for f in FLOWS.values()]
        geo = dict(GEO)
        names = dict(DEV_NAMES)
        ipdom = dict(IPDOMAIN)
        bypass = {d: sorted(v["types"]) for d, v in BYPASS.items()}
        alerts = ALERTS[-60:][::-1]
        threat_stat = {"loaded": THREAT["loaded"], "ts": THREAT["ts"],
                       "error": THREAT["error"]}

    dests = {}
    devices = {}
    countries = set()
    active_flows = 0
    flagged = 0
    for f in flows:
        active = now - f["last"] <= STALE_AFTER
        if active:
            active_flows += 1
        g = geo.get(f["rem"])
        gg = g if (g and g.get("status") == "ok") else None
        if gg:
            countries.add(gg["countryCode"])
        threat = threat_match(f["rem"])
        host = f.get("host") or ipdom.get(f["rem"], "")

        d = dests.setdefault(f["rem"], {
            "ip": f["rem"], "geo": None, "host": host, "devices": set(),
            "ports": set(), "pkts": 0, "up": 0, "down": 0, "active": False,
            "threat": threat, "last": f["last"]})
        d["geo"] = ({k: gg[k] for k in ("lat", "lon", "city", "region",
                    "country", "countryCode", "isp", "org")} if gg else None)
        if host and not d["host"]:
            d["host"] = host
        d["devices"].add(f["dev"])
        d["ports"].update(f["ports"])
        d["pkts"] += f["pkts"]
        d["up"] += f["up"]
        d["down"] += f["down"]
        d["active"] = d["active"] or active
        d["last"] = max(d["last"], f["last"])

        dv = devices.setdefault(f["dev"], {
            "ip": f["dev"], "name": names.get(f["dev"]) or "", "dests": set(),
            "pkts": 0, "up": 0, "down": 0, "active": False, "last": f["last"],
            "bypass": bypass.get(f["dev"], []), "threats": 0})
        dv["dests"].add(f["rem"])
        dv["pkts"] += f["pkts"]
        dv["up"] += f["up"]
        dv["down"] += f["down"]
        dv["active"] = dv["active"] or active
        dv["last"] = max(dv["last"], f["last"])
        if threat:
            dv["threats"] += 1

    dest_list = []
    for d in dests.values():
        if d["threat"]:
            flagged += 1
        d["devices"] = sorted(d["devices"])
        d["ports"] = sorted(d["ports"])[:8]
        d["ndev"] = len(d["devices"])
        d["age"] = round(now - d["last"], 1)
        dest_list.append(d)
    dest_list.sort(key=lambda d: (-(d["threat"] is not None), -d["active"],
                                  -(d["up"] + d["down"])))

    dev_list = []
    for dv in devices.values():
        dv["ndest"] = len(dv["dests"])
        dv["dests"] = sorted(dv["dests"])
        dv["age"] = round(now - dv["last"], 1)
        dev_list.append(dv)
    dev_list.sort(key=lambda d: (-(d["threats"] > 0), -bool(d["bypass"]),
                                 -d["active"], -d["ndest"], d["ip"]))

    return {
        "home": HOME, "geo_state": GEO_STATE,
        "capture": {"iface": CAP_STATE["iface"], "pps": CAP_STATE["pps"],
                    "drops": CAP_STATE["drops"], "error": CAP_STATE["error"],
                    "demo": CAP_STATE["demo"]},
        "threat": threat_stat,
        "stats": {"active": active_flows, "devices": len(dev_list),
                  "dests": len(dest_list), "countries": len(countries),
                  "flagged": flagged, "alerts": len(alerts)},
        "alerts": alerts,
        "devices": dev_list, "dests": dest_list,
    }


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path == "/" or u.path.startswith("/index"):
            body = HTML_PAGE.encode("utf-8"); ctype = "text/html; charset=utf-8"
        elif u.path == "/data":
            body = json.dumps(snapshot()).encode("utf-8"); ctype = "application/json"
        elif u.path == "/history":
            q = parse_qs(u.query)
            hours = float(q.get("hours", ["24"])[0])
            dev = q.get("dev", [None])[0]
            since = time.time() - hours * 3600
            body = json.dumps({"rows": db_history(since, dev)}).encode("utf-8")
            ctype = "application/json"
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/quit":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
            _save_cache()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        else:
            self.send_response(404); self.end_headers()

    def log_message(self, *a):
        pass


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetWatch — network-wide connection map</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet"
  href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<style>
  :root{
    color-scheme:dark;
    --surface-1:#141413; --surface-2:#1e1e1c; --surface-3:#2a2a27;
    --border:#3a3a36;
    --text-primary:#ffffff; --text-secondary:#c3c2b7; --text-muted:#8a897f;
    --series-1:#3987e5; --home:#f4f4ee;
    --good:#0ca30c; --warn:#fab219; --bad:#d03b3b;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--surface-1);
    font:13px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif;
    color:var(--text-primary);overflow:hidden}
  #app{display:grid;grid-template-rows:auto 1fr;height:100%}
  header{display:flex;align-items:center;gap:14px;padding:10px 16px;
    background:var(--surface-2);border-bottom:1px solid var(--border);flex-wrap:wrap}
  h1{font-size:15px;margin:0;font-weight:600}
  h1 span{color:var(--series-1)}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;
    border-radius:999px;background:var(--surface-3);color:var(--text-secondary);font-size:11px}
  .pill .led{width:7px;height:7px;border-radius:50%;background:var(--good)}
  .pill.warn .led{background:var(--warn)} .pill.bad .led{background:var(--bad)}
  .pill .badge{background:var(--warn);color:#000;border-radius:4px;padding:0 5px;
    font-weight:600;font-size:10px}
  .tiles{display:flex;gap:10px;margin-left:auto;flex-wrap:wrap}
  .tile{background:var(--surface-3);border-radius:8px;padding:5px 12px;text-align:right;min-width:74px}
  .tile b{display:block;font-size:16px;font-variant-numeric:tabular-nums}
  .tile small{color:var(--text-muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em}
  #quitBtn{align-self:center;background:var(--surface-3);color:var(--text-secondary);
    border:1px solid var(--border);border-radius:8px;padding:6px 12px;font:inherit;font-size:11px;cursor:pointer}
  #quitBtn:hover{border-color:var(--bad);color:var(--text-primary)}
  main{display:grid;grid-template-columns:1fr 340px;min-height:0}
  #map{height:100%;background:var(--surface-1)}
  aside{border-left:1px solid var(--border);background:var(--surface-2);display:flex;flex-direction:column;min-height:0}
  .filter{padding:10px 12px;border-bottom:1px solid var(--border)}
  .filter input{width:100%;padding:6px 10px;border-radius:6px;border:1px solid var(--border);
    background:var(--surface-1);color:var(--text-primary);font:inherit;outline:none}
  .filter input:focus{border-color:var(--series-1)}
  #list{overflow-y:auto;flex:1;padding:2px 0 40px}
  .section-hd{display:flex;justify-content:space-between;align-items:center;padding:9px 12px 5px;
    font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);
    background:var(--surface-2);position:sticky;top:0;border-top:1px solid var(--border);z-index:2}
  .section-hd a{color:var(--series-1);cursor:pointer;text-transform:none;letter-spacing:0;font-size:11px}
  .row{padding:8px 12px;border-bottom:1px solid #262623;cursor:pointer}
  .row:hover{background:var(--surface-3)}
  .row.off{opacity:.45}
  .row.sel{background:#20303f;box-shadow:inset 3px 0 0 var(--series-1)}
  .row .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .row .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
    display:flex;align-items:center;gap:7px}
  .sw{width:9px;height:9px;border-radius:2px;flex:none}
  .row .cnt{color:var(--text-muted);font-size:11px;flex:none}
  .row .loc{color:var(--text-secondary);font-size:12px;margin-top:1px}
  .row .ipline{color:var(--text-muted);font-size:11px;font-family:Consolas,ui-monospace,monospace;margin-top:1px}
  .empty{padding:22px 16px;color:var(--text-muted);text-align:center}
  .leaflet-container{font:inherit}
  .leaflet-tooltip.nm{background:var(--surface-2);color:var(--text-primary);border:1px solid var(--border);
    border-radius:8px;box-shadow:0 4px 14px #0008;padding:8px 10px;max-width:300px;white-space:normal}
  .leaflet-tooltip.nm::before{display:none}
  .tt-host{font-weight:600}
  .tt-ip{font-family:Consolas,ui-monospace,monospace;color:var(--text-secondary)}
  .tt-isp{color:var(--text-muted);font-size:11px}
  .tt-dev{margin-top:4px;font-size:11px;color:var(--text-secondary)}
  .nm-dot{position:relative;width:100%;height:100%}
  .nm-dot .core{position:absolute;inset:0;border-radius:50%;background:var(--series-1);border:2px solid var(--surface-1)}
  .nm-dot .ring{position:absolute;inset:0;border-radius:50%;border:2px solid var(--series-1);opacity:0}
  .nm-dot.active .ring{animation:pulse 1.9s ease-out infinite}
  .nm-dot.home .core{background:var(--home);border-color:#0008;border-radius:3px}
  .nm-dot.home .ring{border-color:var(--home);border-radius:3px;animation:pulse 2.5s ease-out infinite}
  @keyframes pulse{0%{opacity:.8;transform:scale(1)}100%{opacity:0;transform:scale(3)}}
  path.nm-arc{stroke-dasharray:3 9;animation:dash 1.1s linear infinite}
  @keyframes dash{to{stroke-dashoffset:-12}}
  .osm-dark{filter:invert(1) hue-rotate(180deg) brightness(.85) saturate(.35) contrast(.95)}
  #banner{position:absolute;left:50%;top:64px;transform:translateX(-50%);z-index:1000;
    background:var(--surface-2);border:1px solid var(--warn);color:var(--text-primary);
    padding:8px 14px;border-radius:8px;display:none;max-width:80%;box-shadow:0 4px 14px #0008}
  #stopped{position:fixed;inset:0;z-index:2000;display:none;place-items:center;background:var(--surface-1)}
  #stopped div{text-align:center;color:var(--text-secondary)}
  #stopped b{display:block;font-size:18px;color:var(--text-primary);margin-bottom:6px}
  /* threat + badges + bytes */
  .nm-dot.bad .core{background:var(--bad)} .nm-dot.bad .ring{border-color:var(--bad)}
  .row.flag{box-shadow:inset 3px 0 0 var(--bad)}
  .badge2{font-size:9px;padding:1px 5px;border-radius:4px;font-weight:600;flex:none;
    text-transform:uppercase;letter-spacing:.03em}
  .badge2.doh{background:#4a2020;color:#ff9d9d} .badge2.dns{background:#4a3a10;color:#f4c256}
  .badge2.threat{background:var(--bad);color:#fff}
  .bytes{color:var(--text-muted);font-size:11px;font-variant-numeric:tabular-nums}
  .tile.alert{cursor:pointer} .tile.alert:hover{background:#3a2a10}
  .tile.flagged b{color:var(--bad)}
  /* header alert button */
  #alertBtn{align-self:center;background:var(--surface-3);border:1px solid var(--border);
    color:var(--text-secondary);border-radius:8px;padding:6px 10px;font:inherit;font-size:11px;cursor:pointer;position:relative}
  #alertBtn.has{border-color:var(--warn);color:var(--text-primary)}
  #alertBtn .n{background:var(--bad);color:#fff;border-radius:999px;padding:0 5px;font-size:10px;margin-left:4px}
  /* segmented toggle */
  .seg{display:flex;gap:2px;padding:8px 12px 4px;background:var(--surface-2)}
  .seg button{flex:1;background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);
    padding:5px;font:inherit;font-size:11px;cursor:pointer;border-radius:6px}
  .seg button.on{background:#20303f;border-color:var(--series-1);color:var(--text-primary)}
  /* alerts panel */
  #alerts{position:absolute;top:0;right:0;width:380px;max-width:92vw;height:100%;z-index:1500;
    background:var(--surface-2);border-left:1px solid var(--border);box-shadow:-8px 0 24px #0009;
    transform:translateX(100%);transition:transform .18s ease;display:flex;flex-direction:column}
  #alerts.open{transform:none}
  #alerts .hd{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;
    border-bottom:1px solid var(--border);font-weight:600}
  #alerts .hd button{background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer}
  #alertList{overflow-y:auto;flex:1}
  .al{padding:9px 14px;border-bottom:1px solid #262623;border-left:3px solid var(--text-muted)}
  .al.critical{border-left-color:var(--bad)} .al.warning{border-left-color:var(--warn)}
  .al.notice{border-left-color:var(--series-1)} .al.info{border-left-color:var(--text-muted)}
  .al .k{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted)}
  .al .m{margin-top:2px} .al .w{color:var(--text-muted);font-size:11px;margin-top:2px}
  .hist .top{display:flex;justify-content:space-between;gap:8px}
  .hist .when{color:var(--text-muted);font-size:11px}
  @media (max-width:900px){main{grid-template-columns:1fr}aside{display:none}}
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>Net<span>Watch</span></h1>
    <span class="pill" id="capPill"><span class="led"></span><span id="capTxt">capture</span></span>
    <span class="pill" id="geoPill"><span class="led"></span><span id="geoTxt">geo: waiting</span></span>
    <span class="pill" id="threatPill" style="display:none"><span class="led"></span><span id="threatTxt">threat</span></span>
    <div class="tiles">
      <div class="tile"><b id="tActive">–</b><small>active flows</small></div>
      <div class="tile"><b id="tDevices">–</b><small>devices</small></div>
      <div class="tile"><b id="tDests">–</b><small>destinations</small></div>
      <div class="tile flagged"><b id="tFlagged">–</b><small>flagged</small></div>
      <button id="alertBtn" title="Show alerts">&#9873; alerts<span class="n" id="alertN" style="display:none">0</span></button>
      <button id="quitBtn" title="Stop NetWatch">&#10005; quit</button>
    </div>
  </header>
  <main>
    <div id="map"></div>
    <aside>
      <div class="filter"><input id="q" type="search"
        placeholder="Filter by device, host, IP, country&hellip;" autocomplete="off"></div>
      <div class="seg">
        <button id="segLive" class="on">Live</button>
        <button id="segHist">History 24h</button>
      </div>
      <div id="list"><div class="empty">Waiting for traffic&hellip;</div></div>
    </aside>
  </main>
</div>
<div id="alerts">
  <div class="hd"><span>Alerts</span><button id="alertClose">&times;</button></div>
  <div id="alertList"><div class="empty">No alerts yet.</div></div>
</div>
<div id="banner"></div>
<div id="stopped"><div><b>NetWatch stopped</b>You can close this tab.</div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script>
"use strict";
const PALETTE=["#3987e5","#008300","#d55181","#c98500","#199e70","#d95926","#9085e9","#e66767"];
const HAS_MAP=typeof L!=="undefined";
let map=null,tileBanner=null;
if(HAS_MAP){
  map=L.map("map",{worldCopyJump:true,minZoom:2}).setView([25,0],2);
  const osmAttr='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>';
  let tileOK=false,tileErr=0,fell=false;
  const carto=L.tileLayer("https://{s}.basemap.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {attribution:osmAttr+' &copy; <a href="https://carto.com/attributions">CARTO</a>',subdomains:"abcd",maxZoom:19}).addTo(map);
  function fallback(){if(fell)return;fell=true;map.removeLayer(carto);
    const osm=L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",{attribution:osmAttr,maxZoom:19,className:"osm-dark"});
    let ok=false;osm.on("tileload",()=>ok=true);
    osm.on("tileerror",()=>{if(!ok)tileBanner="Map tiles unreachable; connections still plot on black.";});
    osm.addTo(map);}
  carto.on("tileload",()=>tileOK=true);
  carto.on("tileerror",()=>{if(!tileOK&&++tileErr>=3)fallback();});
  setTimeout(()=>{if(!tileOK)fallback();},8000);
}else{document.getElementById("map").innerHTML=
  '<div class="empty" style="padding-top:15vh">Map library could not load (check cdnjs.cloudflare.com).<br>The device &amp; destination lists still work.</div>';}

const BLUE=PALETTE[0];
let homeMarker=null,homeLL=null,latest=null,selDev=null;
const layers=new Map();          // rem_ip -> {marker,arc}
const devColor=new Map();        // dev_ip -> hex

function colorFor(ip){
  if(!devColor.has(ip)) devColor.set(ip, PALETTE[devColor.size % PALETTE.length]);
  return devColor.get(ip);
}
function flag(cc){if(!cc||cc.length!==2)return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c=>127397+c.charCodeAt(0)));}
function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function arcPoints(a,b){let lon2=b[1];if(Math.abs(lon2-a[1])>180)lon2+=(a[1]>lon2?360:-360);
  const p0=a,p2=[b[0],lon2],mx=(p0[0]+p2[0])/2,my=(p0[1]+p2[1])/2,dx=p2[0]-p0[0],dy=p2[1]-p0[1];
  const dist=Math.hypot(dx,dy)||1,bow=Math.min(dist*0.18,14),c=[mx+(-dy/dist)*bow,my+(dx/dist)*bow],pts=[];
  for(let i=0;i<=36;i++){const t=i/36,u=1-t;pts.push([u*u*p0[0]+2*u*t*c[0]+t*t*p2[0],u*u*p0[1]+2*u*t*c[1]+t*t*p2[1]]);}
  return pts;}
function dotIcon(extra,size,color){
  const st=color?'style="background:'+color+'"':'';
  const rst=color?'style="border-color:'+color+'"':'';
  return L.divIcon({className:"",iconSize:[size,size],
    html:'<div class="nm-dot '+extra+'"><span class="ring" '+rst+'></span><span class="core" '+st+'></span></div>'});}
function devLabel(ip){const n=(latest&&latest.devices||[]).find(d=>d.ip===ip);
  return n&&n.name?n.name:ip;}
function fmtBytes(b){if(!b)return "0 B";
  if(b<1024)return b+" B";if(b<1048576)return (b/1024).toFixed(1)+" KB";
  if(b<1073741824)return (b/1048576).toFixed(1)+" MB";return (b/1073741824).toFixed(2)+" GB";}
function ago(sec){const s=Date.now()/1000-sec;
  if(s<60)return Math.round(s)+"s ago";if(s<3600)return Math.round(s/60)+"m ago";
  if(s<86400)return Math.round(s/3600)+"h ago";return Math.round(s/86400)+"d ago";}
function destTip(d){const g=d.geo||{};
  const devs=d.devices.map(ip=>'<span style="color:'+colorFor(ip)+'">&#9632;</span> '+esc(devLabel(ip))).join("<br>");
  return (d.threat?'<div class="tt-host" style="color:var(--bad)">&#9888; On threat blocklist</div>':"")
    +'<div class="tt-host">'+(d.host?esc(d.host):esc(g.country||"Unknown"))+"</div>"
    +'<div class="tt-ip">'+esc(d.ip)+(d.ports.length?"  :"+d.ports.slice(0,5).join(" :"):"")+"</div>"
    +'<div class="tt-isp">'+flag(g.countryCode)+" "+esc(g.city?g.city+", ":"")+esc(g.country||"")
    +(g.isp?" &middot; "+esc(g.isp):"")+"</div>"
    +'<div class="tt-isp">&#8593; '+fmtBytes(d.up)+" &nbsp; &#8595; "+fmtBytes(d.down)+"</div>"
    +'<div class="tt-dev">'+devs+"</div>";}

function render(d){
  latest=d;
  document.getElementById("tActive").textContent=d.stats.active;
  document.getElementById("tDevices").textContent=d.stats.devices;
  document.getElementById("tDests").textContent=d.stats.dests;
  document.getElementById("tFlagged").textContent=d.stats.flagged;

  const th=d.threat||{}, thp=document.getElementById("threatPill"), tht=document.getElementById("threatTxt");
  if(th.loaded){thp.style.display="";thp.className="pill"+(d.stats.flagged?" bad":"");
    tht.textContent="threat lists: "+th.loaded.toLocaleString()+" entries"+(d.stats.flagged?" · "+d.stats.flagged+" hit":"");}
  else if(th.error){thp.style.display="";thp.className="pill warn";tht.textContent="threat: "+th.error;}
  else thp.style.display="none";

  const ab=document.getElementById("alertBtn"),an=document.getElementById("alertN");
  const nA=(d.alerts||[]).length;
  if(nA){an.style.display="";an.textContent=nA>99?"99+":nA;ab.classList.add("has");}
  else{an.style.display="none";ab.classList.remove("has");}
  renderAlerts(d.alerts||[]);

  const cap=d.capture||{}, cp=document.getElementById("capPill"), ct=document.getElementById("capTxt");
  if(cap.error){cp.className="pill bad";ct.textContent="capture: "+cap.error;}
  else{cp.className="pill";
    ct.innerHTML=(cap.demo?'<span class="badge">DEMO</span> ':"")
      +"capture: "+esc(cap.iface||"")+" &middot; "+(cap.pps||0)+" pps"
      +(cap.drops?" &middot; "+cap.drops+" dropped":"");}

  const gp=document.getElementById("geoPill"),gt=document.getElementById("geoTxt");
  gp.className="pill"+(d.geo_state==="ok"?"":d.geo_state==="waiting"?" warn":" bad");
  gt.textContent="geo: "+(d.geo_state==="ok"?"live":d.geo_state==="waiting"?"waiting":"offline");

  const banner=document.getElementById("banner");
  const msg=cap.error?null:tileBanner;
  if(msg){banner.textContent=msg;banner.style.display="block";}else banner.style.display="none";

  // Render the lists/stats FIRST — the map must never be able to block them.
  renderList();

  // Everything below draws on the map and is fully isolated: any Leaflet error
  // (bad coords, a not-yet-sized container in a background tab, etc.) is caught
  // so it can never leave the dashboard stuck on "Waiting for traffic".
  if(!HAS_MAP||!map) return;
  try{
    if(d.home&&!homeMarker){
      homeLL=[d.home.lat,d.home.lon];
      homeMarker=L.marker(homeLL,{icon:dotIcon("home",15),zIndexOffset:1000}).addTo(map)
        .bindTooltip('<div class="tt-host">'+flag(d.home.countryCode)+" Your network</div>"
          +'<div class="tt-ip">'+esc(d.home.city)+", "+esc(d.home.country)+"</div>",
          {className:"nm",direction:"top",offset:[0,-8]});
      map.setView(homeLL,3);
    }
    const seen=new Set();
    for(const x of d.dests){
      if(!x.geo) continue;
      const la=+x.geo.lat, lo=+x.geo.lon;
      if(!isFinite(la)||!isFinite(lo)) continue;
      if(selDev&&!x.devices.includes(selDev)) continue;
      try{
        seen.add(x.ip);
        const ll=[la,lo];
        const bad=!!x.threat;
        const color=bad?"#d03b3b":(selDev?colorFor(selDev):(x.devices.length===1?colorFor(x.devices[0]):BLUE));
        const cls=(x.active?"active":"")+(bad?" bad":"");
        const size=Math.min(9+Math.log2(1+(x.up+x.down)/500)*2.0,24);
        let e=layers.get(x.ip);
        if(!e){
          const marker=L.marker(ll,{icon:dotIcon(cls,size,color),zIndexOffset:bad?800:0}).addTo(map)
            .bindTooltip(destTip(x),{className:"nm",direction:"top",offset:[0,-8],sticky:true});
          let arc=null;
          if(homeLL) arc=L.polyline(arcPoints(homeLL,ll),{color:color,weight:bad?2:1.4,
            opacity:bad?.8:(x.active?.55:.16),className:x.active?"nm-arc":"",interactive:false}).addTo(map);
          e={marker,arc};layers.set(x.ip,e);
        }else{
          e.marker.setIcon(dotIcon(cls,size,color));
          e.marker.setTooltipContent(destTip(x));
          if(e.arc) e.arc.setStyle({color:color,weight:bad?2:1.4,opacity:bad?.8:(x.active?.55:.16),className:x.active?"nm-arc":""});
        }
        e.marker.setOpacity(x.active||bad?1:.4);
      }catch(err){/* skip a single problematic marker, keep going */}
    }
    for(const [ip,e] of layers){if(!seen.has(ip)){map.removeLayer(e.marker);
      if(e.arc)map.removeLayer(e.arc);layers.delete(ip);}}
  }catch(err){/* a map error must never block the dashboard */}
}

function bypassBadges(dv){
  return (dv.bypass||[]).map(t=>t==="doh"
    ?'<span class="badge2 doh" title="Using its own encrypted DNS (DoH)">&#9888; DoH</span>'
    :'<span class="badge2 dns" title="Using an external DNS resolver, bypassing Pi-hole">&#9888; ext-DNS</span>').join("");
}

function renderList(){
  if(!latest)return;
  if(mode==="hist"){renderHistory();return;}
  const q=document.getElementById("q").value.trim().toLowerCase();
  const list=document.getElementById("list");
  let html="";

  const drows=[];
  for(const dv of latest.devices){
    const label=dv.name||dv.ip;
    if(q && !(label+" "+dv.ip).toLowerCase().includes(q)) continue;
    const tb=dv.threats?'<span class="badge2 threat" title="talks to a flagged IP">&#9888;</span>':"";
    drows.push('<div class="row'+(dv.active?"":" off")+(dv.threats?" flag":"")+(selDev===dv.ip?" sel":"")
      +'" data-dev="'+esc(dv.ip)+'"><div class="top"><div class="nm">'
      +'<span class="sw" style="background:'+colorFor(dv.ip)+'"></span>'+esc(label)+" "+tb+bypassBadges(dv)+"</div>"
      +'<div class="cnt">'+dv.ndest+" dest"+(dv.ndest===1?"":"s")+"</div></div>"
      +'<div class="ipline">'+esc(dv.ip)+'</div>'
      +'<div class="bytes">&#8593; '+fmtBytes(dv.up)+" &nbsp; &#8595; "+fmtBytes(dv.down)+"</div></div>");
  }
  const clear=selDev?'<a id="clearSel">show all</a>':"";
  html+='<div class="section-hd"><span>Devices</span>'+clear+"</div>"
    +(drows.length?drows.join(""):'<div class="empty">No devices yet&hellip;</div>');

  const rrows=[];
  for(const x of latest.dests){
    if(!x.geo && q) continue;
    const g=x.geo||{};
    if(selDev && !x.devices.includes(selDev)) continue;
    const hay=(x.ip+" "+(x.host||"")+" "+(g.country||"")+" "+(g.city||"")+" "+(g.isp||"")).toLowerCase();
    if(q && !hay.includes(q)) continue;
    const tb=x.threat?'<span class="badge2 threat">&#9888; flagged</span> ':"";
    rrows.push('<div class="row'+(x.active?"":" off")+(x.threat?" flag":"")+'" data-dest="'+esc(x.ip)+'">'
      +'<div class="top"><div class="nm">'+tb+esc(x.host||g.country||x.ip)+"</div>"
      +'<div class="cnt">'+x.ndev+" dev"+(x.ndev===1?"":"s")+"</div></div>"
      +'<div class="loc">'+flag(g.countryCode)+" "+esc(g.city?g.city+", ":"")
      +(g.country?esc(g.country):"locating&hellip;")+(g.isp?' &middot; <span style="color:var(--text-muted)">'+esc(g.isp)+"</span>":"")+"</div>"
      +'<div class="ipline">'+esc(x.ip)+'</div>'
      +'<div class="bytes">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>");
  }
  html+='<div class="section-hd"><span>Destinations'+(selDev?" &middot; "+esc(devLabel(selDev)):"")+"</span></div>"
    +(rrows.length?rrows.join(""):'<div class="empty">'+(q?"No matches.":"No destinations yet&hellip;")+"</div>");

  list.innerHTML=html;
}

function renderAlerts(alerts){
  const el=document.getElementById("alertList");
  if(!alerts.length){el.innerHTML='<div class="empty">No alerts yet.</div>';return;}
  el.innerHTML=alerts.map(a=>'<div class="al '+esc(a.level)+'"><div class="k">'
    +esc(a.kind.replace(/_/g," "))+" &middot; "+ago(a.ts)+"</div>"
    +'<div class="m"><b>'+esc(a.dev_name||a.dev)+"</b> "+esc(a.msg)+"</div>"
    +(a.host||a.rem?'<div class="w">'+esc(a.host||a.rem)+"</div>":"")+"</div>").join("");
}

// ---- History view ----
let histData=[];
async function loadHistory(){
  try{
    const dev=selDev?("&dev="+encodeURIComponent(selDev)):"";
    const r=await fetch("/history?hours=24"+dev,{cache:"no-store"});
    histData=(await r.json()).rows||[];
  }catch(e){histData=[];}
  renderHistory();
}
function renderHistory(){
  const q=document.getElementById("q").value.trim().toLowerCase();
  const list=document.getElementById("list");
  const rows=histData.filter(r=>{
    const hay=((r.dev_name||r.dev)+" "+(r.host||r.rem)+" "+(r.country||"")).toLowerCase();
    return !q||hay.includes(q);
  }).map(r=>'<div class="row hist'+(r.threat?" flag":"")+'"><div class="top"><div class="nm">'
    +(r.threat?'<span class="badge2 threat">&#9888;</span> ':"")+esc(r.host||r.rem)+"</div>"
    +'<div class="when">'+ago(r.last)+"</div></div>"
    +'<div class="loc">'+flag(r.cc)+" "+esc(r.country||"")+" &middot; "+esc(r.dev_name||r.dev)+"</div>"
    +'<div class="bytes">&#8593; '+fmtBytes(r.up)+" &nbsp; &#8595; "+fmtBytes(r.down)+"</div></div>").join("");
  list.innerHTML='<div class="section-hd"><span>History &middot; last 24h'
    +(selDev?" &middot; "+esc(devLabel(selDev)):"")+"</span></div>"
    +(rows||'<div class="empty">No history in this window yet.</div>');
}

let mode="live";
function setMode(m){
  mode=m;
  document.getElementById("segLive").classList.toggle("on",m==="live");
  document.getElementById("segHist").classList.toggle("on",m==="hist");
  if(m==="hist")loadHistory(); else renderList();
}
document.getElementById("segLive").addEventListener("click",()=>setMode("live"));
document.getElementById("segHist").addEventListener("click",()=>setMode("hist"));

document.getElementById("list").addEventListener("click",e=>{
  if(e.target.id==="clearSel"){selDev=null;wipeLayers();render(latest);return;}
  const drow=e.target.closest("[data-dev]");
  if(drow){selDev=(selDev===drow.dataset.dev)?null:drow.dataset.dev;wipeLayers();
    if(mode==="hist")loadHistory(); else render(latest);return;}
  const rrow=e.target.closest("[data-dest]");
  if(rrow){const e2=layers.get(rrow.dataset.dest);
    if(e2&&map){map.flyTo(e2.marker.getLatLng(),Math.max(map.getZoom(),5));e2.marker.openTooltip();}}
});
function wipeLayers(){for(const [ip,e] of layers){map.removeLayer(e.marker);
  if(e.arc)map.removeLayer(e.arc);}layers.clear();}
document.getElementById("q").addEventListener("input",()=>{mode==="hist"?renderHistory():renderList();});

const alertsPanel=document.getElementById("alerts");
document.getElementById("alertBtn").addEventListener("click",()=>alertsPanel.classList.toggle("open"));
document.getElementById("alertClose").addEventListener("click",()=>alertsPanel.classList.remove("open"));

let quitting=false;
document.getElementById("quitBtn").addEventListener("click",async()=>{
  quitting=true;try{await fetch("/quit",{method:"POST"});}catch(e){}
  document.getElementById("stopped").style.display="grid";});

async function tick(){if(quitting)return;
  try{const r=await fetch("/data",{cache:"no-store"});render(await r.json());}catch(e){}}
tick();setInterval(tick,2500);
</script>
</body>
</html>"""


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    global HOME
    ap = argparse.ArgumentParser(description="NetWatch - network-wide map")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--home", metavar="LAT,LON")
    ap.add_argument("--pihole", metavar="IP", action="append", default=[],
                    help="your Pi-hole IP(s); DNS to anything else flags a bypass")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--no-alerts", action="store_true",
                    help="collect data but never send notifications")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.home:
        try:
            lat, lon = (float(x) for x in args.home.split(","))
            HOME = {"lat": lat, "lon": lon, "city": "", "country": "",
                    "countryCode": ""}
        except ValueError:
            sys.exit("--home must look like 39.74,-104.99")

    print("NetWatch starting...")
    load_config()
    if args.pihole:
        PIHOLE_IPS.update(args.pihole)
    if args.no_alerts:
        CONF["notify"] = {}
    if PIHOLE_IPS:
        print("  Pi-hole IPs: %s" % ", ".join(sorted(PIHOLE_IPS)))
    _load_cache()

    if args.demo:
        print("  DEMO mode - synthesizing traffic, no capture")
        threading.Thread(target=demo_loop, daemon=True).start()
    else:
        if os.name != "posix":
            sys.exit("Capture mode requires Linux. Use --demo to preview the UI.")
        print("  capturing on %s (needs root)" % args.iface)
        threading.Thread(target=capture_loop, args=(args.iface,),
                         daemon=True).start()
        threading.Thread(target=name_worker, daemon=True).start()
    threading.Thread(target=geo_worker, daemon=True).start()
    threading.Thread(target=threat_worker, daemon=True).start()
    threading.Thread(target=db_worker, daemon=True).start()
    threading.Thread(target=seen_writer, daemon=True).start()
    threading.Thread(target=alert_worker, daemon=True).start()

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        sys.exit("  cannot bind %s:%d (%s)" % (args.host, args.port, e))
    shown = args.host if args.host != "0.0.0.0" else "<this-pi-ip>"
    url = "http://%s:%d" % (shown, args.port)
    print("  serving on %s   (Ctrl+C to stop)" % url)
    if not args.no_browser and args.host in ("127.0.0.1", "localhost"):
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nNetWatch stopped."); _save_cache()


if __name__ == "__main__":
    main()
