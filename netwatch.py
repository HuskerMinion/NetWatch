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
import traceback
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
OUI_CACHE = os.path.join(HERE, "netwatch_oui_cache.json")
OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_REFRESH = 30 * 86400
DIGEST_INTERVAL = 7 * 86400
DIGEST_STATE = os.path.join(HERE, "netwatch_digest.json")

STALE_AFTER = 10       # seconds since last packet -> flow shown as fading
DROP_AFTER = 120       # seconds since last packet -> flow removed
GEO_RETRY = 60
CACHE_SAVE_EVERY = 30
CAP_BYTES = 512        # bytes captured per frame (enough for headers + most SNI)
THREAT_REFRESH = 6 * 3600
DB_FLUSH_EVERY = 20
RETAIN_DAYS = 30
MAX_ALERTS = 300
THREAT_CACHE_MAX = 50000   # cap the threat-match memo cache (bounds long-run memory)

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

LOCK = threading.RLock()   # reentrant: a thread may re-acquire without deadlocking
FLOWS = {}      # (dev,rem) -> {dev,rem,proto,ports:set,first,last,pkts,up,down,host}
GEO = {}        # ip -> {status, ts, ...}
DEV_NAMES = {}  # lan_ip -> hostname
IPDOMAIN = {}   # public_ip -> domain (learned from sniffed DNS answers)
BYPASS = {}     # dev_ip -> {"type": set(), "last": ts, "detail": str}
SEEN = {"dev_country": set(), "dev_rem": set()}   # baselines loaded from DB
ALERTS = []     # recent alert dicts (also persisted)
THREAT = {"exact": set(), "nets": [], "loaded": 0, "ts": 0, "error": None}
DEV_MAC = {}    # lan_ip -> MAC string (from sniffed Ethernet headers)
OUI = {}        # 6-hex OUI prefix -> vendor name
OUI_STATE = {"loaded": 0}
INBOUND = {}    # (dev, rem) -> {dev, rem, ports:set, first, last, count}
HOME = None
GEO_STATE = "waiting"
CAP_STATE = {"iface": "", "pkts": 0, "pps": 0.0, "drops": 0, "error": None,
             "demo": False}
START_TS = time.time()
CONF = {}       # loaded from netwatch.conf (alert channels, pihole ip, etc.)
PIHOLE_IPS = set()
IGNORE = set()   # LAN device IPs to exclude entirely (e.g. your resolvers)
SNAP_CACHE = {"bytes": b'{"stats":{"active":0,"devices":0,"dests":0,'
              b'"countries":0,"flagged":0,"alerts":0},"devices":[],"dests":[],'
              b'"alerts":[],"home":null,"geo_state":"waiting","capture":{},'
              b'"threat":{}}', "ts": 0}
HEARTBEAT = {}   # worker name -> last-alive timestamp (for the watchdog)

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


_dns_target_q = []   # (server, kind, ts) bypass targets waiting to be persisted


def _mark_bypass(dev, kind, detail):
    now = time.time()
    b = BYPASS.get(dev)
    if not b:
        b = {"types": set(), "last": 0, "detail": "", "servers": {}}
        BYPASS[dev] = b
    b["types"].add(kind)
    b["last"] = now
    b["detail"] = detail
    if detail:                       # remember the most recent resolver per type
        b.setdefault("servers", {})[kind] = detail
    # Record the resolver/server so the digest can list every DNS destination
    # devices tried to reach (deduped there), for firewall/ACL blocklisting.
    # This is logged for EVERY event, independent of the capped bypass alerts.
    if detail:
        _dns_target_q.append((detail, kind, now))


def _record_inbound(dev, rem, dport):
    now = time.time()
    key = (dev, rem)
    e = INBOUND.get(key)
    if e is None:
        INBOUND[key] = {"dev": dev, "rem": rem, "ports": {dport},
                        "first": now, "last": now, "count": 1}
    else:
        e["ports"].add(dport)
        e["last"] = now
        e["count"] += 1


def mac_vendor(dev):
    """Vendor name for a device from its MAC OUI, or '' if unknown/randomized."""
    mac = DEV_MAC.get(dev)
    if not mac:
        return ""
    try:
        first = int(mac[0:2], 16)
    except ValueError:
        return ""
    if first & 0x02:                 # locally-administered / randomized MAC
        return ""
    oui = mac.replace(":", "")[:6].upper()
    return OUI.get(oui, "")


def capture_loop(iface):
    """Supervisor: runs a capture session and, if it ever dies for any reason,
    re-opens the socket and starts again — so a fluke never leaves the dashboard
    frozen waiting for a manual restart."""
    while True:
        try:
            _capture_session(iface)
        except PermissionError:
            CAP_STATE["error"] = "permission denied (run with sudo)"
            return                                 # never going to succeed
        except Exception as e:
            CAP_STATE["error"] = "capture restarting (%s)" % type(e).__name__
        else:
            CAP_STATE["error"] = "capture ended, restarting"
        time.sleep(3)


def _handle_packet(buf, n, acc, dns_new, bypass_new, mac_new, inbound_new):
    """Process one captured frame into the local accumulators. Callers wrap this
    so a single malformed packet can never kill the capture thread."""
    pk = parse_frame(buf, n)
    if not pk:
        return
    now = time.time()
    if pk["sport"] == 53:                          # a DNS response
        for ip, qname in parse_dns_answers(buf, n, pk["payload"]):
            try:
                if ipaddress.ip_address(ip).is_global and qname:
                    dns_new[ip] = qname.lower().rstrip(".")
            except ValueError:
                pass
    elif pk["dport"] == 53:                        # a DNS query
        try:
            sa = ipaddress.ip_address(pk["src"])
            da = ipaddress.ip_address(pk["dst"])
            # Don't flag an excluded resolver's own upstream DNS as a "bypass".
            if (pk["src"] not in IGNORE and is_private_lan(sa) and da.is_global
                    and pk["dst"] not in PIHOLE_IPS):
                bypass_new.append((pk["src"], "plaintext-dns", pk["dst"]))
        except ValueError:
            pass

    c = classify(pk["src"], pk["dst"])
    if not c:
        return
    dev, rem, direction = c
    if dev in IGNORE:      # excluded device: not listed, mapped, flagged or alerted
        return

    # Unsolicited inbound: a TCP SYN (no ACK) arriving FROM the internet TO a LAN
    # device is someone opening a connection to us (a scan or a hit on a
    # forwarded service), not our own outbound traffic.
    if direction == "in" and pk["proto"] == "tcp" and (pk["flags"] & 0x12) == 0x02:
        inbound_new.append((dev, rem, pk["dport"]))

    # Learn the device's MAC from the source of its outbound frames (src MAC is
    # the LAN device's own hardware address on the wire).
    if direction == "out" and dev not in DEV_MAC and dev not in mac_new:
        mac_new[dev] = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(buf[6:12])

    port = pk["dport"] if direction == "out" else pk["sport"]
    host = None
    if (direction == "out" and pk["proto"] == "tcp" and pk["dport"] == 443
            and pk["payload"] < n and buf[pk["payload"]] == 0x16):
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


def _capture_session(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    except OSError:
        pass
    s.bind((iface, 0))
    try:                    # promiscuous mode: accept mirrored frames
        idx = socket.if_nametoindex(iface)
        mreq = struct.pack("iHH8s", idx, 1, 0, b"")   # ifindex, MR_PROMISC
        s.setsockopt(263, 1, mreq)                    # SOL_PACKET, ADD_MEMBERSHIP
    except OSError as e:
        print("  warning: could not enable promiscuous mode (%s)" % e)
    s.settimeout(1.0)       # wake at least once a second for housekeeping
    CAP_STATE["iface"] = iface
    CAP_STATE["error"] = None

    buf = bytearray(CAP_BYTES)
    acc, dns_new, bypass_new, mac_new, inbound_new = {}, {}, [], {}, []
    count = win_count = 0
    win_start = last_flush = time.time()

    def flush():
        if acc or dns_new or bypass_new or mac_new or inbound_new:
            with LOCK:
                for k, e in acc.items():
                    _merge_flow(k, e, e["last"])
                for ip, dom in dns_new.items():
                    IPDOMAIN.setdefault(ip, dom)
                for dev, kind, detail in bypass_new:
                    _mark_bypass(dev, kind, detail)
                for dev, mac in mac_new.items():
                    DEV_MAC.setdefault(dev, mac)
                for dev, rem, dport in inbound_new:
                    _record_inbound(dev, rem, dport)
            acc.clear(); dns_new.clear(); bypass_new.clear()
            mac_new.clear(); inbound_new.clear()

    try:
        while True:
            try:
                n = s.recv_into(buf, CAP_BYTES)
            except (socket.timeout, OSError):
                n = 0
            if n:
                count += 1
                win_count += 1
                try:
                    _handle_packet(buf, n, acc, dns_new, bypass_new,
                                   mac_new, inbound_new)
                except Exception:
                    pass          # one bad packet must never stop capture
            now = time.time()
            if now - last_flush >= 1.0 or len(acc) > 4000:
                _beat("capture")
                flush()
                dt = now - win_start
                if dt >= 1:
                    CAP_STATE["pps"] = round(win_count / dt, 1)
                    win_start, win_count = now, 0
                CAP_STATE["pkts"] = count
                last_flush = now
                try:
                    st = s.getsockopt(263, 6, 8)   # SOL_PACKET, PACKET_STATISTICS
                    CAP_STATE["drops"] += struct.unpack("II", st)[1]
                except Exception:
                    pass
                _prune(now)
    finally:
        try:
            s.close()
        except Exception:
            pass


def _prune(now):
    with LOCK:
        for k in [k for k, f in FLOWS.items() if now - f["last"] > DROP_AFTER]:
            del FLOWS[k]
        for k in [k for k, v in INBOUND.items() if now - v["last"] > DROP_AFTER]:
            del INBOUND[k]


# ----------------------------------------------------------------------------
# Demo mode (no root; synthesize plausible flows to preview the UI)
# ----------------------------------------------------------------------------

def demo_loop():
    CAP_STATE["demo"] = True
    CAP_STATE["iface"] = "demo"
    devices = ["192.168.1.20", "192.168.1.31", "192.168.1.44", "192.168.1.57",
               "192.168.1.66"]
    dnames = {"192.168.1.20": "terry-pc", "192.168.1.31": "living-room-tv",
              "192.168.1.44": "pixel-phone", "192.168.1.57": "ring-doorbell"}
    # 192.168.1.66 intentionally has no hostname -> named by MAC vendor instead
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
        # MAC vendor demo: the un-named device resolves to a vendor name
        DEV_MAC["192.168.1.66"] = "44:07:0b:11:22:33"
        OUI["44070B"] = "Amazon Technologies"; OUI_STATE["loaded"] = 1
        # An unsolicited inbound connection attempt (e.g. hitting a forwarded port)
        _record_inbound("192.168.1.20", "185.220.101.5", 22)
        _record_inbound("192.168.1.20", "185.220.101.5", 22)
        # DNS-bypass demo: one device reaches SEVERAL resolvers. This shows both
        # the per-device alert cap (many attempts -> only 2 alerts) and the
        # deduplicated DNS-server list in the digest (every server still logged).
        for srv in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"):
            _mark_bypass("192.168.1.31", "plaintext-dns", srv)
        _mark_bypass("192.168.1.57", "doh", "dns.google")
        _mark_bypass("192.168.1.57", "doh", "cloudflare-dns.com")
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
        # One device keeps reaching new resolvers over time: shows the 2-alert
        # cap (only 2 shown, rest suppressed) while every server is still logged
        # to the digest's DNS-server list.
        if i % 20 == 0:
            rr = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
                  "94.140.14.14")
            with LOCK:
                _mark_bypass("192.168.1.31", "plaintext-dns",
                             rr[(i // 20) % len(rr)])
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
        _beat("geo")
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
    global CONF, PIHOLE_IPS, IGNORE
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
    IGNORE = set(cfg.get("ignore_devices", []))


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


def oui_worker():
    """Download and cache the IEEE OUI list so unknown devices can be named by
    their hardware vendor (e.g. 'Espressif', 'Amazon Technologies')."""
    try:                                    # instant start from disk cache
        with open(OUI_CACHE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with LOCK:
            OUI.update(data)
            OUI_STATE["loaded"] = len(OUI)
    except Exception:
        pass
    while True:
        if OUI_STATE["loaded"] == 0:
            try:
                text = _http_text(OUI_URL, timeout=60)
                table = {}
                for line in text.splitlines():
                    # CSV: Registry,Assignment(6 hex),Organization Name,Address
                    parts = line.split(",", 3)
                    if len(parts) >= 3 and len(parts[1]) == 6:
                        try:
                            int(parts[1], 16)
                        except ValueError:
                            continue
                        vendor = parts[2].strip().strip('"')
                        if vendor:
                            table[parts[1].upper()] = vendor[:40]
                if table:
                    with LOCK:
                        OUI.clear(); OUI.update(table)
                        OUI_STATE["loaded"] = len(OUI)
                    try:
                        with open(OUI_CACHE, "w", encoding="utf-8") as f:
                            json.dump(table, f)
                    except Exception:
                        pass
                    print("  loaded %d MAC vendor prefixes" % len(table))
            except Exception:
                pass
        time.sleep(OUI_REFRESH)


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
    # Bound the cache: on an always-on service the set of distinct remote IPs
    # grows forever, so clear (and re-memoize on demand) once it gets large.
    if len(_threat_verdict) >= THREAT_CACHE_MAX:
        _threat_verdict.clear()
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
    con.execute("""CREATE TABLE IF NOT EXISTS dns_targets(
        server TEXT PRIMARY KEY, kind TEXT, first REAL, last REAL,
        hits INTEGER)""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_dns_last ON dns_targets(last)")
    con.execute("""CREATE TABLE IF NOT EXISTS bypass_seen(
        dev TEXT, server TEXT, alerts INTEGER, PRIMARY KEY(dev, server))""")
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
        for dev, server, alerts in con.execute(
                "SELECT dev,server,alerts FROM bypass_seen"):
            _bypass_alert_count[(dev, server)] = alerts
    print("  history: %d known (device,country) pairs, %d alerts, "
          "%d bypass pairs seen"
          % (len(SEEN["dev_country"]), len(ALERTS), len(_bypass_alert_count)))


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
        _beat("db")
        now = time.time()
        # Snapshot the raw flow data under the lock, then do the expensive
        # threat matching AFTER releasing it (threat_match takes the lock itself
        # and iterates thousands of CIDRs — never hold LOCK across that).
        with LOCK:
            raw = [(f["dev"], DEV_NAMES.get(f["dev"]) or mac_vendor(f["dev"]), f["rem"],
                    f.get("host") or IPDOMAIN.get(f["rem"], ""),
                    (GEO.get(f["rem"]) or {}), f["first"], f["last"],
                    f["up"], f["down"]) for f in FLOWS.values()]
            pending = list(_alert_persist_q)
            _alert_persist_q.clear()
            dns_pending = list(_dns_target_q)
            _dns_target_q.clear()
            bypass_pending = list(_bypass_persist_q)
            _bypass_persist_q.clear()
        rows = []
        for dev, name, rem, host, g, first, last, up, down in raw:
            gg = g if g.get("status") == "ok" else {}
            rows.append((dev, name, rem, host, gg.get("country", ""),
                         gg.get("countryCode", ""), first, last, up, down,
                         threat_match(rem) or ""))
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
            for server, kind, ts in dns_pending:
                # dedup by server: keep first-seen time, bump last + hit count
                con.execute(
                    "INSERT INTO dns_targets(server,kind,first,last,hits)"
                    " VALUES(?,?,?,?,1) ON CONFLICT(server) DO UPDATE SET"
                    " last=excluded.last, hits=hits+1", (server, kind, ts, ts))
            for dev, server in bypass_pending:
                # persist the per-(device,resolver) bypass alert count so the
                # 2-alert cap survives restarts (and clears)
                con.execute(
                    "INSERT INTO bypass_seen(dev,server,alerts) VALUES(?,?,1)"
                    " ON CONFLICT(dev,server) DO UPDATE SET alerts=alerts+1",
                    (dev, server))
            if now - last_prune > 3600:
                cutoff = now - RETAIN_DAYS * 86400
                con.execute("DELETE FROM sessions WHERE last < ?", (cutoff,))
                con.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
                con.execute("DELETE FROM dns_targets WHERE last < ?", (cutoff,))
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
_bypass_alert_count = {}  # (dev, server) -> bypass alerts shown (persistent, capped)
_bypass_persist_q = []    # (dev, server) increments waiting to be written to DB
BYPASS_ALERT_MAX = 2      # alerts per (device, resolver). After this the pair goes
                          # quiet for good (survives clears + restarts); the resolver
                          # lives on in the digest's DNS-server list. New/unique
                          # resolvers still alert. Logging is never affected.


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
        try:
            _beat("alert")
            _alert_pass(warmup)
        except Exception:
            pass          # never let alert evaluation kill its own thread


def _alert_pass(warmup):
    now = time.time()
    learning = (now - START_TS) < warmup
    with LOCK:
        flows = list(FLOWS.values())
        geo = dict(GEO)
        names = dict(DEV_NAMES)
        bypass = {d: dict(v, types=set(v["types"]),
                          servers=dict(v.get("servers", {})))
                  for d, v in BYPASS.items()}
        inbound = [(v["dev"], v["rem"], sorted(v["ports"])[0] if v["ports"] else 0)
                   for v in INBOUND.values()]
    if True:
        # unsolicited inbound connection attempts (someone connecting TO us)
        for dev, rem, port in inbound:
            th = threat_match(rem)
            _fire("inbound", dev, rem, "", None, names, learning=False,
                  msg="unsolicited inbound connection from %s to port %d%s"
                      % (rem, port, " [ON THREAT LIST]" if th else ""))
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
        # bypass alerts — one (device, resolver) pair at a time so the per-pair
        # cap in _fire applies to each distinct DNS server independently.
        for dev, b in bypass.items():
            for t, server in b.get("servers", {}).items():
                if not server:
                    continue
                _fire("bypass_" + t, dev, server, "", None, names, learning,
                      msg=("device using its own %s (%s), bypassing your Pi-hole"
                           % ("encrypted DNS/DoH" if t == "doh" else "external DNS",
                              server)))


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
    elif kind == "inbound":
        level, rem_field = "warning", key
    elif kind.startswith("bypass_"):
        if learning:
            return
        level = "warning"
    else:
        return
    # DNS-bypass: cap per (device, resolver) instead of the generic once-per-window
    # dedup. Each distinct resolver a device reaches alerts up to BYPASS_ALERT_MAX
    # times, then goes quiet permanently — the count is persisted, so clearing
    # alerts or restarting won't resurface it. A brand-new resolver still alerts.
    # Everything is logged regardless (DB sessions + the digest DNS-server list).
    if kind.startswith("bypass_"):
        pair = (dev, key)                      # key is the resolver/server
        if _bypass_alert_count.get(pair, 0) >= BYPASS_ALERT_MAX:
            return
        _bypass_alert_count[pair] = _bypass_alert_count.get(pair, 0) + 1
        _bypass_persist_q.append(pair)
        _emit_alert(level, kind, dev, key, host, msg)
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


def _send_email(subject, body):
    em = (CONF.get("notify") or {}).get("email")
    if not em:
        return False
    msg = EmailMessage()
    msg["From"] = em["from"]
    msg["To"] = em["to"]
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(em["smtp_host"], int(em.get("smtp_port", 587)), timeout=20) as s:
        s.starttls()
        if em.get("username"):
            s.login(em["username"], em["password"])
        s.send_message(msg)
    return True


def _fmt_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return "%.1f %s" % (b, unit)
        b /= 1024
    return "%.1f PB" % b


def digest_data(days):
    """Structured summary of the last `days` days, shared by the on-screen
    digest panel and the weekly email."""
    since = time.time() - days * 86400
    try:
        con = db_connect()
        sess = con.execute("SELECT dev,dev_name,rem,host,cc,country,up,down,threat "
                           "FROM sessions WHERE last>=?", (since,)).fetchall()
        alerts = con.execute("SELECT kind FROM alerts WHERE ts>=?",
                             (since,)).fetchall()
        dns_rows = con.execute(
            "SELECT server,kind,hits FROM dns_targets WHERE last>=? "
            "ORDER BY hits DESC, server", (since,)).fetchall()
        con.close()
    except Exception:
        sess, alerts, dns_rows = [], [], []
    dev_b, dest_b, countries, threats = {}, {}, set(), []
    total = 0
    for dev, dname, rem, host, cc, country, up, down, threat in sess:
        up, down = up or 0, down or 0
        total += up + down
        d = dev_b.setdefault(dev, {"name": dname or dev, "up": 0, "down": 0})
        if dname:
            d["name"] = dname
        d["up"] += up; d["down"] += down
        t = dest_b.setdefault(rem, {"host": host or rem, "cc": cc or "",
                                    "up": 0, "down": 0})
        if host and t["host"] == rem:
            t["host"] = host
        t["up"] += up; t["down"] += down
        if cc:
            countries.add(cc)
        if threat:
            threats.append({"dev": dname or dev, "rem": host or rem,
                            "country": country or cc})
    by_kind = {}
    for (kind,) in alerts:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    top_dev = sorted(({"name": v["name"], "up": v["up"], "down": v["down"],
                       "total": v["up"] + v["down"]} for v in dev_b.values()),
                     key=lambda x: -x["total"])[:10]
    top_dst = sorted(({"host": v["host"], "cc": v["cc"], "up": v["up"],
                       "down": v["down"], "total": v["up"] + v["down"]}
                      for v in dest_b.values()), key=lambda x: -x["total"])[:10]
    # Deduplicated list of DNS servers/resolvers devices tried to reach (for
    # blocklisting at a firewall/ACL). SQLite PRIMARY KEY already dedups by
    # server; label the kind in plain English.
    dns_targets = [{"server": s,
                    "kind": "encrypted DNS/DoH" if k == "doh" else "external DNS",
                    "hits": h} for (s, k, h) in dns_rows]
    return {"days": days, "total": total, "devices": len(dev_b),
            "dests": len(dest_b), "countries": len(countries),
            "top_devices": top_dev, "top_dests": top_dst,
            "alerts_total": len(alerts), "alerts_by_kind": by_kind,
            "threats": threats, "dns_targets": dns_targets}


def build_digest():
    d = digest_data(DIGEST_INTERVAL // 86400)
    L = ["NetWatch weekly digest", "=" * 40, ""]
    L.append("Total traffic seen: %s across %d devices, %d destinations, "
             "%d countries." % (_fmt_bytes(d["total"]), d["devices"],
                                d["dests"], d["countries"]))
    L.append("")
    L.append("Top talkers (by data volume):")
    for x in d["top_devices"]:
        L.append("  %-22s %s" % (x["name"], _fmt_bytes(x["total"])))
    L.append("")
    L.append("Alerts this week: %d total" % d["alerts_total"])
    for kind, cnt in sorted(d["alerts_by_kind"].items(), key=lambda x: -x[1]):
        L.append("  %-18s %d" % (kind.replace("_", " "), cnt))
    if d["threats"]:
        L.append("")
        L.append("Threat-list hits (%d):" % len(d["threats"]))
        for t in d["threats"][:15]:
            L.append("  %s -> %s (%s)" % (t["dev"], t["rem"], t["country"]))
    if d.get("dns_targets"):
        L.append("")
        L.append("DNS servers devices tried to reach (%d) - candidates to block "
                 "at your firewall/ACL:" % len(d["dns_targets"]))
        for t in d["dns_targets"]:
            L.append("  %-24s %-18s (%d hits)"
                     % (t["server"], t["kind"], t["hits"]))
    L.append("")
    L.append("- NetWatch")
    return "\n".join(L)


def digest_worker():
    def last_sent():
        try:
            return json.load(open(DIGEST_STATE))["last"]
        except Exception:
            return 0
    # seed the clock on first run so the first digest fires a week from now
    if last_sent() == 0:
        try:
            json.dump({"last": time.time()}, open(DIGEST_STATE, "w"))
        except Exception:
            pass
    while True:
        time.sleep(3600)
        try:
            if not CONF.get("weekly_digest"):
                continue
            if not (CONF.get("notify") or {}).get("email"):
                continue
            if time.time() - last_sent() < DIGEST_INTERVAL:
                continue
            if _send_email("NetWatch weekly digest", build_digest()):
                json.dump({"last": time.time()}, open(DIGEST_STATE, "w"))
                print("  weekly digest emailed", flush=True)
        except Exception as e:
            print("  digest error: %s" % e, flush=True)


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
        vendors = {d: mac_vendor(d) for d in {f["dev"] for f in flows}}
        inbound_raw = [dict(v, ports=sorted(v["ports"])[:6]) for v in INBOUND.values()]

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
            "ip": f["dev"], "name": names.get(f["dev"]) or "",
            "vendor": vendors.get(f["dev"], ""), "dests": set(),
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

    # Inbound connection attempts, enriched with location + threat
    inbound = []
    for v in inbound_raw:
        g = geo.get(v["rem"])
        gg = g if (g and g.get("status") == "ok") else {}
        inbound.append({
            "dev": v["dev"], "dev_name": names.get(v["dev"]) or vendors.get(v["dev"], ""),
            "rem": v["rem"], "ports": v["ports"], "count": v["count"],
            "age": round(now - v["last"], 1),
            "active": now - v["last"] <= STALE_AFTER,
            "country": gg.get("country", ""), "cc": gg.get("countryCode", ""),
            "isp": gg.get("isp", ""), "threat": threat_match(v["rem"])})
    inbound.sort(key=lambda x: (-x["active"], -x["count"]))

    # Top talkers by data volume
    top_devices = sorted(
        ({"ip": d["ip"], "name": d["name"] or d["vendor"] or d["ip"],
          "up": d["up"], "down": d["down"], "total": d["up"] + d["down"]}
         for d in dev_list), key=lambda d: -d["total"])[:12]
    top_dests = sorted(
        ({"ip": d["ip"], "host": d["host"] or d["ip"],
          "cc": (d["geo"] or {}).get("countryCode", ""),
          "up": d["up"], "down": d["down"], "total": d["up"] + d["down"]}
         for d in dest_list), key=lambda d: -d["total"])[:12]

    return {
        "home": HOME, "geo_state": GEO_STATE,
        "capture": {"iface": CAP_STATE["iface"], "pps": CAP_STATE["pps"],
                    "drops": CAP_STATE["drops"], "error": CAP_STATE["error"],
                    "demo": CAP_STATE["demo"]},
        "threat": threat_stat,
        "stats": {"active": active_flows, "devices": len(dev_list),
                  "dests": len(dest_list), "countries": len(countries),
                  "flagged": flagged, "alerts": len(alerts),
                  "inbound": len(inbound)},
        "alerts": alerts,
        "devices": dev_list, "dests": dest_list, "inbound": inbound,
        "top_devices": top_devices, "top_dests": top_dests,
    }


def _beat(name):
    HEARTBEAT[name] = time.time()


def watchdog():
    """Every 8s log the liveness of each worker. If the dashboard snapshot stops
    advancing (the freeze the user sees), dump every thread's stack so we can see
    exactly where it is stuck. Watch live with: journalctl -u netwatch -f"""
    dumped = False
    while True:
        time.sleep(8)
        now = time.time()
        snap_age = now - SNAP_CACHE.get("ts", 0)
        if snap_age > 5:            # only speak up when something is lagging
            ages = {n: round(now - t, 1) for n, t in list(HEARTBEAT.items())}
            print("HEARTBEAT worker-ages(s)=%s snapshot-age=%.1f" % (ages, snap_age),
                  flush=True)
        if snap_age > 12 and not dumped:
            dumped = True
            print("=" * 60, flush=True)
            print("WATCHDOG: dashboard FROZEN (snapshot stale %.1fs). "
                  "Thread stacks follow:" % snap_age, flush=True)
            names = {t.ident: t.name for t in threading.enumerate()}
            for ident, frame in sys._current_frames().items():
                print("--- thread: %s ---" % names.get(ident, ident), flush=True)
                print("".join(traceback.format_stack(frame)), flush=True)
            print("=" * 60, flush=True)
        elif snap_age <= 12:
            dumped = False


def snapshot_worker():
    """Rebuild the /data payload once every ~1.5s so each HTTP request just
    returns pre-serialized bytes. This keeps the server responsive no matter
    how large the flow table gets or how many browsers/tabs are polling."""
    while True:
        try:
            _beat("snapshot")
            _prune(time.time())     # backstop: clears stale flows regardless of capture
            SNAP_CACHE["bytes"] = json.dumps(snapshot()).encode("utf-8")
            SNAP_CACHE["ts"] = time.time()
        except Exception:
            pass
        time.sleep(1.5)


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def _host_ok(self):
        """Anti-DNS-rebinding: only serve requests whose Host is this LAN box, not
        an attacker-controlled public name that rebinds to our IP. Allows
        localhost, private/loopback/link-local IP literals, *.local (mDNS), plain
        single-label hostnames (can't be public domains), and any name in
        CONF['allow_hosts']. Set CONF['host_check']=false to disable entirely."""
        if not CONF.get("host_check", True):
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        host = host.rsplit(":", 1)[0].strip("[]") if host else ""
        if not host:
            return False
        if host == "localhost" or host in {h.lower() for h in
                                           CONF.get("allow_hosts", [])}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            pass
        return host.endswith(".local") or "." not in host

    def _csrf_ok(self):
        """CSRF guard for state-changing POSTs. Requires the custom header the
        dashboard sends (a cross-site <form> can't set it, and a cross-site fetch
        that does triggers a CORS preflight we never approve), plus a same-origin
        Origin check as defense in depth."""
        if self.headers.get("X-NetWatch") != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            from urllib.parse import urlparse as _up
            o = _up(origin).netloc.rsplit(":", 1)[0].strip("[]").lower()
            h = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            if o and o != h:
                return False
        return True

    def _deny(self, code=403):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self._host_ok():
            self._deny(); return
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path == "/" or u.path.startswith("/index"):
            body = HTML_PAGE.encode("utf-8"); ctype = "text/html; charset=utf-8"
        elif u.path == "/data":
            body = SNAP_CACHE["bytes"]; ctype = "application/json"
        elif u.path == "/history":
            q = parse_qs(u.query)
            hours = float(q.get("hours", ["24"])[0])
            dev = q.get("dev", [None])[0]
            since = time.time() - hours * 3600
            body = json.dumps({"rows": db_history(since, dev)}).encode("utf-8")
            ctype = "application/json"
        elif u.path == "/digest":
            q = parse_qs(u.query)
            days = max(1, min(90, int(float(q.get("days", ["7"])[0]))))
            body = json.dumps(digest_data(days)).encode("utf-8")
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
        if not self._host_ok() or not self._csrf_ok():
            self._deny(); return
        if self.path == "/quit":
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
            _save_cache()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        elif self.path == "/alerts/clear":
            with LOCK:
                ALERTS.clear()
                _alert_dedup.clear()   # let repeats re-alert after a manual clear
                # NOTE: _bypass_alert_count is deliberately NOT reset — a device's
                # bypass to a given resolver alerts only twice ever, then stays
                # quiet across clears/restarts (the resolver is in the digest list).
            try:
                con = db_connect(); con.execute("DELETE FROM alerts")
                con.commit(); con.close()
            except Exception:
                pass
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
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
  .tile.inbound b{color:var(--warn)}
  .vendor{color:var(--text-muted);font-weight:400;font-size:11px}
  /* top talkers */
  .tt-row{padding:7px 12px;border-bottom:1px solid #262623}
  .tt-row .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .tt-row .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tt-row .tot{color:var(--text-secondary);font-size:11px;flex:none;font-variant-numeric:tabular-nums}
  .bar{height:6px;border-radius:3px;background:var(--surface-3);margin-top:5px;overflow:hidden}
  .bar i{display:block;height:100%;background:var(--series-1);border-radius:3px}
  .bar i.dl{background:var(--series-1)}
  .updown{color:var(--text-muted);font-size:10px;margin-top:2px}
  /* inbound rows */
  .inb{padding:8px 12px;border-bottom:1px solid #262623;border-left:3px solid var(--warn)}
  .inb.bad{border-left-color:var(--bad)}
  .inb .nm{font-weight:600}
  .inb .meta{color:var(--text-secondary);font-size:12px;margin-top:1px}
  .inb .ipline{color:var(--text-muted);font-size:11px;font-family:Consolas,ui-monospace,monospace;margin-top:1px}
  .dg-note{color:var(--text-muted);font-size:11px;padding:2px 14px 6px}
  #alertClear{font-size:11px !important;border:1px solid var(--border) !important;border-radius:6px;
    padding:3px 9px !important;margin-right:8px;color:var(--text-secondary) !important}
  #alertClear:hover{border-color:var(--bad) !important;color:var(--text-primary) !important}
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
  /* digest panel */
  #digest{position:absolute;top:0;right:0;width:420px;max-width:94vw;height:100%;z-index:1500;
    background:var(--surface-2);border-left:1px solid var(--border);box-shadow:-8px 0 24px #0009;
    transform:translateX(100%);transition:transform .18s ease;display:flex;flex-direction:column}
  #digest.open{transform:none}
  #digest .hd{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;
    border-bottom:1px solid var(--border);font-weight:600}
  #digest .hd button{background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer}
  .dseg{display:flex;gap:2px;padding:8px 12px;border-bottom:1px solid var(--border)}
  .dseg button{flex:1;background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);
    padding:5px;font:inherit;font-size:11px;cursor:pointer;border-radius:6px}
  .dseg button.on{background:#20303f;border-color:var(--series-1);color:var(--text-primary)}
  #digestBody{overflow-y:auto;flex:1;padding:4px 0 30px}
  .dg-hero{padding:14px;text-align:center;border-bottom:1px solid var(--border)}
  .dg-hero b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
  .dg-hero small{color:var(--text-muted);font-size:12px}
  .dg-stats{display:flex;justify-content:space-around;padding:10px 8px;border-bottom:1px solid var(--border);text-align:center}
  .dg-stats div b{display:block;font-size:16px} .dg-stats div small{color:var(--text-muted);font-size:10px;text-transform:uppercase}
  #digestBtn{align-self:center;background:var(--surface-3);border:1px solid var(--border);
    color:var(--text-secondary);border-radius:8px;padding:6px 10px;font:inherit;font-size:11px;cursor:pointer}
  #digestBtn:hover{border-color:var(--series-1);color:var(--text-primary)}
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
      <div class="tile inbound"><b id="tInbound">–</b><small>inbound</small></div>
      <button id="digestBtn" title="Show a summary">&#9776; digest</button>
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
        <button id="segTop">Top Talkers</button>
      </div>
      <div id="list"><div class="empty">Waiting for traffic&hellip;</div></div>
    </aside>
  </main>
</div>
<div id="alerts">
  <div class="hd"><span>Alerts</span><span>
    <button id="alertClear" title="Clear all alerts">clear</button>
    <button id="alertClose">&times;</button></span></div>
  <div id="alertList"><div class="empty">No alerts yet.</div></div>
</div>
<div id="digest">
  <div class="hd"><span>Summary</span><button id="digestClose">&times;</button></div>
  <div class="dseg">
    <button data-days="1" class="on">24 h</button>
    <button data-days="7">7 days</button>
    <button data-days="30">30 days</button>
  </div>
  <div id="digestBody"><div class="empty">Loading&hellip;</div></div>
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
  return n?(n.name||n.vendor||ip):ip;}
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
  document.getElementById("tInbound").textContent=d.stats.inbound||0;

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

function inboundRow(ib){
  return '<div class="inb'+(ib.threat?" bad":"")+'"><div class="nm">'
    +(ib.threat?'<span class="badge2 threat">&#9888; flagged</span> ':"")
    +flag(ib.cc)+" "+esc(ib.rem)+"</div>"
    +'<div class="meta">to <b>'+esc(ib.dev_name||ib.dev)+"</b> on port"+(ib.ports.length>1?"s":"")
    +" "+ib.ports.join(", ")+(ib.country?" &middot; from "+esc(ib.country):"")+"</div>"
    +'<div class="ipline">'+ib.count+" attempt"+(ib.count===1?"":"s")
    +(ib.isp?" &middot; "+esc(ib.isp):"")+"</div></div>";
}

function renderList(){
  if(!latest)return;
  if(mode==="hist"){renderHistory();return;}
  if(mode==="top"){renderTop();return;}
  const q=document.getElementById("q").value.trim().toLowerCase();
  const list=document.getElementById("list");
  let html="";

  // Inbound connection attempts (usually empty behind NAT; shown when present)
  if(latest.inbound && latest.inbound.length){
    const ib=latest.inbound.filter(x=>{
      const hay=(x.rem+" "+(x.dev_name||x.dev)+" "+(x.country||"")).toLowerCase();
      return !q||hay.includes(q);
    });
    if(ib.length)
      html+='<div class="section-hd"><span>&#9888; Inbound connections</span></div>'
        +ib.map(inboundRow).join("");
  }

  const drows=[];
  for(const dv of latest.devices){
    const label=dv.name||dv.vendor||dv.ip;
    if(q && !(label+" "+dv.ip).toLowerCase().includes(q)) continue;
    const tb=dv.threats?'<span class="badge2 threat" title="talks to a flagged IP">&#9888;</span>':"";
    const vend=(!dv.name&&dv.vendor)?'<span class="vendor">('+esc(dv.vendor)+")</span>":"";
    drows.push('<div class="row'+(dv.active?"":" off")+(dv.threats?" flag":"")+(selDev===dv.ip?" sel":"")
      +'" data-dev="'+esc(dv.ip)+'"><div class="top"><div class="nm">'
      +'<span class="sw" style="background:'+colorFor(dv.ip)+'"></span>'+esc(label)+" "+vend+" "+tb+bypassBadges(dv)+"</div>"
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

function renderTop(){
  const list=document.getElementById("list");
  const dv=latest.top_devices||[], ds=latest.top_dests||[];
  const maxD=Math.max(1,...dv.map(x=>x.total));
  const maxT=Math.max(1,...ds.map(x=>x.total));
  const bar=(v,max,cls)=>'<div class="bar"><i class="'+cls+'" style="width:'
    +Math.max(2,Math.round(v/max*100))+'%"></i></div>';
  let html='<div class="section-hd"><span>Top devices by volume</span></div>';
  html+=dv.length?dv.map(x=>'<div class="tt-row"><div class="top"><div class="nm">'
    +esc(x.name)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"
    +bar(x.total,maxD,"")
    +'<div class="updown">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>").join("")
    :'<div class="empty">No traffic yet&hellip;</div>';
  html+='<div class="section-hd"><span>Top destinations by volume</span></div>';
  html+=ds.length?ds.map(x=>'<div class="tt-row"><div class="top"><div class="nm">'
    +flag(x.cc)+" "+esc(x.host)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"
    +bar(x.total,maxT,"")
    +'<div class="updown">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>").join("")
    :'<div class="empty">No traffic yet&hellip;</div>';
  list.innerHTML=html;
}

let mode="live";
function setMode(m){
  mode=m;
  document.getElementById("segLive").classList.toggle("on",m==="live");
  document.getElementById("segHist").classList.toggle("on",m==="hist");
  document.getElementById("segTop").classList.toggle("on",m==="top");
  if(m==="hist")loadHistory(); else renderList();
}
document.getElementById("segLive").addEventListener("click",()=>setMode("live"));
document.getElementById("segHist").addEventListener("click",()=>setMode("hist"));
document.getElementById("segTop").addEventListener("click",()=>setMode("top"));

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
document.getElementById("alertClear").addEventListener("click",async()=>{
  try{await fetch("/alerts/clear",{method:"POST",headers:{"X-NetWatch":"1"}});}catch(e){}
  renderAlerts([]);
  document.getElementById("alertN").style.display="none";
  document.getElementById("alertBtn").classList.remove("has");
});

// ---- Digest panel ----
const digestPanel=document.getElementById("digest");
let digestDays=1;
async function loadDigest(){
  const body=document.getElementById("digestBody");
  body.innerHTML='<div class="empty">Loading&hellip;</div>';
  let d;
  try{ d=await (await fetch("/digest?days="+digestDays,{cache:"no-store"})).json(); }
  catch(e){ body.innerHTML='<div class="empty">Could not load summary.</div>'; return; }
  const label=digestDays===1?"last 24 hours":"last "+digestDays+" days";
  const maxD=Math.max(1,...d.top_devices.map(x=>x.total));
  const maxT=Math.max(1,...d.top_dests.map(x=>x.total));
  const bar=(v,max)=>'<div class="bar"><i style="width:'+Math.max(2,Math.round(v/max*100))+'%"></i></div>';
  let h='<div class="dg-hero"><b>'+fmtBytes(d.total)+"</b><small>total traffic &middot; "+label+"</small></div>";
  h+='<div class="dg-stats">'
    +'<div><b>'+d.devices+"</b><small>devices</small></div>"
    +'<div><b>'+d.dests+"</b><small>destinations</small></div>"
    +'<div><b>'+d.countries+"</b><small>countries</small></div>"
    +'<div><b>'+d.alerts_total+"</b><small>alerts</small></div></div>";
  h+='<div class="section-hd"><span>Top devices</span></div>';
  h+=d.top_devices.length?d.top_devices.map(x=>'<div class="tt-row"><div class="top">'
    +'<div class="nm">'+esc(x.name)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"+bar(x.total,maxD)
    +'<div class="updown">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>").join("")
    :'<div class="empty">No traffic in this window.</div>';
  h+='<div class="section-hd"><span>Top destinations</span></div>';
  h+=d.top_dests.length?d.top_dests.map(x=>'<div class="tt-row"><div class="top">'
    +'<div class="nm">'+flag(x.cc)+" "+esc(x.host)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"+bar(x.total,maxT)+"</div>").join("")
    :"";
  h+='<div class="section-hd"><span>Alerts ('+d.alerts_total+")</span></div>";
  const kinds=Object.entries(d.alerts_by_kind).sort((a,b)=>b[1]-a[1]);
  h+=kinds.length?kinds.map(([k,c])=>'<div class="row"><div class="top"><div class="nm">'
    +esc(k.replace(/_/g," "))+'</div><div class="cnt">'+c+"</div></div></div>").join("")
    :'<div class="empty">No alerts in this window.</div>';
  if(d.threats.length){
    h+='<div class="section-hd"><span>&#9888; Threat-list hits ('+d.threats.length+")</span></div>";
    h+=d.threats.slice(0,20).map(t=>'<div class="row flag"><div class="nm">'+esc(t.dev)
      +" &rarr; "+esc(t.rem)+'</div><div class="ipline">'+esc(t.country||"")+"</div></div>").join("");
  }
  if(d.dns_targets&&d.dns_targets.length){
    h+='<div class="section-hd"><span>DNS servers to block ('+d.dns_targets.length+")</span></div>";
    h+='<div class="dg-note">Resolvers devices tried to reach &mdash; block these at your firewall/ACL.</div>';
    h+=d.dns_targets.map(t=>'<div class="row"><div class="top">'
      +'<div class="nm">'+esc(t.server)+'</div><div class="cnt">'+t.hits+"</div></div>"
      +'<div class="ipline">'+esc(t.kind)+"</div></div>").join("");
  }
  document.getElementById("digestBody").innerHTML=h;
}
document.getElementById("digestBtn").addEventListener("click",()=>{
  const opening=!digestPanel.classList.contains("open");
  digestPanel.classList.toggle("open");
  if(opening)loadDigest();
});
document.getElementById("digestClose").addEventListener("click",()=>digestPanel.classList.remove("open"));
document.querySelectorAll(".dseg button").forEach(b=>b.addEventListener("click",()=>{
  digestDays=+b.dataset.days;
  document.querySelectorAll(".dseg button").forEach(x=>x.classList.toggle("on",x===b));
  loadDigest();
}));

let quitting=false;
document.getElementById("quitBtn").addEventListener("click",async()=>{
  quitting=true;try{await fetch("/quit",{method:"POST",headers:{"X-NetWatch":"1"}});}catch(e){}
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
    ap.add_argument("--ignore", metavar="IP", action="append", default=[],
                    help="LAN device IP(s) to exclude entirely (e.g. your resolvers)")
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
    if args.ignore:
        IGNORE.update(args.ignore)
    if args.no_alerts:
        CONF["notify"] = {}
    if PIHOLE_IPS:
        print("  Pi-hole IPs: %s" % ", ".join(sorted(PIHOLE_IPS)))
    if IGNORE:
        print("  ignoring devices: %s" % ", ".join(sorted(IGNORE)))
    _load_cache()

    if args.demo:
        print("  DEMO mode - synthesizing traffic, no capture")
        CONF["learn_minutes"] = 0   # skip warm-up so alerts show immediately
        threading.Thread(target=demo_loop, name="demo", daemon=True).start()
    else:
        if os.name != "posix":
            sys.exit("Capture mode requires Linux. Use --demo to preview the UI.")
        print("  capturing on %s (needs root)" % args.iface)
        threading.Thread(target=capture_loop, args=(args.iface,),
                         name="capture", daemon=True).start()
        threading.Thread(target=name_worker, name="name", daemon=True).start()
    threading.Thread(target=geo_worker, name="geo", daemon=True).start()
    threading.Thread(target=threat_worker, name="threat", daemon=True).start()
    threading.Thread(target=oui_worker, name="oui", daemon=True).start()
    threading.Thread(target=db_worker, name="db", daemon=True).start()
    threading.Thread(target=seen_writer, name="seen", daemon=True).start()
    threading.Thread(target=alert_worker, name="alert", daemon=True).start()
    threading.Thread(target=digest_worker, name="digest", daemon=True).start()
    threading.Thread(target=snapshot_worker, name="snapshot", daemon=True).start()
    threading.Thread(target=watchdog, name="watchdog", daemon=True).start()

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
