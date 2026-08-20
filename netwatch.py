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
import hmac
import ipaddress
import json
import os
import re
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

VERSION = "2026.08.20.1"  # date + same-day build number, so successive changes on
                          # one day are distinguishable. Shown in the header +
                          # startup log to confirm which build is actually running.
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
NAMES_FILE = os.path.join(HERE, "netwatch_names.json")  # manual MAC/IP -> name map
NOTES_FILE = os.path.join(HERE, "netwatch_notes.json")  # dest IP/host/*.suffix -> note

STALE_AFTER = 10       # seconds since last packet -> flow shown as fading
DROP_AFTER = 120       # seconds since last packet -> flow removed
EVENT_RETAIN = 6 * 3600    # how long a security EVENT stays visible on the counters
                           # and side panel (6h). Applies equally to unsolicited
                           # inbound connections AND threat-list hits: both are
                           # events, not live flows, so they must linger like their
                           # alert does instead of vanishing with the flow in 2
                           # minutes. Override with "event_retain_hours" in
                           # netwatch.conf. Both kinds are persisted to SQLite and
                           # reloaded on start, so a restart doesn't blank them.
INBOUND_RETAIN = EVENT_RETAIN   # back-compat alias (same window, one knob)
INBOUND_MAX = 400      # cap on retained inbound records (drop oldest beyond this)
THREAT_HIT_MAX = 600   # cap on retained threat-hit records (drop oldest beyond this)
GEO_RETRY = 60
CACHE_SAVE_EVERY = 30
CAP_BYTES = 512        # bytes captured per frame (enough for headers + most SNI)
THREAT_REFRESH = 6 * 3600
DB_FLUSH_EVERY = 20
RETAIN_DAYS = 30
MAX_ALERTS = 300
THREAT_CACHE_MAX = 50000   # cap the threat-match memo cache (bounds long-run memory)

# --- process attribution (optional per-PC agent; see netwatch_agent.py) -------
AGENT_TTL = 900        # a reported socket->process mapping is trusted this long
AGENT_MAX = 20000      # cap on mappings held in memory (oldest dropped first)

# --- per-device behavioural profile ("fingerprint") --------------------------
PROFILE_INTERVAL = 300     # seconds between fingerprint passes
PROFILE_MIN_HOURS = 24     # hours of history required before deviations alert
PROFILE_VOL_FACTOR = 3.0   # hourly bytes above baseline_max * this = anomaly
PROFILE_VOL_FLOOR = 10 * 1024 * 1024   # ...but never alert under this absolute
PROFILE_DEST_FACTOR = 4.0  # distinct destinations in an hour vs baseline max
PROFILE_DEST_FLOOR = 25    # ...but never alert under this absolute
PROFILE_MAX_PORTS = 200    # cap the learned per-device port set
DEVIATION_RETAIN = 7 * 86400   # how long a recorded deviation stays queryable

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
# Human-readable name per source, plus what a hit on it actually means. Shown in
# the detail drawer so "flagged" is an explanation rather than a red dot.
THREAT_LABELS = {
    "tor": "Tor exit node",
    "firehol": "FireHOL level 1",
    "spamhaus": "Spamhaus DROP",
    "blocklist": "Public blocklist",
}
THREAT_MEANING = {
    "tor": "The far end is a Tor exit relay. Traffic to it is anonymised — normal "
           "for a Tor user on your LAN, suspicious for an IoT device or a TV.",
    "firehol": "Aggregated list of IPs that should never appear in normal traffic: "
               "bogons, hijacked ranges, and known attack infrastructure.",
    "spamhaus": "Spamhaus DROP — netblocks leased or hijacked wholesale by "
                "criminal operations. No legitimate traffic should go here.",
    "blocklist": "Matched a public reputation blocklist.",
}

LOCK = threading.RLock()   # reentrant: a thread may re-acquire without deadlocking
FLOWS = {}      # (dev,rem) -> {dev,rem,proto,ports:set,first,last,pkts,up,down,host}
GEO = {}        # ip -> {status, ts, ...}
DEV_NAMES = {}  # lan_ip -> hostname
NAMES_OVERRIDE = {}  # normalized MAC or IP -> user-supplied friendly name (top priority)
IPDOMAIN = {}   # public_ip -> domain (learned from sniffed DNS answers)
BYPASS = {}     # dev_ip -> {"types": set(), "last": ts, "detail": str, "servers": {}}
SEEN = {"dev_country": set(), "dev_rem": set(), "device": set()}  # baselines loaded from DB
ALERTS = []     # recent alert dicts (also persisted)
# exact: ip -> comma-joined source keys ("tor", "firehol,spamhaus", ...)
# nets:  list of (ip_network, source_key)
# gen:   bumped every time the lists are replaced, so the threat_match memo cache
#        can be invalidated instead of serving verdicts from an empty list.
THREAT = {"exact": {}, "nets": [], "loaded": 0, "ts": 0, "error": None, "gen": 0}
DEV_MAC = {}    # lan_ip -> MAC string (from sniffed Ethernet headers)
OUI = {}        # 6-hex OUI prefix -> vendor name
OUI_STATE = {"loaded": 0}
INBOUND = {}    # (dev, rem) -> {dev, rem, ports:set, first, last, count}
# Threat-list hits kept as EVENTS for EVENT_RETAIN, independent of the live flow
# table. This is what the header's "flagged" tile counts, so a hit stays on screen
# for hours like its alert does instead of disappearing when the flow ages out.
THREAT_HITS = {}  # (dev, rem, dir) -> {dev, rem, dir, ports:set, hosts:set,
                  #                     lists:str, first, last, count}
NOTES = {}      # dest key (IP / hostname / *.suffix) -> user note text
PROCS = {}      # (dev, rem, port) -> {"proc", "pid", "ts"} from a per-PC agent
AGENTS = {}     # dev IP -> {"host", "os", "last", "n"} agent check-in state
IPV6 = {}       # dev -> {"rem", "last", "count"} global IPv6 traffic seen
PROFILE = {}    # dev -> learned behavioural profile (built by fingerprint_worker)
DEVIATIONS = [] # recent profile deviations, newest last (also persisted)
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


def v6_prefix(ip):
    """The /64 an IPv6 address sits in, used to group leak alerts so one device
    chatting to a dozen addresses at one provider doesn't produce a dozen alerts."""
    try:
        return str(ipaddress.ip_network(ip + "/64", strict=False).network_address)
    except ValueError:
        return ip


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
                return buf[start:start + nlen].decode("ascii", "ignore") or None
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


def _record_threat_hit(dev, rem, direction, lists, ports=(), host=None, ts=None,
                       count=1, first=None):
    """Log a contact with a blocklisted IP as a retained EVENT.

    The header's "flagged" tile counts these, NOT the live flow table, which is why
    a flagged destination now stays on screen for EVENT_RETAIN instead of vanishing
    when its flow ages out after DROP_AFTER (2 minutes). Call under LOCK."""
    now = ts if ts is not None else time.time()
    key = (dev, rem, direction)
    e = THREAT_HITS.get(key)
    if e is None:
        # count starts at 1 for the sighting that created the record; `count` on
        # later calls is an increment (0 = "still happening", don't double-count
        # the same ongoing flow on every 4-second evaluation pass).
        e = {"dev": dev, "rem": rem, "dir": direction, "ports": set(),
             "hosts": set(), "lists": lists or "", "count": 1,
             "first": first if first is not None else now, "last": now}
        THREAT_HITS[key] = e
    else:
        e["count"] += count
    e["ports"].update(p for p in ports if p)
    if host:
        e["hosts"].add(host)
    if lists:
        e["lists"] = lists
    e["last"] = max(e["last"], now)
    if first is not None:
        e["first"] = min(e["first"], first)
    return e


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
    elif pk["dport"] == 853:                       # DNS-over-TLS (or DoQ over UDP)
        try:
            sa = ipaddress.ip_address(pk["src"])
            da = ipaddress.ip_address(pk["dst"])
            if (pk["src"] not in IGNORE and is_private_lan(sa) and da.is_global
                    and pk["dst"] not in PIHOLE_IPS):
                bypass_new.append((pk["src"], "dot", pk["dst"]))
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
        # Security events (inbound + threat hits) share one retention window, so the
        # flagged tile can never drain faster than the inbound tile.
        for k in [k for k, v in INBOUND.items() if now - v["last"] > EVENT_RETAIN]:
            del INBOUND[k]
        if len(INBOUND) > INBOUND_MAX:      # bound memory: keep the most recent
            for k, _ in sorted(INBOUND.items(), key=lambda kv: kv[1]["last"]
                               )[:len(INBOUND) - INBOUND_MAX]:
                del INBOUND[k]
        for k in [k for k, v in THREAT_HITS.items()
                  if now - v["last"] > EVENT_RETAIN]:
            del THREAT_HITS[k]
        for k in [k for k, v in IPV6.items() if now - v["last"] > EVENT_RETAIN]:
            del IPV6[k]
        if len(THREAT_HITS) > THREAT_HIT_MAX:
            for k, _ in sorted(THREAT_HITS.items(), key=lambda kv: kv[1]["last"]
                               )[:len(THREAT_HITS) - THREAT_HIT_MAX]:
                del THREAT_HITS[k]


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
        # 101.6.6.6 lands on two lists so the detail drawer's multi-list case shows.
        THREAT["exact"]["77.88.8.8"] = "spamhaus"
        THREAT["exact"]["101.6.6.6"] = "tor,firehol"
        THREAT["loaded"] = len(THREAT["exact"])
        THREAT["ts"] = START_TS
        THREAT["gen"] += 1
        # MAC vendor demo: the un-named device resolves to a vendor name
        DEV_MAC["192.168.1.66"] = "44:07:0b:11:22:33"
        OUI["44070B"] = "Amazon Technologies"; OUI_STATE["loaded"] = 1
        # An unsolicited inbound connection attempt (e.g. hitting a forwarded port),
        # from an IP that is itself on a blocklist -> inbound AND flagged.
        THREAT["exact"]["185.220.101.5"] = "tor"
        THREAT["loaded"] = len(THREAT["exact"])
        _record_inbound("192.168.1.20", "185.220.101.5", 22)
        _record_inbound("192.168.1.20", "185.220.101.5", 22)
        # DNS-bypass demo: one device reaches SEVERAL resolvers. This shows both
        # the per-device alert cap (many attempts -> only 2 alerts) and the
        # deduplicated DNS-server list in the digest (every server still logged).
        for srv in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"):
            _mark_bypass("192.168.1.31", "plaintext-dns", srv)
        _mark_bypass("192.168.1.44", "dot", "94.140.14.14")     # DoT to an IP
        _mark_bypass("192.168.1.57", "doh", "dns.google")       # DoH by hostname
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

def _norm_mac(m):
    """Normalize any common MAC spelling to lowercase colon form aa:bb:cc:dd:ee:ff."""
    if not m:
        return ""
    h = "".join(c for c in m.lower() if c in "0123456789abcdef")
    if len(h) != 12:
        return m.strip().lower()          # not a MAC; return as-is (e.g. an IP)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def load_names_override():
    """Load the optional netwatch_names.json (MAC or IP -> friendly name). Keys
    that look like MACs are normalized so any spelling matches. Missing file is
    fine; a malformed file is logged and ignored."""
    try:
        with open(NAMES_FILE) as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print("names: could not read %s (%s) - ignoring" % (NAMES_FILE, e),
              file=sys.stderr)
        return {}
    out = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k.startswith("_") or not isinstance(v, str) or not v.strip():
                continue                  # skip comment keys / blank values
            out[_norm_mac(k)] = v.strip()
    return out


def _override_name(ip, macs):
    """Friendly name for a device from the manual override map: match its MAC
    first (survives IP changes), then its IP. '' if none."""
    mac = macs.get(ip)
    if mac:
        n = NAMES_OVERRIDE.get(_norm_mac(mac))
        if n:
            return n
    return NAMES_OVERRIDE.get(ip, "")


def name_worker():
    global NAMES_OVERRIDE
    ov_mtime = None
    while True:
        # Hot-reload the manual names file whenever it changes (no restart needed
        # to ADD a name; removing one still needs a restart).
        try:
            m = os.path.getmtime(NAMES_FILE)
        except OSError:
            m = None
        if m != ov_mtime:
            NAMES_OVERRIDE = load_names_override()
            ov_mtime = m
        with LOCK:
            devs = {f["dev"] for f in FLOWS.values()}
            devs |= {v["dev"] for v in INBOUND.values()}
            known = dict(DEV_NAMES)
            macs = dict(DEV_MAC)
        for ip in devs:
            ov = _override_name(ip, macs)
            if ov:                        # manual name wins over everything
                if known.get(ip) != ov:
                    with LOCK:
                        DEV_NAMES[ip] = ov
                continue
            if ip in known:               # already resolved once — don't re-hammer DNS
                continue
            try:
                name = socket.gethostbyaddr(ip)[0].split(".")[0]
            except Exception:
                name = None
            with LOCK:
                if not DEV_NAMES.get(ip):
                    DEV_NAMES[ip] = name or ""
        time.sleep(5)


# ----------------------------------------------------------------------------
# Destination notes — annotate a remote IP / hostname / domain suffix
# ----------------------------------------------------------------------------
# Same shape as the manual device-name map, but for the OTHER end of the flow:
# "this IP is my Syncthing relay", "this host is the TV's telemetry". Notes ride
# along in the snapshot so a known-good destination stops looking suspicious
# every time you glance at the list.

def _note_key(k):
    """Normalize a note key: IPs and hostnames lowercase, '*.x.com' kept as a
    suffix rule. Returns '' for anything that isn't a plausible key."""
    k = (k or "").strip().lower().rstrip(".")
    if not k or len(k) > 253:
        return ""
    if k.startswith("*."):
        body = k[2:]
        return k if body and re.match(r"^[a-z0-9.\-]+$", body) else ""
    try:
        ipaddress.ip_address(k)
        return k
    except ValueError:
        pass
    return k if re.match(r"^[a-z0-9.\-]+$", k) else ""


def load_notes():
    """Load netwatch_notes.json ({key: note}). Missing file is fine; a malformed
    one is reported and ignored rather than taking the dashboard down."""
    try:
        with open(NOTES_FILE, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print("notes: could not read %s (%s) - ignoring" % (NOTES_FILE, e),
              file=sys.stderr)
        return {}
    out = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if k.startswith("_") or not isinstance(v, str) or not v.strip():
                continue                       # skip comment keys / blank values
            nk = _note_key(k)
            if nk:
                out[nk] = v.strip()[:200]
    return out


def note_for(ip, host="", notes=None):
    """Note for a destination: exact IP wins, then exact hostname, then the
    longest matching '*.suffix' rule. '' when nothing matches."""
    notes = NOTES if notes is None else notes
    if not notes:
        return ""
    if ip and ip in notes:
        return notes[ip]
    h = (host or "").strip().lower().rstrip(".")
    if h:
        if h in notes:
            return notes[h]
        best = ""
        for k in notes:
            if (k.startswith("*.") and (h == k[2:] or h.endswith(k[1:]))
                    and len(k) > len(best)):
                best = k
        if best:
            return notes[best]
    return ""


def save_note(key, text):
    """Write one note through to netwatch_notes.json (empty text deletes it).
    Rewrites the whole small file atomically; the hot-reloader picks it up."""
    nk = _note_key(key)
    if not nk:
        raise ValueError("bad note key")
    try:
        with open(NOTES_FILE, encoding="utf-8") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raw = {}
    except FileNotFoundError:
        raw = {}
    except Exception:
        raw = {}
    text = (text or "").strip()[:200]
    existing = {k: v for k, v in raw.items() if _note_key(k) != nk or k.startswith("_")}
    if text:
        existing[nk] = text
    tmp = NOTES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2, sort_keys=True)
    os.replace(tmp, NOTES_FILE)
    with LOCK:
        NOTES.clear()
        NOTES.update(load_notes())
    return text


def notes_worker():
    """Hot-reload the notes file whenever it changes on disk, so editing it by
    hand works exactly like editing netwatch_names.json."""
    global NOTES
    mtime = None
    while True:
        try:
            m = os.path.getmtime(NOTES_FILE)
        except OSError:
            m = None
        if m != mtime:
            loaded = load_notes()
            with LOCK:
                NOTES.clear()
                NOTES.update(loaded)
            mtime = m
        _beat("notes")
        time.sleep(5)


# ----------------------------------------------------------------------------
# Process attribution (optional per-PC agent)
# ----------------------------------------------------------------------------
# A mirrored port can never see WHICH program opened a socket — that lives only
# on the machine itself. netwatch_agent.py runs on a PC you care about and posts
# its socket->process table here; we join on (device, remote, port) so those
# flows gain a process name while every other device keeps working as before.

def agent_ingest(dev, payload):
    """Merge one agent check-in. `dev` is the peer address of the POST (trusted
    over anything the body claims). Returns the number of mappings accepted."""
    now = time.time()
    conns = payload.get("conns") or []
    n = 0
    with LOCK:
        AGENTS[dev] = {"host": str(payload.get("host", ""))[:64],
                       "os": str(payload.get("os", ""))[:32],
                       "last": now, "n": len(conns)}
        for c in conns:
            try:
                rem = str(c.get("rem", ""))
                port = int(c.get("port", 0))
                proc = str(c.get("proc", ""))[:64]
            except (TypeError, ValueError):
                continue
            if not rem or not proc:
                continue
            try:
                if not ipaddress.ip_address(rem).is_global:
                    continue          # only public destinations are ever mapped
            except ValueError:
                continue
            pid = c.get("pid")
            PROCS[(dev, rem, port)] = {"proc": proc, "ts": now,
                                       "pid": pid if isinstance(pid, int) else None}
            n += 1
        if len(PROCS) > AGENT_MAX:
            for k, _ in sorted(PROCS.items(),
                               key=lambda kv: kv[1]["ts"])[:len(PROCS) - AGENT_MAX]:
                del PROCS[k]
    return n


def proc_for(dev, rem, ports=()):
    """Process name behind a flow, or '' when no agent covers that device.
    Tries each port the flow used, then any port for the (device, remote) pair."""
    now = time.time()
    for p in ports:
        e = PROCS.get((dev, rem, p))
        if e and now - e["ts"] <= AGENT_TTL:
            return e["proc"]
    for (d, r, _p), e in PROCS.items():
        if d == dev and r == rem and now - e["ts"] <= AGENT_TTL:
            return e["proc"]
    return ""


def _prune_procs(now):
    with LOCK:
        for k in [k for k, v in PROCS.items() if now - v["ts"] > AGENT_TTL]:
            del PROCS[k]
        for d in [d for d, v in AGENTS.items() if now - v["last"] > AGENT_TTL]:
            del AGENTS[d]


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
    global CONF, PIHOLE_IPS, IGNORE, EVENT_RETAIN, INBOUND_RETAIN
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
    try:
        hrs = float(cfg.get("event_retain_hours", EVENT_RETAIN / 3600.0))
        # 5 minutes to 30 days; one window for BOTH inbound and flagged events
        EVENT_RETAIN = max(300.0, min(30 * 86400.0, hrs * 3600.0))
        INBOUND_RETAIN = EVENT_RETAIN
    except (TypeError, ValueError):
        print("  config: event_retain_hours must be a number; using default")


# ----------------------------------------------------------------------------
# Threat intelligence (public blocklists -> flag remote IPs)
# ----------------------------------------------------------------------------

def _parse_netset(text, source="blocklist"):
    """Parse a plain-text IP/CIDR blocklist. Returns (exact, nets) where exact is
    {ip: source} and nets is [(network, source)] — the source tag is what lets the
    UI say "Tor exit node" instead of a bare red dot."""
    exact, nets = {}, []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            if "/" in token:
                nets.append((ipaddress.ip_network(token, strict=False), source))
            else:
                ipaddress.ip_address(token)
                exact[token] = source
        except ValueError:
            continue
    return exact, nets


def _http_text(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": "netwatch/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore")


def _threat_install(exact, nets, ts):
    """Swap in a new blocklist set and bump the generation counter so every
    memoised verdict from the previous generation is discarded."""
    with LOCK:
        THREAT["exact"] = exact
        THREAT["nets"] = nets
        THREAT["loaded"] = len(exact) + len(nets)
        THREAT["ts"] = ts
        THREAT["gen"] += 1


def threat_worker():
    # Try disk cache first for an instant start.
    try:
        with open(THREAT_CACHE, "r", encoding="utf-8") as f:
            c = json.load(f)
        cached_exact = c.get("exact", {})
        if isinstance(cached_exact, list):     # pre-attribution cache format
            cached_exact = {ip: "blocklist" for ip in cached_exact}
        cached_nets = []
        for item in c.get("nets", []):
            # new format: ["1.2.3.0/24", "spamhaus"]; old format: "1.2.3.0/24"
            net, src = item if isinstance(item, (list, tuple)) else (item, "blocklist")
            cached_nets.append((ipaddress.ip_network(net), src))
        _threat_install(cached_exact, cached_nets, c.get("ts", 0))
    except Exception:
        pass
    while True:
        exact, nets, srcs_ok = {}, [], 0
        for name, url in THREAT_SOURCES.items():
            try:
                e, nn = _parse_netset(_http_text(url), name)
                for ip, src in e.items():
                    prev = exact.get(ip)
                    # an IP on several lists keeps all of them, comma-joined
                    exact[ip] = src if not prev else prev + "," + src
                nets += nn
                srcs_ok += 1
            except Exception:
                pass
        if srcs_ok:
            _threat_install(exact, nets, time.time())
            with LOCK:
                THREAT["error"] = None
            try:
                with open(THREAT_CACHE, "w", encoding="utf-8") as f:
                    json.dump({"exact": exact,
                               "nets": [[str(n), s] for n, s in nets],
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


_threat_verdict = {}     # ip -> comma-joined source keys, or "" (memoised)
_threat_verdict_gen = -1  # generation the memo cache above was built against


def threat_match(ip):
    """Comma-joined blocklist source keys for `ip` (e.g. "tor" or
    "firehol,spamhaus"), or None if it isn't listed. Truthy on a hit, so callers
    that only test for listedness keep working."""
    global _threat_verdict_gen
    with LOCK:
        gen = THREAT["gen"]
        exact = THREAT["exact"]
        nets = THREAT["nets"]
        loaded = THREAT["loaded"]
    # The lists load asynchronously at startup. Without this guard the first few
    # seconds of traffic get memoised as "clean" against an EMPTY blocklist and are
    # never re-checked — a silent false negative on every single restart. Verdicts
    # are therefore tied to a generation, and nothing is cached before a list exists.
    if gen != _threat_verdict_gen:
        _threat_verdict.clear()
        _threat_verdict_gen = gen
    if not loaded:
        return None
    v = _threat_verdict.get(ip)
    if v is not None:
        return v or None
    hits = []
    src = exact.get(ip)
    if src:
        hits.append(src)
    try:
        a = ipaddress.ip_address(ip)
        for net, nsrc in nets:
            if a in net and nsrc not in hits:
                hits.append(nsrc)
    except ValueError:
        pass
    hit = ",".join(sorted(set(",".join(hits).split(","))) if hits else [])
    # Bound the cache: on an always-on service the set of distinct remote IPs
    # grows forever, so clear (and re-memoize on demand) once it gets large.
    if len(_threat_verdict) >= THREAT_CACHE_MAX:
        _threat_verdict.clear()
    _threat_verdict[ip] = hit
    return hit or None


def threat_sources(ip):
    """[{key,label,meaning}] for each blocklist `ip` appears on (empty if clean)."""
    hit = threat_match(ip) or ""
    out = []
    for key in [k for k in hit.split(",") if k]:
        out.append({"key": key,
                    "label": THREAT_LABELS.get(key, key),
                    "meaning": THREAT_MEANING.get(key, "")})
    return out


# ----------------------------------------------------------------------------
# History (SQLite: sessions + seen baselines + alerts)
# ----------------------------------------------------------------------------

_schema_ready = False


def db_init():
    """Create the schema once. Called at startup; also guarded so the first
    db_connect() is safe even if something connects before startup runs."""
    global _schema_ready
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
    # Security events kept across restarts so the flagged / inbound tiles survive a
    # service restart instead of resetting to zero.
    con.execute("""CREATE TABLE IF NOT EXISTS threat_hits(
        dev TEXT, rem TEXT, dir TEXT, ports TEXT, hosts TEXT, lists TEXT,
        first REAL, last REAL, count INTEGER, PRIMARY KEY(dev, rem, dir))""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_thit_last ON threat_hits(last)")
    con.execute("""CREATE TABLE IF NOT EXISTS inbound_hits(
        dev TEXT, rem TEXT, ports TEXT, first REAL, last REAL, count INTEGER,
        PRIMARY KEY(dev, rem))""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_inb_last ON inbound_hits(last)")
    # Hourly per-device rollup that the behavioural profile is computed from.
    # One row per (device, hour) — tiny, and it makes the fingerprint pass a few
    # indexed reads instead of a scan over every session ever recorded.
    con.execute("""CREATE TABLE IF NOT EXISTS dev_hourly(
        dev TEXT, hour INTEGER, bytes INTEGER, dests INTEGER, flows INTEGER,
        PRIMARY KEY(dev, hour))""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_hourly_hour ON dev_hourly(hour)")
    con.execute("""CREATE TABLE IF NOT EXISTS dev_profile(
        dev TEXT PRIMARY KEY, first REAL, last REAL, hours INTEGER, hod TEXT,
        ports TEXT, max_bytes INTEGER, max_dests INTEGER, avg_bytes REAL,
        updated REAL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS deviations(
        ts REAL, dev TEXT, kind TEXT, detail TEXT, value REAL, baseline REAL)""")
    con.execute("CREATE INDEX IF NOT EXISTS ix_dev_ts ON deviations(ts)")
    # Upgrade path: older databases have a sessions table without `ports`.
    _add_column(con, "sessions", "ports", "TEXT")
    con.commit()
    con.close()
    _schema_ready = True


def _add_column(con, table, col, decl):
    """Idempotent ALTER TABLE ... ADD COLUMN, so upgrading in place never needs
    the user to delete netwatch.db."""
    try:
        have = {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}
    except Exception:
        return False
    if col in have:
        return False
    try:
        con.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))
        return True
    except Exception:
        return False


def db_connect():
    """Lightweight per-request connection. Schema DDL runs once (db_init), not on
    every call, so read endpoints (/digest, /dns, /history) stay cheap."""
    if not _schema_ready:
        db_init()
    con = sqlite3.connect(DB_FILE, timeout=10)
    con.execute("PRAGMA busy_timeout=10000")
    return con


def db_load_baselines(con):
    with LOCK:
        for kind, a, b in con.execute("SELECT kind,a,b FROM seen"):
            if kind == "dev_country":
                SEEN["dev_country"].add((a, b))
            elif kind == "dev_rem":
                SEEN["dev_rem"].add((a, b))
            elif kind == "device":
                SEEN["device"].add(a)
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
        # Reload still-current security events so the flagged / inbound counters
        # pick up where they left off rather than showing 0 after a restart.
        cutoff = time.time() - EVENT_RETAIN
        _ports = lambda s: {int(p) for p in (s or "").split(",") if p.strip().isdigit()}
        n_thit = n_inb = 0
        try:
            for dev, rem, dr, ports, hosts, lists, first, last, cnt in con.execute(
                    "SELECT dev,rem,dir,ports,hosts,lists,first,last,count "
                    "FROM threat_hits WHERE last >= ?", (cutoff,)):
                THREAT_HITS[(dev, rem, dr)] = {
                    "dev": dev, "rem": rem, "dir": dr, "ports": _ports(ports),
                    "hosts": {h for h in (hosts or "").split(",") if h},
                    "lists": lists or "", "first": first, "last": last,
                    "count": cnt or 1}
                n_thit += 1
            for dev, rem, ports, first, last, cnt in con.execute(
                    "SELECT dev,rem,ports,first,last,count FROM inbound_hits "
                    "WHERE last >= ?", (cutoff,)):
                INBOUND[(dev, rem)] = {
                    "dev": dev, "rem": rem, "ports": _ports(ports),
                    "first": first, "last": last, "count": cnt or 1}
                n_inb += 1
        except Exception:
            pass
    print("  history: %d known (device,country) pairs, %d alerts, "
          "%d bypass pairs seen, %d known device MACs"
          % (len(SEEN["dev_country"]), len(ALERTS), len(_bypass_alert_count),
             len(SEEN["device"])))
    if n_thit or n_inb:
        print("  events restored: %d threat hit(s), %d inbound source(s) "
              "(within the last %.1fh)" % (n_thit, n_inb, EVENT_RETAIN / 3600.0))


def _backfill_dns_targets(con):
    """Seed the DNS-server list from historical bypass alerts so upgrading from a
    version without the dns_targets table doesn't leave the list empty. The old
    alerts kept the resolver in the message text; newer ones store it in `rem`.
    Idempotent (server is a PRIMARY KEY)."""
    try:
        rows = con.execute("SELECT ts, kind, rem, msg FROM alerts "
                           "WHERE kind LIKE 'bypass%'").fetchall()
    except Exception:
        return
    n = 0
    for ts, kind, rem, msg in rows:
        server = (rem or "").strip()
        if not server:                      # old format: pull "(1.2.3.4)" from msg
            m = re.search(r"\(([^)]+)\)", msg or "")
            server = m.group(1).strip() if m else ""
        if not server:
            continue
        k = "doh" if "doh" in (kind or "") else "plaintext-dns"
        try:
            con.execute(
                "INSERT INTO dns_targets(server,kind,first,last,hits) "
                "VALUES(?,?,?,?,1) ON CONFLICT(server) DO UPDATE SET "
                "last=MAX(last, excluded.last)", (server, k, ts, ts))
            n += 1
        except Exception:
            pass
    if n:
        con.commit()
        print("  backfilled DNS-server list from %d historical bypass alerts" % n)


_flow_bytes = {}     # (dev,rem,first) -> bytes counted so far, for hourly deltas
_hour_dests = {"hour": 0, "map": {}}   # distinct destinations per device this hour


def _rollup_hourly(rows, now):
    """Turn this pass's absolute session totals into per-device, per-hour byte
    DELTAS. Attributing a whole session to one hour would make a long download
    look like a spike in whichever hour it happened to end in; taking the
    difference since the previous pass puts the bytes in the hour they moved."""
    hour = int(now // 3600)
    if _hour_dests["hour"] != hour:
        _hour_dests["hour"], _hour_dests["map"] = hour, {}
    agg = {}
    live = set()
    for r in rows:
        dev, rem, first = r[0], r[2], r[6]
        key = (dev, rem, first)
        live.add(key)
        total = (r[8] or 0) + (r[9] or 0)
        prev = _flow_bytes.get(key, 0)
        delta = total - prev if total >= prev else total
        _flow_bytes[key] = total
        a = agg.setdefault(dev, {"bytes": 0, "flows": 0})
        a["bytes"] += delta
        a["flows"] += 1
        _hour_dests["map"].setdefault(dev, set()).add(rem)
    for key in [k for k in _flow_bytes if k not in live]:
        del _flow_bytes[key]
    return hour, [(dev, hour, a["bytes"],
                   len(_hour_dests["map"].get(dev, ())), a["flows"])
                  for dev, a in agg.items()]


def db_worker():
    try:
        con = db_connect()
        db_load_baselines(con)
        _backfill_dns_targets(con)
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
                    f["up"], f["down"],
                    ",".join(str(p) for p in sorted(f["ports"])[:12]))
                   for f in FLOWS.values()]
            pending = list(_alert_persist_q)
            _alert_persist_q.clear()
            dns_pending = list(_dns_target_q)
            _dns_target_q.clear()
            bypass_pending = list(_bypass_persist_q)
            _bypass_persist_q.clear()
            # Snapshot the retained security events for upsert (small: hundreds max)
            thit_rows = [(v["dev"], v["rem"], v["dir"],
                          ",".join(str(p) for p in sorted(v["ports"])),
                          ",".join(sorted(v["hosts"]))[:400], v["lists"],
                          v["first"], v["last"], v["count"])
                         for v in THREAT_HITS.values()]
            inb_rows = [(v["dev"], v["rem"],
                         ",".join(str(p) for p in sorted(v["ports"])[:20]),
                         v["first"], v["last"], v["count"])
                        for v in INBOUND.values()]
        rows = []
        for dev, name, rem, host, g, first, last, up, down, ports in raw:
            gg = g if g.get("status") == "ok" else {}
            rows.append((dev, name, rem, host, gg.get("country", ""),
                         gg.get("countryCode", ""), first, last, up, down,
                         threat_match(rem) or "", ports))
        try:
            # Keep one row per (dev,rem,first) session, updated in place.
            for r in rows:
                con.execute(
                    "DELETE FROM sessions WHERE dev=? AND rem=? AND first=?",
                    (r[0], r[2], r[6]))
                con.execute(
                    "INSERT INTO sessions(dev,dev_name,rem,host,country,cc,"
                    "first,last,up,down,threat,ports) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", r)
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
            for r in thit_rows:
                con.execute(
                    "INSERT INTO threat_hits(dev,rem,dir,ports,hosts,lists,"
                    "first,last,count) VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(dev,rem,dir) DO UPDATE SET ports=excluded.ports,"
                    "hosts=excluded.hosts, lists=excluded.lists,"
                    "first=MIN(first, excluded.first), last=excluded.last,"
                    "count=excluded.count", r)
            for r in _rollup_hourly(rows, now)[1]:
                con.execute(
                    "INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(dev,hour) DO UPDATE SET "
                    "bytes=bytes+excluded.bytes, dests=MAX(dests,excluded.dests),"
                    "flows=MAX(flows,excluded.flows)", r)
            for r in inb_rows:
                con.execute(
                    "INSERT INTO inbound_hits(dev,rem,ports,first,last,count) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(dev,rem) DO UPDATE SET "
                    "ports=excluded.ports, first=MIN(first, excluded.first),"
                    "last=excluded.last, count=excluded.count", r)
            if now - last_prune > 3600:
                cutoff = now - RETAIN_DAYS * 86400
                con.execute("DELETE FROM sessions WHERE last < ?", (cutoff,))
                con.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
                # Events are kept a bit past their on-screen window so a quick
                # restart still restores them; nothing older is useful.
                ev_cutoff = now - max(EVENT_RETAIN * 2, 86400)
                con.execute("DELETE FROM threat_hits WHERE last < ?", (ev_cutoff,))
                con.execute("DELETE FROM inbound_hits WHERE last < ?", (ev_cutoff,))
                con.execute("DELETE FROM deviations WHERE ts < ?",
                            (now - DEVIATION_RETAIN,))
                # The hourly rollup follows the same 30-day window as sessions;
                # the profile derived from it (dev_profile) is cumulative.
                con.execute("DELETE FROM dev_hourly WHERE hour < ?",
                            (int(cutoff // 3600),))
                # NOTE: dns_targets is deliberately NOT pruned — it's the cumulative
                # firewall/ACL blocklist and must be a permanent record, not a
                # rolling 30-day window (it's tiny: one row per distinct resolver).
                last_prune = now
            con.commit()
        except Exception as e:
            print("  history write error: %s" % e)


def db_history(since, dev=None, limit=500):
    try:
        con = db_connect()
        q = ("SELECT dev,dev_name,rem,host,country,cc,first,last,up,down,threat,"
             "COALESCE(ports,'') FROM sessions WHERE last >= ?")
        args = [since]
        if dev:
            q += " AND dev = ?"
            args.append(dev)
        q += " ORDER BY last DESC LIMIT ?"
        args.append(limit)
        rows = con.execute(q, args).fetchall()
        con.close()
        cols = ["dev", "dev_name", "rem", "host", "country", "cc", "first",
                "last", "up", "down", "threat", "ports"]
        return [dict(zip(cols, r)) for r in rows]
    except Exception:
        return []


# ----------------------------------------------------------------------------
# Device behavioural profile ("fingerprint") + deviation detection
# ----------------------------------------------------------------------------
# A mirrored port sees devices, not processes, so instead of fingerprinting an
# application we fingerprint a DEVICE: the hours it is normally awake, the ports
# it normally uses, how much it normally moves in an hour and how many distinct
# destinations it normally touches. IoT gear is boringly consistent, which makes
# a deviation genuinely interesting — a doorbell that suddenly uploads 200 MB at
# 3am to fifty new hosts is exactly the shape of a compromise.

def _hod(hour):
    """Local hour-of-day (0-23) for an absolute epoch-hour number."""
    try:
        return time.localtime(hour * 3600).tm_hour
    except (OSError, ValueError, OverflowError):
        return hour % 24


def _hod_add(bitmap, h):
    b = list((bitmap or "0" * 24).ljust(24, "0")[:24])
    if 0 <= h < 24:
        b[h] = "1"
    return "".join(b)


def _ports_union(stored, new_ports):
    have = {p for p in (stored or "").split(",") if p}
    have |= {str(p) for p in new_ports if str(p).isdigit()}
    return ",".join(sorted(have, key=lambda x: int(x))[:PROFILE_MAX_PORTS])


def profile_pass(con, now=None):
    """One fingerprint pass: refresh every device's learned profile from the
    hourly rollup, then compare the hour in progress against it. Returns the
    list of deviation dicts found this pass (already recorded, not yet alerted).
    Kept a pure function of (connection, clock) so tests can drive it."""
    now = time.time() if now is None else now
    cur_hour = int(now // 3600)
    profiles = {}
    for dev, first, last, hours, hod, ports, mx, mxd, avg, upd in con.execute(
            "SELECT dev,first,last,hours,hod,ports,max_bytes,max_dests,"
            "avg_bytes,updated FROM dev_profile"):
        profiles[dev] = {"dev": dev, "first": first, "last": last,
                         "hours": hours or 0, "hod": hod or "0" * 24,
                         "ports": ports or "", "max_bytes": mx or 0,
                         "max_dests": mxd or 0, "avg_bytes": avg or 0.0,
                         "updated": upd or 0}

    # Baseline from COMPLETED hours only — the hour in progress is what we are
    # testing, so folding it into its own baseline would hide every anomaly.
    stats = {}
    for dev, n, mx, mxd, avg in con.execute(
            "SELECT dev, COUNT(*), MAX(bytes), MAX(dests), AVG(bytes) "
            "FROM dev_hourly WHERE hour < ? GROUP BY dev", (cur_hour,)):
        stats[dev] = (n or 0, mx or 0, mxd or 0, avg or 0.0)

    hod_seen = {}
    for dev, hour in con.execute(
            "SELECT dev, hour FROM dev_hourly WHERE hour < ? AND bytes > 0",
            (cur_hour,)):
        hod_seen.setdefault(dev, set()).add(_hod(hour))

    # Ports used since the last pass, so the learned set grows without ever
    # re-reading the whole sessions table.
    port_new = {}
    for dev, ports in con.execute(
            "SELECT dev, COALESCE(ports,'') FROM sessions WHERE last >= ?",
            (now - 2 * PROFILE_INTERVAL,)):
        s = port_new.setdefault(dev, set())
        for p in (ports or "").split(","):
            if p.isdigit():
                s.add(p)

    current = {}
    for dev, b, d in con.execute(
            "SELECT dev, bytes, dests FROM dev_hourly WHERE hour = ?", (cur_hour,)):
        current[dev] = (b or 0, d or 0)

    found = []
    for dev in set(stats) | set(current) | set(profiles):
        p = profiles.get(dev) or {"dev": dev, "first": now, "hours": 0,
                                  "hod": "0" * 24, "ports": "", "max_bytes": 0,
                                  "max_dests": 0, "avg_bytes": 0.0}
        n, mx, mxd, avg = stats.get(dev, (0, 0, 0, 0.0))
        hod = p["hod"]
        for h in hod_seen.get(dev, ()):
            hod = _hod_add(hod, h)
        cur_bytes, cur_dests = current.get(dev, (0, 0))
        mature = n >= PROFILE_MIN_HOURS

        if mature and cur_bytes > max(mx * PROFILE_VOL_FACTOR, PROFILE_VOL_FLOOR):
            found.append({"dev": dev, "kind": "volume", "value": cur_bytes,
                          "baseline": mx, "hour": cur_hour,
                          "detail": "moved %s this hour; its busiest hour on "
                                    "record is %s" % (_fmt_bytes(cur_bytes),
                                                      _fmt_bytes(mx))})
        if mature and cur_dests > max(mxd * PROFILE_DEST_FACTOR, PROFILE_DEST_FLOOR):
            found.append({"dev": dev, "kind": "dests", "value": cur_dests,
                          "baseline": mxd, "hour": cur_hour,
                          "detail": "reached %d distinct destinations this hour; "
                                    "its widest hour on record is %d"
                                    % (cur_dests, mxd)})
        # Off-hours needs a full week before it means anything — a device simply
        # hasn't had the chance to be seen at 4am until it has lived through one.
        if n >= 7 * 24 and cur_bytes > 0:
            h_now = _hod(cur_hour)
            if hod[h_now] != "1":
                found.append({"dev": dev, "kind": "hours", "value": h_now,
                              "baseline": -1, "hour": cur_hour,
                              "detail": "active at %02d:00 — an hour it has never "
                                        "been active before" % h_now})
        known_ports = {x for x in (p["ports"] or "").split(",") if x}
        fresh = sorted(port_new.get(dev, set()) - known_ports, key=int)
        if mature and fresh:
            found.append({"dev": dev, "kind": "port", "value": int(fresh[0]),
                          "baseline": len(known_ports), "hour": cur_hour,
                          "detail": "used port %s for the first time"
                                    % ", ".join(fresh[:5])})

        # Persist the refreshed profile. Ports are unioned in AFTER the
        # comparison above, so a brand-new port is reported exactly once.
        hod = _hod_add(hod, _hod(cur_hour)) if cur_bytes > 0 else hod
        merged = {"dev": dev, "first": p.get("first") or now, "last": now,
                  "hours": n, "hod": hod,
                  "ports": _ports_union(p["ports"], port_new.get(dev, set())),
                  "max_bytes": max(mx, p["max_bytes"]),
                  "max_dests": max(mxd, p["max_dests"]),
                  "avg_bytes": avg, "updated": now}
        con.execute(
            "INSERT INTO dev_profile(dev,first,last,hours,hod,ports,max_bytes,"
            "max_dests,avg_bytes,updated) VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(dev) DO UPDATE SET last=excluded.last,"
            "hours=excluded.hours, hod=excluded.hod, ports=excluded.ports,"
            "max_bytes=excluded.max_bytes, max_dests=excluded.max_dests,"
            "avg_bytes=excluded.avg_bytes, updated=excluded.updated",
            (dev, merged["first"], merged["last"], merged["hours"], merged["hod"],
             merged["ports"], merged["max_bytes"], merged["max_dests"],
             merged["avg_bytes"], merged["updated"]))
        profiles[dev] = merged

    for d in found:
        con.execute("INSERT INTO deviations(ts,dev,kind,detail,value,baseline) "
                    "VALUES(?,?,?,?,?,?)",
                    (now, d["dev"], d["kind"], d["detail"], d["value"],
                     d["baseline"]))
    con.commit()
    with LOCK:
        PROFILE.clear()
        PROFILE.update(profiles)
        for d in found:
            DEVIATIONS.append(dict(d, ts=now))
        del DEVIATIONS[:-200]
    return found


def fingerprint_worker():
    """Refresh device profiles and alert on deviations. Deliberately slow (every
    PROFILE_INTERVAL) — this is a trend detector, not a live path."""
    time.sleep(30)                     # let the first sessions land
    while True:
        try:
            _beat("fingerprint")
            con = db_connect()
            try:
                found = profile_pass(con)
            finally:
                con.close()
            names = dict(DEV_NAMES)
            for d in found:
                _fire("profile_" + d["kind"], d["dev"], str(d["hour"]), "", None,
                      names, False, msg=d["detail"])
        except Exception as e:
            print("  fingerprint pass failed (%s)" % e)
        time.sleep(PROFILE_INTERVAL)


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


_notify_q = []            # alerts waiting on the single notification worker
NOTIFY_QUEUE_MAX = 200    # drop the oldest rather than grow without bound


def _emit_alert(level, kind, dev, rem, host, msg):
    now = time.time()
    a = {"ts": now, "level": level, "kind": kind, "dev": dev,
         "dev_name": DEV_NAMES.get(dev, ""), "rem": rem, "host": host, "msg": msg}
    with LOCK:
        ALERTS.append(a)
        del ALERTS[:-MAX_ALERTS]
        _alert_persist_q.append(a)
        # Queue for delivery instead of spawning a thread per alert: a port scan or
        # a freshly-loaded blocklist can emit dozens at once, and one thread (plus
        # possibly one SMTP connection) each is a thread storm on a Pi.
        _notify_q.append(a)
        del _notify_q[:-NOTIFY_QUEUE_MAX]


def notify_worker():
    """Single consumer for the notification queue. Sends are serialized, so a slow
    or unreachable ntfy/webhook/SMTP endpoint delays notifications but can never
    pile up threads or sockets."""
    while True:
        with LOCK:
            batch = _notify_q[:]
            del _notify_q[:]
        for a in batch:
            try:
                notify(a)
            except Exception:
                pass          # one bad channel must never kill the worker
        time.sleep(1.0 if not batch else 0.05)


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
        # Freeze each flow's port set while we hold the lock — the capture thread
        # mutates these sets, and iterating one unlocked can raise "set changed
        # size during iteration".
        cand = [(f["dev"], f["rem"], tuple(f["ports"]),
                 f.get("host") or IPDOMAIN.get(f["rem"], ""), f["first"])
                for f in flows]
    # Record every current contact with a blocklisted IP as a retained event before
    # alerting, so the flagged tile is driven by the event store (EVENT_RETAIN) and
    # not by whether the flow happens to still be alive. threat_match scans
    # thousands of CIDRs, so it runs with the lock released.
    hits = []
    for dev, rem, ports, host, first in cand:
        th = threat_match(rem)
        if th:
            hits.append((dev, rem, "out", th, ports, host, first))
    for dev, rem, port in inbound:
        th = threat_match(rem)
        if th:
            hits.append((dev, rem, "in", th, (port,) if port else (), "", None))
    if hits:
        with LOCK:
            for dev, rem, direction, th, ports, host, first in hits:
                _record_threat_hit(dev, rem, direction, th, ports=ports,
                                   host=host, ts=now, count=0, first=first)
    if True:
        # new device on the network: fires once per never-before-seen MAC. Keyed on
        # MAC (not IP) so a DHCP lease renewal on a known device doesn't re-alert,
        # but a genuinely new NIC joining the LAN does. Devices whose MAC hasn't
        # been learned yet (no outbound frame captured for them so far) are skipped
        # this pass and picked up on a later pass once DEV_MAC has it -- normally
        # within a few seconds, since mac learning happens on their next flush.
        devs_active = set(f["dev"] for f in flows) | set(d for d, _, _ in inbound)
        for dev in devs_active:
            mac = DEV_MAC.get(dev)
            if mac:
                _fire("device", dev, mac, "", None, names, learning,
                      msg="new device joined the network (MAC %s)" % mac)
        # IPv6 leak. This network is deliberately v4-only (the DNS/DoH/DoT ACLs
        # on the gateway are v4 rules), so a device reaching a global v6 address
        # is either misconfigured or routing straight around those rules.
        if CONF.get("alert_ipv6", True):
            v6 = [(d, r) for d, r, _p, _h, _f in cand if ":" in r]
            if v6:
                with LOCK:
                    for d, r in v6:
                        e6 = IPV6.get(d)
                        if e6 is None:
                            IPV6[d] = {"rem": r, "last": now, "count": 1}
                        else:
                            e6["rem"] = r
                            e6["last"] = now
                            e6["count"] += 1
                for d, r in v6:
                    _fire("ipv6", d, v6_prefix(r), "", None, names, learning,
                          msg="IPv6 traffic to %s — IPv6 is supposed to be "
                              "disabled on this network" % r)
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
                           % (_bypass_label(t), server)))


def _fire(kind, dev, key, host, cc, names, learning, msg):
    """key is rem for dev_rem/threat, cc for dev_country, mac for device,
    detail for bypass."""
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
    elif kind == "device":
        with LOCK:
            known = key in SEEN["device"]
            SEEN["device"].add(key)
        _remember("device", key, "")
        if known or learning:
            return
        level, rem_field = "notice", key
    elif kind == "threat":
        level, rem_field = "critical", key
    elif kind == "inbound":
        level, rem_field = "warning", key
    elif kind.startswith("bypass_"):
        if learning:
            return
        level = "warning"
    elif kind == "ipv6":
        # IPv6 is meant to be off on this network, so any global v6 traffic is a
        # misconfiguration (or a device routing around the v4 firewall rules).
        if learning:
            return
        level, rem_field = "warning", key
    elif kind.startswith("profile_"):
        # Behavioural deviation from the device's learned fingerprint.
        if learning:
            return
        level = "warning" if kind == "profile_volume" else "notice"
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
    total = devices = dests = countries = 0
    top_dev, top_dst, threats, dns_rows = [], [], [], []
    by_kind = {}
    by_kind_dev = {}
    try:
        con = db_connect()
        # Aggregate in SQL (uses the ix_sess_last index) instead of pulling every
        # session row into Python — this is what keeps the digest fast over 30 days.
        row = con.execute(
            "SELECT COALESCE(SUM(up+down),0), COUNT(DISTINCT dev), "
            "COUNT(DISTINCT rem), COUNT(DISTINCT NULLIF(cc,'')) "
            "FROM sessions WHERE last>=?", (since,)).fetchone()
        total, devices, dests, countries = row
        top_dev = [{"name": nm or dev, "up": up or 0, "down": down or 0,
                    "total": (up or 0) + (down or 0)}
                   for dev, nm, up, down in con.execute(
                       "SELECT dev, MAX(dev_name), SUM(up), SUM(down) FROM sessions "
                       "WHERE last>=? GROUP BY dev ORDER BY SUM(up+down) DESC "
                       "LIMIT 10", (since,))]
        top_dst = [{"ip": rem, "host": host or rem, "cc": cc or "", "up": up or 0,
                    "down": down or 0, "total": (up or 0) + (down or 0)}
                   for rem, host, cc, up, down in con.execute(
                       "SELECT rem, MAX(host), MAX(cc), SUM(up), SUM(down) "
                       "FROM sessions WHERE last>=? GROUP BY rem "
                       "ORDER BY SUM(up+down) DESC LIMIT 10", (since,))]
        by_kind = {k: c for (k, c) in con.execute(
            "SELECT kind, COUNT(*) FROM alerts WHERE ts>=? GROUP BY kind",
            (since,))}
        # Per-(kind,device) breakdown so the on-screen digest can drill into "which
        # devices triggered this alert kind" when a row is clicked.
        by_kind_dev = {}
        for kind, dev, dev_name, cnt in con.execute(
                "SELECT kind, dev, MAX(dev_name), COUNT(*) FROM alerts "
                "WHERE ts>=? GROUP BY kind, dev", (since,)):
            by_kind_dev.setdefault(kind, []).append(
                {"dev": dev, "dev_name": dev_name or "", "count": cnt})
        for lst in by_kind_dev.values():
            lst.sort(key=lambda x: -x["count"])
        # Keep the raw device IP and remote IP alongside the display strings — the
        # dashboard needs them to open the detail drawer for a clicked threat row.
        threats = [{"dev": nm or dev, "dev_ip": dev, "ip": rem,
                    "rem": host or rem, "host": host or "",
                    "country": country or cc, "cc": cc or "",
                    "up": up or 0, "down": down or 0,
                    "total": (up or 0) + (down or 0), "first": first, "last": last,
                    "lists": [THREAT_LABELS.get(k, k)
                              for k in (th or "").split(",") if k]}
                   for dev, nm, rem, host, country, cc, up, down, first, last, th
                   in con.execute(
                       "SELECT dev, MAX(dev_name), rem, MAX(host), MAX(country), "
                       "MAX(cc), SUM(up), SUM(down), MIN(first), MAX(last), "
                       "MAX(threat) FROM sessions WHERE threat<>'' AND last>=? "
                       "GROUP BY dev, rem ORDER BY MAX(last) DESC LIMIT 50",
                       (since,))]
        con.close()
    except Exception:
        pass
    return {"days": days, "total": total, "devices": devices,
            "dests": dests, "countries": countries,
            "top_devices": top_dev, "top_dests": top_dst,
            "alerts_total": sum(by_kind.values()), "alerts_by_kind": by_kind,
            "alerts_by_kind_dev": by_kind_dev,
            "threats": threats, "dns_targets": dns_blocklist()}


def _bypass_label(kind):
    return {"doh": "encrypted DNS/DoH", "dot": "encrypted DNS/DoT",
            "plaintext-dns": "external DNS"}.get(kind, "external DNS")


def dns_blocklist():
    """The full cumulative list of every DNS resolver devices have tried to reach
    (NOT time-windowed) — a ready-to-paste blocklist. Its own tiny, instant query
    so the DNS view never waits on the traffic aggregation. Each entry is tagged
    block_at='firewall' (it's an IP → block in an ACL/IP group) or 'pihole' (it's
    a hostname, e.g. a DoH endpoint → block as a domain in Pi-hole)."""
    try:
        con = db_connect()
        rows = con.execute("SELECT server, kind, hits FROM dns_targets "
                           "ORDER BY hits DESC, server").fetchall()
        con.close()
    except Exception:
        rows = []
    out = []
    for s, k, h in rows:
        try:
            ipaddress.ip_address(s)
            at = "firewall"
        except ValueError:
            at = "pihole"
        out.append({"server": s, "kind": _bypass_label(k), "hits": h,
                    "block_at": at})
    return out


_rdns_cache = {}       # ip -> PTR name or "" (memoised; bounded)


def _rdns(ip, wait=1.5):
    """Best-effort PTR lookup for the detail drawer, time-boxed without touching
    socket.setdefaulttimeout (which is process-wide and would affect the geo and
    email workers too). A slow or missing PTR just yields ""."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    box = {}

    def go():
        try:
            box["n"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            box["n"] = ""
    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(wait)
    name = box.get("n", "")
    if "n" in box:                  # only cache a completed lookup
        if len(_rdns_cache) > 4000:
            _rdns_cache.clear()
        _rdns_cache[ip] = name
    return name


def detail_data(ip, dev=None):
    """Everything NetWatch knows about one remote IP, for the detail drawer.

    Pulls together the live flow table, the retained threat/inbound event stores,
    30 days of session history, and every alert that mentioned the address, so
    clicking a flagged row answers "what actually is this?" in one place."""
    now = time.time()
    srcs = threat_sources(ip)
    with LOCK:
        live = []
        for f in FLOWS.values():
            if f["rem"] != ip:
                continue
            live.append({"dev": f["dev"],
                         "dev_name": DEV_NAMES.get(f["dev"]) or mac_vendor(f["dev"]),
                         "ports": sorted(f["ports"])[:8], "proto": f["proto"],
                         "up": f["up"], "down": f["down"], "pkts": f["pkts"],
                         "first": f["first"], "last": f["last"],
                         "active": now - f["last"] <= STALE_AFTER,
                         "host": f.get("host") or ""})
        events = [{"dev": v["dev"],
                   "dev_name": DEV_NAMES.get(v["dev"]) or mac_vendor(v["dev"]),
                   "dir": v["dir"], "ports": sorted(v["ports"])[:8],
                   "hosts": sorted(v["hosts"]), "count": v["count"],
                   "first": v["first"], "last": v["last"],
                   "lists": [THREAT_LABELS.get(k, k)
                             for k in (v["lists"] or "").split(",") if k]}
                  for v in THREAT_HITS.values() if v["rem"] == ip]
        inbound = [{"dev": v["dev"],
                    "dev_name": DEV_NAMES.get(v["dev"]) or mac_vendor(v["dev"]),
                    "ports": sorted(v["ports"])[:12], "count": v["count"],
                    "first": v["first"], "last": v["last"]}
                   for v in INBOUND.values() if v["rem"] == ip]
        g = GEO.get(ip) or {}
        geo = g if g.get("status") == "ok" else None
        dns_host = IPDOMAIN.get(ip, "")
        threat_ts = THREAT["ts"]
        threat_loaded = THREAT["loaded"]
    live.sort(key=lambda x: (-x["active"], -(x["up"] + x["down"])))
    events.sort(key=lambda x: -x["last"])
    inbound.sort(key=lambda x: -x["last"])

    hist, alerts, totals, hosts = [], [], {}, set()
    if dns_host:
        hosts.add(dns_host)
    try:
        con = db_connect()
        since = now - RETAIN_DAYS * 86400
        q = ("SELECT dev, MAX(dev_name), MAX(host), MIN(first), MAX(last), "
             "SUM(up), SUM(down), MAX(threat) FROM sessions "
             "WHERE rem=? AND last>=? GROUP BY dev ORDER BY MAX(last) DESC")
        for d, nm, host, first, last, up, down, th in con.execute(q, (ip, since)):
            if host:
                hosts.add(host)
            hist.append({"dev": d, "dev_name": nm or "", "host": host or "",
                         "first": first, "last": last, "up": up or 0,
                         "down": down or 0, "threat": th or ""})
        row = con.execute("SELECT SUM(up), SUM(down), MIN(first), MAX(last), "
                          "COUNT(DISTINCT dev) FROM sessions WHERE rem=?",
                          (ip,)).fetchone()
        totals = {"up": row[0] or 0, "down": row[1] or 0,
                  "first_seen": row[2], "last_seen": row[3],
                  "devices": row[4] or 0}
        for ts, level, kind, d, nm, host, msg in con.execute(
                "SELECT ts,level,kind,dev,dev_name,host,msg FROM alerts "
                "WHERE rem=? ORDER BY ts DESC LIMIT 40", (ip,)):
            alerts.append({"ts": ts, "level": level, "kind": kind, "dev": d,
                           "dev_name": nm or "", "host": host or "", "msg": msg})
        con.close()
    except Exception:
        pass
    for e in live:
        if e["host"]:
            hosts.add(e["host"])
    for e in events:
        hosts.update(e["hosts"])

    host_list = sorted(h for h in hosts if h)
    with LOCK:
        procs = sorted({v["proc"] for (d, r, _p), v in PROCS.items()
                        if r == ip and now - v["ts"] <= AGENT_TTL
                        and (not dev or d == dev)})
        note = note_for(ip, host_list[0] if host_list else "", dict(NOTES))
    return {
        "ip": ip, "focus_dev": dev or "",
        "geo": geo, "reverse_dns": _rdns(ip), "dns_host": dns_host,
        "note": note, "procs": procs,
        "hosts": host_list,
        # Edit the key the note is actually stored under, so saving from the
        # drawer updates the existing note instead of quietly creating a second
        # one under the hostname.
        "note_key": (ip if ip in NOTES or not host_list else host_list[0]),
        "threat": {"listed": bool(srcs), "sources": srcs,
                   "lists_refreshed": threat_ts, "entries": threat_loaded},
        "live": live, "events": events, "inbound": inbound,
        "history": hist, "alerts": alerts, "totals": totals,
        "retain_h": round(EVENT_RETAIN / 3600.0, 1),
        "now": now,
    }


def viz_data(hours=24):
    """Aggregates behind the Visualizations panel — four different questions
    asked of the same window, all answered in SQL so a 7-day view costs about
    what an hour does.

      constellation : who talks to whom (device -> destination, by volume)
      flow          : where the bytes go (device -> country)
      weather       : when the network is busy (per-hour activity + alerts)
      fingerprint   : what "normal" looks like per device, and what broke it
    """
    now = time.time()
    since = now - hours * 3600
    out = {"hours": hours, "generated": now,
           "constellation": {"devices": [], "links": []},
           "flow": {"devices": [], "countries": [], "links": []},
           "weather": {"buckets": [], "peak": 0},
           "fingerprint": {"devices": [], "deviations": []}}
    try:
        con = db_connect()
    except Exception:
        return out
    try:
        names = {}
        for dev, nm in con.execute(
                "SELECT dev, MAX(COALESCE(dev_name,'')) FROM sessions "
                "WHERE last >= ? GROUP BY dev", (since,)):
            names[dev] = nm or ""

        # ---- constellation: top devices, each with its top destinations ------
        devs = []
        for dev, tot, ndest in con.execute(
                "SELECT dev, SUM(up+down), COUNT(DISTINCT rem) FROM sessions "
                "WHERE last >= ? GROUP BY dev ORDER BY 2 DESC LIMIT 10", (since,)):
            devs.append({"ip": dev, "name": names.get(dev) or dev,
                         "bytes": tot or 0, "ndest": ndest or 0})
        out["constellation"]["devices"] = devs
        keep = {d["ip"] for d in devs}
        per_dev = {}
        for dev, node, b, cc, threat, host in con.execute(
                "SELECT dev, COALESCE(NULLIF(host,''), rem) AS node, "
                "SUM(up+down) AS b, MAX(COALESCE(cc,'')), MAX(COALESCE(threat,'')), "
                "MAX(COALESCE(host,'')) FROM sessions WHERE last >= ? "
                "GROUP BY dev, node ORDER BY b DESC", (since,)):
            if dev not in keep:
                continue
            lst = per_dev.setdefault(dev, [])
            if len(lst) >= 8:
                continue
            lst.append({"dev": dev, "node": node, "bytes": b or 0,
                        "cc": cc or "", "threat": threat or "",
                        "host": host or ""})
        for lst in per_dev.values():
            out["constellation"]["links"].extend(lst)

        # ---- flow: device -> country, bytes -------------------------------
        pairs = con.execute(
            "SELECT dev, COALESCE(NULLIF(country,''),'Unknown'), SUM(up+down) "
            "FROM sessions WHERE last >= ? GROUP BY 1,2", (since,)).fetchall()
        dev_tot, cc_tot = {}, {}
        for dev, country, b in pairs:
            dev_tot[dev] = dev_tot.get(dev, 0) + (b or 0)
            cc_tot[country] = cc_tot.get(country, 0) + (b or 0)
        top_dev = [d for d, _ in sorted(dev_tot.items(), key=lambda kv: -kv[1])[:8]]
        top_cc = [c for c, _ in sorted(cc_tot.items(), key=lambda kv: -kv[1])[:8]]
        links = {}
        for dev, country, b in pairs:
            d = dev if dev in top_dev else "other"
            c = country if country in top_cc else "Other"
            links[(d, c)] = links.get((d, c), 0) + (b or 0)
        out["flow"]["devices"] = [
            {"ip": d, "name": (names.get(d) or d) if d != "other" else "other",
             "bytes": dev_tot.get(d, sum(v for k, v in links.items() if k[0] == "other"))}
            for d in (top_dev + (["other"] if len(dev_tot) > len(top_dev) else []))]
        out["flow"]["countries"] = [
            {"name": c, "bytes": cc_tot.get(c, sum(v for k, v in links.items()
                                                   if k[1] == "Other"))}
            for c in (top_cc + (["Other"] if len(cc_tot) > len(top_cc) else []))]
        out["flow"]["links"] = [{"dev": k[0], "country": k[1], "bytes": v}
                                for k, v in sorted(links.items(), key=lambda kv: -kv[1])]

        # ---- weather: per-hour activity ------------------------------------
        h0, h1 = int(since // 3600), int(now // 3600)
        by_hour = {}
        for h, b, nd in con.execute(
                "SELECT hour, SUM(bytes), SUM(dests) FROM dev_hourly "
                "WHERE hour >= ? GROUP BY hour", (h0,)):
            by_hour[h] = [b or 0, nd or 0, 0, 0]
        if not by_hour:
            # dev_hourly only fills going forward; fall back to session rows so
            # the view isn't blank on a freshly upgraded install.
            for h, b, nd in con.execute(
                    "SELECT CAST(last/3600 AS INTEGER) h, SUM(up+down), "
                    "COUNT(DISTINCT rem) FROM sessions WHERE last >= ? "
                    "GROUP BY h", (since,)):
                by_hour[h] = [b or 0, nd or 0, 0, 0]
        for h, n in con.execute(
                "SELECT CAST(last/3600 AS INTEGER) h, COUNT(DISTINCT dev) "
                "FROM sessions WHERE last >= ? GROUP BY h", (since,)):
            by_hour.setdefault(h, [0, 0, 0, 0])[2] = n or 0
        for h, n in con.execute(
                "SELECT CAST(ts/3600 AS INTEGER) h, COUNT(*) FROM alerts "
                "WHERE ts >= ? GROUP BY h", (since,)):
            by_hour.setdefault(h, [0, 0, 0, 0])[3] = n or 0
        buckets = []
        for h in range(h0, h1 + 1):
            b, nd, ndev, na = by_hour.get(h, [0, 0, 0, 0])
            buckets.append({"hour": h, "ts": h * 3600, "hod": _hod(h),
                            "bytes": b, "dests": nd, "devices": ndev,
                            "alerts": na})
        out["weather"]["buckets"] = buckets
        out["weather"]["peak"] = max([x["bytes"] for x in buckets] or [0])

        # ---- fingerprint: learned profile per device + deviations ----------
        cur_hour = int(now // 3600)
        cur = {}
        for dev, b, nd in con.execute(
                "SELECT dev, bytes, dests FROM dev_hourly WHERE hour = ?",
                (cur_hour,)):
            cur[dev] = (b or 0, nd or 0)
        rows = []
        for (dev, first, last, hrs, hod, ports, mx, mxd, avg) in con.execute(
                "SELECT dev,first,last,hours,hod,ports,max_bytes,max_dests,"
                "avg_bytes FROM dev_profile ORDER BY max_bytes DESC LIMIT 40"):
            cb, cd = cur.get(dev, (0, 0))
            plist = [p for p in (ports or "").split(",") if p]
            rows.append({"ip": dev, "name": names.get(dev) or dev,
                         "first": first, "last": last, "hours": hrs or 0,
                         "hod": (hod or "0" * 24), "ports": plist[:24],
                         "nports": len(plist), "max_bytes": mx or 0,
                         "max_dests": mxd or 0, "avg_bytes": avg or 0.0,
                         "cur_bytes": cb, "cur_dests": cd,
                         "mature": (hrs or 0) >= PROFILE_MIN_HOURS})
        out["fingerprint"]["devices"] = rows
        for ts, dev, kind, detail, val, base in con.execute(
                "SELECT ts,dev,kind,detail,value,baseline FROM deviations "
                "WHERE ts >= ? ORDER BY ts DESC LIMIT 60", (since,)):
            out["fingerprint"]["deviations"].append(
                {"ts": ts, "dev": dev, "name": names.get(dev) or dev,
                 "kind": kind, "detail": detail, "value": val, "baseline": base})
    except Exception as e:
        out["error"] = str(e)
    finally:
        try:
            con.close()
        except Exception:
            pass
    return out


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
        vendors = {d: mac_vendor(d)
                   for d in ({f["dev"] for f in flows}
                             | {v["dev"] for v in INBOUND.values()}
                             | {v["dev"] for v in THREAT_HITS.values()})}
        inbound_raw = [dict(v, ports=sorted(v["ports"])[:6]) for v in INBOUND.values()]
        thits_raw = [dict(v, ports=sorted(v["ports"])[:6], hosts=sorted(v["hosts"]))
                     for v in THREAT_HITS.values()]
        notes_map = dict(NOTES)
        # Flatten the agent's socket table to (device, remote) -> process once,
        # instead of scanning it per flow.
        proc_idx = {}
        for (_d, _r, _p), _v in PROCS.items():
            if now - _v["ts"] <= AGENT_TTL:
                proc_idx.setdefault((_d, _r), _v["proc"])
        agents = [dict(v, ip=d) for d, v in AGENTS.items()]
        ipv6_raw = [dict(v, dev=d) for d, v in IPV6.items()]

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
            "threat": threat, "last": f["last"],
            "note": note_for(f["rem"], host, notes_map), "procs": set()})
        if not d["note"] and host:
            d["note"] = note_for(f["rem"], host, notes_map)
        pname = proc_idx.get((f["dev"], f["rem"]))
        if pname:
            d["procs"].add(pname)
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
            "bypass": bypass.get(f["dev"], []), "threats": 0,
            "agent": "", "ipv6": 0})
        dv["dests"].add(f["rem"])
        dv["pkts"] += f["pkts"]
        dv["up"] += f["up"]
        dv["down"] += f["down"]
        dv["active"] = dv["active"] or active
        dv["last"] = max(dv["last"], f["last"])
        if threat:
            dv["threats"] += 1

    dest_list = []
    flagged_ips = set()
    for d in dests.values():
        if d["threat"]:
            flagged_ips.add(d["ip"])
        d["devices"] = sorted(d["devices"])
        d["ports"] = sorted(d["ports"])[:8]
        d["procs"] = sorted(d["procs"])[:4]
        d["ndev"] = len(d["devices"])
        d["age"] = round(now - d["last"], 1)
        dest_list.append(d)
    dest_list.sort(key=lambda d: (-(d["threat"] is not None), -d["active"],
                                  -(d["up"] + d["down"])))

    agent_by_ip = {a["ip"]: a for a in agents}
    v6_by_dev = {v["dev"]: v for v in ipv6_raw}
    dev_list = []
    for dv in devices.values():
        ag = agent_by_ip.get(dv["ip"])
        dv["agent"] = (ag or {}).get("host", "") or ("yes" if ag else "")
        dv["ipv6"] = (v6_by_dev.get(dv["ip"]) or {}).get("count", 0)
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

    # Retained threat-list hits. THIS is what the flagged tile counts — an event
    # store with the same EVENT_RETAIN window as inbound, so a flagged destination
    # no longer disappears from the counter when its flow ages out after 2 minutes.
    flagged_events = []
    for v in thits_raw:
        g = geo.get(v["rem"])
        gg = g if (g and g.get("status") == "ok") else {}
        flagged_ips.add(v["rem"])
        flagged_events.append({
            "dev": v["dev"], "dev_name": names.get(v["dev"]) or vendors.get(v["dev"], ""),
            "rem": v["rem"], "dir": v["dir"], "ports": v["ports"],
            "host": (v["hosts"] or [""])[0], "lists": v["lists"],
            "list_labels": [THREAT_LABELS.get(k, k)
                            for k in v["lists"].split(",") if k],
            "count": v["count"], "first": v["first"], "last": v["last"],
            "age": round(now - v["last"], 1),
            "active": now - v["last"] <= STALE_AFTER,
            "country": gg.get("country", ""), "cc": gg.get("countryCode", ""),
            "isp": gg.get("isp", "")})
    flagged_events.sort(key=lambda x: (-x["active"], -x["last"]))
    flagged = len(flagged_ips)

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
        "version": VERSION, "home": HOME, "geo_state": GEO_STATE,
        "capture": {"iface": CAP_STATE["iface"], "pps": CAP_STATE["pps"],
                    "drops": CAP_STATE["drops"], "error": CAP_STATE["error"],
                    "demo": CAP_STATE["demo"]},
        "threat": threat_stat,
        "stats": {"active": active_flows, "devices": len(dev_list),
                  "dests": len(dest_list), "countries": len(countries),
                  "flagged": flagged, "alerts": len(alerts),
                  "inbound": len(inbound), "ipv6": len(ipv6_raw),
                  "agents": len(agents), "notes": len(notes_map),
                  "event_retain_h": round(EVENT_RETAIN / 3600.0, 1)},
        "alerts": alerts,
        "devices": dev_list, "dests": dest_list, "inbound": inbound,
        "flagged_events": flagged_events,
        "top_devices": top_devices, "top_dests": top_dests,
        "ipv6": sorted(ipv6_raw, key=lambda v: -v["last"]),
        "agents": sorted(agents, key=lambda a: a["ip"]),
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
            _prune_procs(time.time())
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

    def _read_json(self, limit=512 * 1024):
        """Read a bounded JSON request body. Returns None on anything wrong —
        callers treat that as a 400 rather than trusting a partial parse."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n <= 0 or n > limit:
            return None
        try:
            return json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except Exception:
            return None

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

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
            try:
                hours = max(0.1, min(24.0 * RETAIN_DAYS,
                                     float(q.get("hours", ["24"])[0])))
            except ValueError:
                hours = 24.0
            dev = q.get("dev", [None])[0]
            since = time.time() - hours * 3600
            body = json.dumps({"rows": db_history(since, dev)}).encode("utf-8")
            ctype = "application/json"
        elif u.path == "/digest":
            q = parse_qs(u.query)
            try:
                days = max(1, min(90, int(float(q.get("days", ["7"])[0]))))
            except ValueError:
                days = 7
            body = json.dumps(digest_data(days)).encode("utf-8")
            ctype = "application/json"
        elif u.path == "/detail":              # everything known about one remote IP
            q = parse_qs(u.query)
            ip = (q.get("ip", [""])[0] or "").strip()
            try:                               # validate: only ever an IP literal
                ipaddress.ip_address(ip)
            except ValueError:
                self._deny(400); return
            dev = (q.get("dev", [""])[0] or "").strip()
            body = json.dumps(detail_data(ip, dev)).encode("utf-8")
            ctype = "application/json"
        elif u.path == "/dns":                 # instant cumulative DNS blocklist
            body = json.dumps({"dns_targets": dns_blocklist()}).encode("utf-8")
            ctype = "application/json"
        elif u.path == "/viz":                 # visualizations panel aggregates
            q = parse_qs(u.query)
            try:
                hours = max(1, min(24 * RETAIN_DAYS,
                                   int(float(q.get("hours", ["24"])[0]))))
            except ValueError:
                hours = 24
            body = json.dumps(viz_data(hours)).encode("utf-8")
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
        if self.path == "/agent":
            # Process attribution from a per-PC agent. Off unless an agent_token
            # is configured, so an un-configured NetWatch accepts nothing.
            token = str(CONF.get("agent_token") or "")
            if not token:
                self._json({"ok": False, "error": "agent_token not configured"}, 403)
                return
            sent = str(self.headers.get("X-NetWatch-Token") or "")
            if not hmac.compare_digest(sent, token):
                self._json({"ok": False, "error": "bad token"}, 403)
                return
            payload = self._read_json()
            if not isinstance(payload, dict):
                self._json({"ok": False, "error": "bad body"}, 400)
                return
            dev = self.client_address[0]
            try:                        # only a LAN peer can describe a LAN device
                addr = ipaddress.ip_address(dev)
                if not (is_private_lan(addr) or addr.is_loopback):
                    self._json({"ok": False, "error": "not a LAN client"}, 403)
                    return
            except ValueError:
                self._deny(400); return
            n = agent_ingest(dev, payload)
            self._json({"ok": True, "accepted": n, "dev": dev})
            return
        if self.path == "/note":
            payload = self._read_json(8192)
            if not isinstance(payload, dict):
                self._json({"ok": False, "error": "bad body"}, 400)
                return
            try:
                text = save_note(payload.get("key", ""), payload.get("note", ""))
            except ValueError:
                self._json({"ok": False, "error": "bad key"}, 400)
                return
            except Exception as e:
                self._json({"ok": False, "error": str(e)}, 500)
                return
            self._json({"ok": True, "note": text})
            return
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
  .badge2.dot{background:#1a3a4a;color:#7dd3fc}
  .badge2.threat{background:var(--bad);color:#fff}
  .kindrow.open{background:var(--surface-3)}
  .kinddevs{padding:2px 12px 8px 22px;border-bottom:1px solid #262623}
  .kinddev{display:flex;justify-content:space-between;gap:8px;font-size:12px;
    color:var(--text-secondary);padding:3px 0}
  .kinddev .cnt{color:var(--text-muted);font-size:11px;flex:none}
  .bytes{color:var(--text-muted);font-size:11px;font-variant-numeric:tabular-nums}
  .tile.alert{cursor:pointer} .tile.alert:hover{background:#3a2a10}
  .tile.flagged b{color:var(--bad)}
  .tile.inbound b{color:var(--warn)}
  .tile.jump{cursor:pointer}
  .tile.jump:hover{background:#3a2a2a}
  /* flagged (retained threat event) rows */
  .flg{padding:8px 12px;border-bottom:1px solid #262623;border-left:3px solid var(--bad);
    cursor:pointer}
  .flg:hover{background:var(--surface-3)}
  .flg .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .flg .nm{font-weight:600;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
  .flg .meta{color:var(--text-secondary);font-size:12px;margin-top:1px}
  .flg .ipline{color:var(--text-muted);font-size:11px;font-family:Consolas,ui-monospace,monospace;margin-top:1px}
  .flg .when{color:var(--text-muted);font-size:11px;flex:none}
  .lst{font-size:9px;padding:1px 5px;border-radius:4px;background:#4a2020;color:#ff9d9d;
    font-weight:600;text-transform:uppercase;letter-spacing:.03em}
  .dirb{font-size:9px;padding:1px 5px;border-radius:4px;background:var(--surface-3);
    color:var(--text-secondary);font-weight:600;text-transform:uppercase}
  .inb,.al{cursor:pointer}
  .al:hover,.inb:hover{background:var(--surface-3)}
  .info{margin-left:auto;color:var(--text-muted);font-size:11px;border:1px solid var(--border);
    border-radius:5px;padding:0 5px;flex:none;cursor:pointer}
  .info:hover{border-color:var(--series-1);color:var(--text-primary)}
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
  #ver{color:var(--text-muted);font-size:11px;align-self:center;margin:-6px 4px 0 -4px;font-family:Consolas,ui-monospace,monospace}
  .dg-copy{margin:6px 12px;padding:6px 12px;background:var(--surface-3);border:1px solid var(--border);
    color:var(--text-secondary);border-radius:7px;font:inherit;font-size:12px;cursor:pointer}
  .dg-copy:hover{border-color:var(--series-1);color:var(--text-primary)}
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
  #digestBtn,#vizBtn{align-self:center;background:var(--surface-3);border:1px solid var(--border);
    color:var(--text-secondary);border-radius:8px;padding:6px 10px;font:inherit;font-size:11px;cursor:pointer}
  #digestBtn:hover,#vizBtn:hover{border-color:var(--series-1);color:var(--text-primary)}
  /* visualizations panel */
  #viz{position:absolute;top:0;right:0;width:620px;max-width:96vw;height:100%;z-index:1600;
    background:var(--surface-2);border-left:1px solid var(--border);
    transform:translateX(102%);transition:transform .18s ease;display:flex;flex-direction:column}
  #viz.open{transform:none}
  #viz .hd{display:flex;justify-content:space-between;align-items:center;padding:12px 14px;
    border-bottom:1px solid var(--border);font-weight:600}
  #viz .hd button{background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer}
  .vseg{display:flex;gap:2px;padding:8px 12px;border-bottom:1px solid var(--border)}
  .vseg button{flex:1;background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);
    border-radius:6px;padding:5px 4px;font:inherit;font-size:11px;cursor:pointer}
  .vseg button.on{background:#20303f;border-color:var(--series-1);color:var(--text-primary)}
  .vwin{display:flex;gap:8px;align-items:center;padding:6px 12px;border-bottom:1px solid var(--border);
    font-size:11px;color:var(--text-muted)}
  .vwin select{background:var(--surface-3);color:var(--text-secondary);border:1px solid var(--border);
    border-radius:6px;padding:3px 6px;font:inherit;font-size:11px}
  #vizBody{overflow-y:auto;flex:1;padding:10px 12px 40px}
  #vizBody h4{margin:2px 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:.08em;
    color:var(--text-muted);font-weight:600}
  #vizBody .vnote{color:var(--text-muted);font-size:11px;margin:8px 2px 12px;line-height:1.5}
  .vlegend{display:flex;flex-wrap:wrap;gap:6px 14px;margin:8px 0 4px;font-size:11px;
    color:var(--text-secondary)}
  .vlegend span{display:inline-flex;align-items:center;gap:5px}
  .vlegend i{width:9px;height:9px;border-radius:2px;display:inline-block}
  .vempty{color:var(--text-muted);text-align:center;padding:34px 10px;font-size:12px}
  svg.vchart{width:100%;display:block;overflow:visible}
  svg.vchart text{fill:var(--text-secondary);font:11px "Segoe UI",system-ui,sans-serif;
    paint-order:stroke;stroke:var(--surface-2);stroke-width:3px;stroke-linejoin:round}
  svg.vchart text.mut{fill:var(--text-muted);font-size:10px}
  svg.vchart .grid{stroke:var(--border);stroke-width:1}
  svg.vchart .hit{cursor:pointer}
  .vtable{width:100%;border-collapse:collapse;font-size:11px;margin-top:6px}
  .vtable th{text-align:left;color:var(--text-muted);font-weight:600;text-transform:uppercase;
    font-size:10px;letter-spacing:.05em;padding:4px 6px;border-bottom:1px solid var(--border)}
  .vtable td{padding:4px 6px;border-bottom:1px solid #262623;vertical-align:top}
  .vtable td.num{text-align:right;font-variant-numeric:tabular-nums}
  .fpcard{border:1px solid var(--border);border-radius:8px;padding:9px 11px;margin-bottom:8px;
    background:var(--surface-1)}
  .fpcard .fh{display:flex;justify-content:space-between;align-items:baseline;gap:8px}
  .fpcard .fh b{font-size:12px} .fpcard .fh small{color:var(--text-muted);font-size:10px}
  .fpstrip{display:flex;gap:2px;margin:7px 0 5px}
  .fpstrip i{flex:1;height:13px;border-radius:2px;background:var(--surface-3);display:block}
  .fpstrip i.on{background:var(--series-1)}
  .fpstrip i.now{outline:2px solid var(--warn);outline-offset:1px}
  .fpmeta{color:var(--text-muted);font-size:10.5px;line-height:1.6}
  .fpmeta code{color:var(--text-secondary);font-size:10.5px}
  .dv{border-left:3px solid var(--warn);padding:6px 10px;margin-bottom:6px;background:var(--surface-1);
    border-radius:0 6px 6px 0}
  .dv b{font-size:11.5px} .dv small{display:block;color:var(--text-muted);font-size:10.5px;margin-top:2px}
  .dv.volume{border-left-color:var(--bad)}
  .dt-note{padding:10px 14px;border-bottom:1px solid var(--border)}
  .dt-note label{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em;
    color:var(--text-muted);margin-bottom:6px}
  .dt-noterow{display:flex;gap:6px}
  .dt-note input{flex:1;padding:6px 9px;border-radius:6px;border:1px solid var(--border);
    background:var(--surface-1);color:var(--text-primary);font:inherit;outline:none}
  .dt-note input:focus{border-color:var(--series-1)}
  .dt-note button{background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);
    border-radius:6px;padding:6px 12px;font:inherit;font-size:11px;cursor:pointer}
  .dt-note button:hover{border-color:var(--series-1);color:var(--text-primary)}
  .dt-note small{display:block;color:var(--text-muted);font-size:10.5px;margin-top:5px;min-height:13px}
  .noteline{color:var(--text-secondary);font-size:11px;margin-top:2px;font-style:italic}
  .procline{color:var(--text-muted);font-size:11px;margin-top:2px}
  .row.noted{border-left:3px solid var(--good)}
  .badge2.v6{background:#3a2f52;color:#c9bdf0}
  .badge2.agent{background:#1f3a2c;color:#8fd6ab}
  .al{padding:9px 14px;border-bottom:1px solid #262623;border-left:3px solid var(--text-muted)}
  .al.critical{border-left-color:var(--bad)} .al.warning{border-left-color:var(--warn)}
  .al.notice{border-left-color:var(--series-1)} .al.info{border-left-color:var(--text-muted)}
  .al .k{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--text-muted)}
  .al .m{margin-top:2px} .al .w{color:var(--text-muted);font-size:11px;margin-top:2px}
  .hist .top{display:flex;justify-content:space-between;gap:8px}
  .hist .when{color:var(--text-muted);font-size:11px}
  /* ---- detail drawer (one remote IP, everything we know) ---- */
  #detail{position:absolute;top:0;right:0;width:460px;max-width:96vw;height:100%;z-index:1700;
    background:var(--surface-2);border-left:1px solid var(--border);box-shadow:-8px 0 28px #000a;
    transform:translateX(100%);transition:transform .18s ease;display:flex;flex-direction:column}
  #detail.open{transform:none}
  #detail .hd{display:flex;justify-content:space-between;align-items:center;gap:8px;
    padding:12px 14px;border-bottom:1px solid var(--border);font-weight:600}
  #detail .hd .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  #detail .hd button{background:none;border:none;color:var(--text-muted);font-size:18px;
    cursor:pointer;flex:none}
  #detailBody{overflow-y:auto;flex:1;padding:0 0 40px}
  .dt-verdict{padding:12px 14px;border-bottom:1px solid var(--border)}
  .dt-verdict.bad{background:#2a1414;border-left:3px solid var(--bad)}
  .dt-verdict.ok{background:#16221a;border-left:3px solid var(--good)}
  .dt-verdict b{display:block;font-size:14px;margin-bottom:3px}
  .dt-verdict p{margin:5px 0 0;color:var(--text-secondary);font-size:12px}
  .dt-kv{display:grid;grid-template-columns:104px 1fr;gap:3px 10px;padding:10px 14px;
    border-bottom:1px solid var(--border);font-size:12px}
  .dt-kv dt{color:var(--text-muted)}
  .dt-kv dd{margin:0;overflow-wrap:anywhere}
  .dt-mono{font-family:Consolas,ui-monospace,monospace}
  .dt-row{padding:8px 14px;border-bottom:1px solid #262623;font-size:12px}
  .dt-row .top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
  .dt-row b{font-weight:600}
  .dt-row .sub{color:var(--text-muted);font-size:11px;margin-top:2px}
  .dt-empty{padding:10px 14px;color:var(--text-muted);font-size:12px}
  .dt-actions{display:flex;gap:6px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--border)}
  .dt-actions button{background:var(--surface-3);border:1px solid var(--border);color:var(--text-secondary);
    border-radius:7px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}
  .dt-actions button:hover{border-color:var(--series-1);color:var(--text-primary)}
  /* ---- small screens: stack the panel under the map instead of hiding it ---- */
  @media (max-width:900px){
    main{grid-template-columns:1fr;grid-template-rows:34vh minmax(0,1fr)}
    #map{min-height:0}
    aside{border-left:none;border-top:1px solid var(--border);min-height:0}
    header{gap:6px;padding:7px 9px}
    #ver{display:none}
    .pill{font-size:10px;padding:2px 8px}
    .tiles{gap:5px;width:100%;margin-left:0}
    .tile{min-width:0;padding:3px 7px;text-align:center}
    .tile b{font-size:14px}
    .tile small{font-size:9px;letter-spacing:0;white-space:nowrap}
    #digestBtn,#alertBtn,#quitBtn{padding:5px 8px}
    #detail,#alerts,#digest,#viz{width:100%;max-width:100%}
    #banner{top:auto;bottom:12px}
  }
</style>
</head>
<body>
<div id="app">
  <header>
    <h1>Net<span>Watch</span></h1>
    <span id="ver" title="running build">v–</span>
    <span class="pill" id="capPill"><span class="led"></span><span id="capTxt">capture</span></span>
    <span class="pill" id="geoPill"><span class="led"></span><span id="geoTxt">geo: waiting</span></span>
    <span class="pill" id="threatPill" style="display:none"><span class="led"></span><span id="threatTxt">threat</span></span>
    <div class="tiles">
      <div class="tile"><b id="tActive">–</b><small>active flows</small></div>
      <div class="tile"><b id="tDevices">–</b><small>devices</small></div>
      <div class="tile"><b id="tDests">–</b><small>destinations</small></div>
      <div class="tile flagged jump" id="tileFlagged"
        title="Blocklisted IPs seen recently — click to jump to the list">
        <b id="tFlagged">–</b><small>flagged</small></div>
      <div class="tile inbound jump" id="tileInbound"
        title="Unsolicited inbound sources seen recently — click to jump to the list">
        <b id="tInbound">–</b><small>inbound</small></div>
      <button id="vizBtn" title="Constellation, flow, weather and device fingerprints">&#9680; views</button>
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
    <button data-view="dns">DNS list</button>
  </div>
  <div id="digestBody"><div class="empty">Loading&hellip;</div></div>
</div>
<div id="viz">
  <div class="hd"><span>Visualizations</span><button id="vizClose">&times;</button></div>
  <div class="vseg">
    <button data-view="constellation" class="on">Constellation</button>
    <button data-view="flow">Flow</button>
    <button data-view="weather">Weather</button>
    <button data-view="fingerprint">Fingerprint</button>
  </div>
  <div class="vwin"><label for="vizHours">window</label>
    <select id="vizHours">
      <option value="1">1 hour</option>
      <option value="6">6 hours</option>
      <option value="24" selected>24 hours</option>
      <option value="168">7 days</option>
      <option value="720">30 days</option>
    </select>
    <span id="vizStamp"></span></div>
  <div id="vizBody"><div class="vempty">Loading&hellip;</div></div>
</div>
<div id="detail">
  <div class="hd"><span class="t" id="detailTitle">Details</span>
    <button id="detailClose" title="Close (Esc)">&times;</button></div>
  <div id="detailBody"><div class="dt-empty">Loading&hellip;</div></div>
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
// Replace a scrollable list's contents without yanking the user's scroll position
// back to the top on every 2.5s poll, and skip the DOM work entirely when the
// markup hasn't changed (the common case between ticks).
function setHTML(el,html){
  if(!el)return;
  if(el.dataset.sig===html)return;
  const y=el.scrollTop;
  el.innerHTML=html;
  el.dataset.sig=html;
  if(y)el.scrollTop=y;
}
const IPRE=/^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)$/;
function isIP(s){return !!s&&IPRE.test(String(s).trim());}
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
function arcWeight(bytes,bad){
  // 1px at a handful of bytes up to 7px at ~100 MB, log-scaled.
  const w=1+Math.log2(1+(bytes||0)/4096)*0.42;
  return Math.max(bad?2:1,Math.min(w,7));
}
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
    +((d.procs&&d.procs.length)?'<div class="tt-isp">&#9881; '+esc(d.procs.join(", "))+"</div>":"")
    +(d.note?'<div class="tt-host" style="font-style:italic">&#9998; '+esc(d.note)+"</div>":"")
    +'<div class="tt-dev">'+devs+"</div>";}

function render(d){
  latest=d;
  if(d.version)document.getElementById("ver").textContent="v"+d.version;
  document.getElementById("tActive").textContent=d.stats.active;
  document.getElementById("tDevices").textContent=d.stats.devices;
  document.getElementById("tDests").textContent=d.stats.dests;
  document.getElementById("tFlagged").textContent=d.stats.flagged;
  document.getElementById("tInbound").textContent=d.stats.inbound||0;
  // Both counters are event counters over the SAME retention window, so flagged can
  // never drain faster than inbound. Say so in the tooltip.
  const rh=d.stats.event_retain_h||6;
  document.getElementById("tileFlagged").title=
    "Blocklisted IPs contacted in the last "+rh+"h (kept "+rh
    +"h after the last sighting) — click to jump to the list";
  document.getElementById("tileInbound").title=
    "Unsolicited inbound sources in the last "+rh+"h — click to jump to the list";

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
        // Bandwidth arc: thickness carries volume, so a 900 KB upload no longer
        // looks identical to a 40-byte keepalive. Log-scaled — a home network
        // spans several orders of magnitude in a single window.
        const aw=arcWeight(x.up+x.down,bad);
        const ao=bad?.85:(x.active?Math.min(.35+Math.log2(1+(x.up+x.down)/20000)*0.08,.75):.16);
        let e=layers.get(x.ip);
        if(!e){
          const marker=L.marker(ll,{icon:dotIcon(cls,size,color),zIndexOffset:bad?800:0}).addTo(map)
            .bindTooltip(destTip(x),{className:"nm",direction:"top",offset:[0,-8],sticky:true});
          let arc=null;
          if(homeLL) arc=L.polyline(arcPoints(homeLL,ll),{color:color,weight:aw,
            opacity:ao,className:x.active?"nm-arc":"",interactive:false}).addTo(map);
          e={marker,arc};layers.set(x.ip,e);
        }else{
          e.marker.setIcon(dotIcon(cls,size,color));
          e.marker.setTooltipContent(destTip(x));
          if(e.arc) e.arc.setStyle({color:color,weight:aw,opacity:ao,className:x.active?"nm-arc":""});
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
    :t==="dot"
    ?'<span class="badge2 dot" title="Using its own encrypted DNS (DoT)">&#9888; DoT</span>'
    :'<span class="badge2 dns" title="Using an external DNS resolver, bypassing Pi-hole">&#9888; ext-DNS</span>').join("");
}

function inboundRow(ib){
  return '<div class="inb'+(ib.threat?" bad":"")+'" data-ip="'+esc(ib.rem)+'" data-dev="'
    +esc(ib.dev)+'" title="Click for details"><div class="nm">'
    +(ib.threat?'<span class="badge2 threat">&#9888; flagged</span> ':"")
    +flag(ib.cc)+" "+esc(ib.rem)+"</div>"
    +'<div class="meta">to <b>'+esc(ib.dev_name||ib.dev)+"</b> on port"+(ib.ports.length>1?"s":"")
    +" "+ib.ports.join(", ")+(ib.country?" &middot; from "+esc(ib.country):"")+"</div>"
    +'<div class="ipline">'+ib.count+" attempt"+(ib.count===1?"":"s")
    +(ib.isp?" &middot; "+esc(ib.isp):"")+"</div></div>";
}

// A retained threat-list hit. These come from the server's event store, not the
// live flow table, so a flagged destination stays listed for the full retention
// window (same one inbound uses) instead of vanishing when the flow ages out.
function flaggedRow(fe){
  const lists=(fe.list_labels||[]).map(l=>'<span class="lst">'+esc(l)+"</span>").join(" ");
  const dir=fe.dir==="in"?'<span class="dirb">inbound</span>':'<span class="dirb">outbound</span>';
  return '<div class="flg" data-ip="'+esc(fe.rem)+'" data-dev="'+esc(fe.dev)
    +'" title="Click for details"><div class="top"><div class="nm">'
    +flag(fe.cc)+" "+esc(fe.host||fe.rem)+" "+dir+" "+lists+"</div>"
    +'<div class="when">'+ago(fe.last)+"</div></div>"
    +'<div class="meta">'+(fe.dir==="in"?"to ":"")+"<b>"+esc(fe.dev_name||fe.dev)+"</b>"
    +(fe.ports.length?" &middot; port"+(fe.ports.length>1?"s":"")+" "+fe.ports.join(", "):"")
    +(fe.country?" &middot; "+esc(fe.country):"")+"</div>"
    +'<div class="ipline">'+esc(fe.rem)+(fe.isp?" &middot; "+esc(fe.isp):"")+"</div></div>";
}

function renderList(){
  if(!latest)return;
  if(mode==="hist"){renderHistory();return;}
  if(mode==="top"){renderTop();return;}
  const q=document.getElementById("q").value.trim().toLowerCase();
  const list=document.getElementById("list");
  let html="";

  const rh=(latest.stats&&latest.stats.event_retain_h)||6;

  // Flagged (threat-list) hits, retained for the same window as inbound.
  if(latest.flagged_events && latest.flagged_events.length){
    const fe=latest.flagged_events.filter(x=>{
      const hay=(x.rem+" "+(x.host||"")+" "+(x.dev_name||x.dev)+" "
        +(x.country||"")+" "+(x.list_labels||[]).join(" ")).toLowerCase();
      return !q||hay.includes(q);
    });
    if(fe.length)
      html+='<div class="section-hd" id="secFlagged"><span>&#9888; Flagged &middot; last '
        +rh+"h</span></div>"+fe.map(flaggedRow).join("");
  }

  // Inbound connection attempts (usually empty behind NAT; shown when present)
  if(latest.inbound && latest.inbound.length){
    const ib=latest.inbound.filter(x=>{
      const hay=(x.rem+" "+(x.dev_name||x.dev)+" "+(x.country||"")).toLowerCase();
      return !q||hay.includes(q);
    });
    if(ib.length)
      html+='<div class="section-hd" id="secInbound"><span>&#9888; Inbound connections &middot; last '
        +rh+"h</span></div>"+ib.map(inboundRow).join("");
  }

  const drows=[];
  for(const dv of latest.devices){
    const label=dv.name||dv.vendor||dv.ip;
    if(q && !(label+" "+dv.ip).toLowerCase().includes(q)) continue;
    const tb=dv.threats?'<span class="badge2 threat" title="talks to a flagged IP">&#9888;</span>':"";
    const vend=(!dv.name&&dv.vendor)?'<span class="vendor">('+esc(dv.vendor)+")</span>":"";
    // IPv6 is meant to be off on this network, so seeing any is worth a badge.
    const v6=dv.ipv6?'<span class="badge2 v6" title="talking over IPv6 — IPv6 should be disabled">IPv6</span>':"";
    const ag=dv.agent?'<span class="badge2 agent" title="process names reported by an agent on this machine">&#9881;</span>':"";
    drows.push('<div class="row'+(dv.active?"":" off")+(dv.threats?" flag":"")+(selDev===dv.ip?" sel":"")
      +'" data-dev="'+esc(dv.ip)+'"><div class="top"><div class="nm">'
      +'<span class="sw" style="background:'+colorFor(dv.ip)+'"></span>'+esc(label)+" "+vend+" "+tb+v6+ag+bypassBadges(dv)+"</div>"
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
    const hay=(x.ip+" "+(x.host||"")+" "+(g.country||"")+" "+(g.city||"")+" "+(g.isp||"")
      +" "+(x.note||"")+" "+((x.procs||[]).join(" "))).toLowerCase();
    if(q && !hay.includes(q)) continue;
    const tb=x.threat?'<span class="badge2 threat">&#9888; flagged</span> ':"";
    // A note is the user's own verdict on this destination, so it outranks
    // anything we inferred — show it right under the name.
    const nb=x.note?'<div class="noteline">&#9998; '+esc(x.note)+"</div>":"";
    const pb=(x.procs&&x.procs.length)
      ?'<div class="procline">&#9881; '+esc(x.procs.join(", "))+"</div>":"";
    rrows.push('<div class="row'+(x.active?"":" off")+(x.threat?" flag":"")
      +(x.note?" noted":"")+'" data-dest="'+esc(x.ip)+'">'
      +'<div class="top"><div class="nm">'+tb+esc(x.host||g.country||x.ip)
      +'<span class="info" data-ip="'+esc(x.ip)+'" title="What is this?">&#9432;</span></div>'
      +'<div class="cnt">'+x.ndev+" dev"+(x.ndev===1?"":"s")+"</div></div>"
      +nb+pb
      +'<div class="loc">'+flag(g.countryCode)+" "+esc(g.city?g.city+", ":"")
      +(g.country?esc(g.country):"locating&hellip;")+(g.isp?' &middot; <span style="color:var(--text-muted)">'+esc(g.isp)+"</span>":"")+"</div>"
      +'<div class="ipline">'+esc(x.ip)+'</div>'
      +'<div class="bytes">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>");
  }
  html+='<div class="section-hd"><span>Destinations'+(selDev?" &middot; "+esc(devLabel(selDev)):"")+"</span></div>"
    +(rrows.length?rrows.join(""):'<div class="empty">'+(q?"No matches.":"No destinations yet&hellip;")+"</div>");

  setHTML(list,html);
}

function renderAlerts(alerts){
  const el=document.getElementById("alertList");
  if(!alerts.length){setHTML(el,'<div class="empty">No alerts yet.</div>');return;}
  // Alerts whose subject is an IP (threat hits, inbound, new destination) are
  // clickable straight through to the detail drawer.
  setHTML(el,alerts.map(a=>{
    const ip=isIP(a.rem)?a.rem:"";
    return '<div class="al '+esc(a.level)+'"'
      +(ip?' data-ip="'+esc(ip)+'" data-dev="'+esc(a.dev||"")+'" title="Click for details"'
          :' style="cursor:default"')
      +'><div class="k">'+esc(a.kind.replace(/_/g," "))+" &middot; "+ago(a.ts)
      +(ip?' &middot; <span style="color:var(--series-1)">details</span>':"")+"</div>"
      +'<div class="m"><b>'+esc(a.dev_name||a.dev)+"</b> "+esc(a.msg)+"</div>"
      +(a.host||a.rem?'<div class="w">'+esc(a.host||a.rem)+"</div>":"")+"</div>";
  }).join(""));
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
  setHTML(list,'<div class="section-hd"><span>History &middot; last 24h'
    +(selDev?" &middot; "+esc(devLabel(selDev)):"")+"</span></div>"
    +(rows||'<div class="empty">No history in this window yet.</div>'));
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
  html+=ds.length?ds.map(x=>'<div class="tt-row" data-ip="'+esc(x.ip)+'" style="cursor:pointer"'
    +' title="Click for details"><div class="top"><div class="nm">'
    +flag(x.cc)+" "+esc(x.host)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"
    +bar(x.total,maxT,"")
    +'<div class="updown">&#8593; '+fmtBytes(x.up)+" &nbsp; &#8595; "+fmtBytes(x.down)+"</div></div>").join("")
    :'<div class="empty">No traffic yet&hellip;</div>';
  setHTML(list,html);
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
  // Anything carrying data-ip (flagged rows, inbound rows, the ⓘ chip on a
  // destination, top-talker rows) opens the detail drawer for that remote IP.
  const iprow=e.target.closest("[data-ip]");
  if(iprow){openDetail(iprow.dataset.ip,iprow.dataset.dev||"");return;}
  const drow=e.target.closest("[data-dev]");
  if(drow){selDev=(selDev===drow.dataset.dev)?null:drow.dataset.dev;wipeLayers();
    if(mode==="hist")loadHistory(); else render(latest);return;}
  const rrow=e.target.closest("[data-dest]");
  if(rrow){const e2=layers.get(rrow.dataset.dest);
    if(e2&&map){map.flyTo(e2.marker.getLatLng(),Math.max(map.getZoom(),5));e2.marker.openTooltip();}
    else openDetail(rrow.dataset.dest,"");}
});
function jumpTo(id){
  setMode("live");
  const go=()=>{const el=document.getElementById(id);
    if(el&&el.scrollIntoView)el.scrollIntoView({block:"start",behavior:"smooth"});};
  setTimeout(go,30);
}
document.getElementById("tileFlagged").addEventListener("click",()=>jumpTo("secFlagged"));
document.getElementById("tileInbound").addEventListener("click",()=>jumpTo("secInbound"));
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
let digestGroups=[];   // current alert-kind groups, indexed for the click-to-expand handler
const KIND_LABEL={"dev_rem":"new destination","dev_country":"new country",
  "threat":"threat-list hit","inbound":"unsolicited inbound",
  "bypass_plaintext-dns":"bypass plaintext-dns","device":"new device"};
function alertGroupLabel(kind){
  if(kind==="bypass_doh"||kind==="bypass_dot")return "bypass DoH/DoT";
  return KIND_LABEL[kind]||kind.replace(/_/g," ");
}
function mergeAlertGroups(d){
  const byKindDev=d.alerts_by_kind_dev||{};
  const groupKeyOf=k=>(k==="bypass_doh"||k==="bypass_dot")?"bypass_doh_dot":k;
  const groups={};
  for(const [k,c] of Object.entries(d.alerts_by_kind||{})){
    const gk=groupKeyOf(k);
    const g=groups[gk]||(groups[gk]={label:alertGroupLabel(k),count:0,devices:{}});
    g.count+=c;
    for(const dv of (byKindDev[k]||[])){
      const cur=g.devices[dv.dev]||{dev:dv.dev,name:dv.dev_name||dv.dev,count:0};
      cur.count+=dv.count;
      g.devices[dv.dev]=cur;
    }
  }
  return Object.values(groups).map(g=>({label:g.label,count:g.count,
    devices:Object.values(g.devices).sort((a,b)=>b.count-a.count)}))
    .sort((a,b)=>b.count-a.count);
}
document.getElementById("digestBody").addEventListener("click",e=>{
  const iprow=e.target.closest("[data-ip]");
  if(iprow){openDetail(iprow.dataset.ip,iprow.dataset.dev||"");return;}
  const row=e.target.closest("[data-gi]");
  if(!row)return;
  const box=document.getElementById("kinddevs_"+row.dataset.gi);
  if(!box)return;
  const opening=box.style.display==="none";
  document.querySelectorAll(".kinddevs").forEach(b=>{b.style.display="none";});
  document.querySelectorAll(".kindrow").forEach(r=>r.classList.remove("open"));
  if(!opening)return;
  const g=digestGroups[row.dataset.gi];
  box.innerHTML=(g&&g.devices.length)?g.devices.map(dv=>'<div class="kinddev"><span>'
    +esc(dv.name)+'</span><span class="cnt">'+dv.count+"</span></div>").join("")
    :'<div class="empty">No device breakdown available.</div>';
  box.style.display="block";
  row.classList.add("open");
});
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
  h+=d.top_dests.length?d.top_dests.map(x=>'<div class="tt-row" data-ip="'+esc(x.ip||"")
    +'" style="cursor:pointer" title="Click for details"><div class="top">'
    +'<div class="nm">'+flag(x.cc)+" "+esc(x.host)+'</div><div class="tot">'+fmtBytes(x.total)+"</div></div>"+bar(x.total,maxT)+"</div>").join("")
    :"";
  h+='<div class="section-hd"><span>Alerts ('+d.alerts_total+")</span></div>";
  digestGroups=mergeAlertGroups(d);
  h+=digestGroups.length?digestGroups.map((g,i)=>'<div class="row kindrow" data-gi="'+i+'">'
    +'<div class="top"><div class="nm">'+esc(g.label)+'</div><div class="cnt">'+g.count+"</div></div></div>"
    +'<div class="kinddevs" id="kinddevs_'+i+'" style="display:none"></div>').join("")
    :'<div class="empty">No alerts in this window.</div>';
  if(d.threats.length){
    h+='<div class="section-hd"><span>&#9888; Threat-list hits ('+d.threats.length+")</span></div>";
    h+='<div class="dg-note">Click any row to see what the address is, which '
      +'blocklist flagged it, and every time your network touched it.</div>';
    h+=d.threats.slice(0,25).map(t=>'<div class="row flag" data-ip="'+esc(t.ip||"")
      +'" data-dev="'+esc(t.dev_ip||"")+'" title="Click for details">'
      +'<div class="top"><div class="nm">'+esc(t.dev)+" &rarr; "+esc(t.rem)
      +'</div><div class="cnt">'+fmtBytes(t.total||0)+"</div></div>"
      +'<div class="loc">'+flag(t.cc)+" "+esc(t.country||"")+" "
      +(t.lists||[]).map(l=>'<span class="lst">'+esc(l)+"</span>").join(" ")+"</div>"
      +'<div class="ipline">'+esc(t.ip||"")+(t.last?" &middot; "+ago(t.last):"")
      +'</div></div>').join("");
  }
  setHTML(document.getElementById("digestBody"),h);
}
function dnsSection(title,note,id,items){
  if(!items.length)
    return '<div class="section-hd"><span>'+title+' (0)</span></div>'
      +'<div class="empty">None seen.</div>';
  return '<div class="section-hd"><span>'+title+' ('+items.length+')</span></div>'
    +'<div class="dg-note">'+note+'</div>'
    +'<button class="dg-copy" id="copy_'+id+'">Copy all</button>'
    +items.map(t=>'<div class="row"><div class="top">'
      +'<div class="nm">'+esc(t.server)+'</div><div class="cnt">'+t.hits+"</div></div>"
      +'<div class="ipline">'+esc(t.kind)+"</div></div>").join("");
}
function wireCopy(id,items){
  const btn=document.getElementById("copy_"+id); if(!btn)return;
  const text=items.map(t=>t.server).join("\n");
  btn.addEventListener("click",()=>{
    const done=()=>{btn.textContent="Copied!";setTimeout(()=>{btn.textContent="Copy all";},1500);};
    if(navigator.clipboard&&navigator.clipboard.writeText)
      navigator.clipboard.writeText(text).then(done).catch(()=>fallbackCopy(text,done,btn));
    else fallbackCopy(text,done,btn);
  });
}
async function loadDNS(){
  const body=document.getElementById("digestBody");
  body.innerHTML='<div class="empty">Loading&hellip;</div>';
  let d;
  try{ d=await (await fetch("/dns",{cache:"no-store"})).json(); }
  catch(e){ body.innerHTML='<div class="empty">Could not load DNS list.</div>'; return; }
  const list=d.dns_targets||[];
  let h='<div class="dg-hero"><b>'+list.length+'</b><small>DNS servers seen &middot; cumulative blocklist</small></div>';
  if(!list.length){
    body.innerHTML=h+'<div class="empty">No DNS-bypass activity recorded yet. As devices try their own resolvers (plaintext, DoT or DoH), they show up here.</div>';
    return;
  }
  const ips=list.filter(t=>t.block_at==="firewall");
  const doms=list.filter(t=>t.block_at==="pihole");
  h+=dnsSection("Block at firewall / ACL","IPs your devices reached directly (plaintext DNS, DoT, or DoH-by-IP). Add these to an ACL / IP group.","fw",ips);
  h+=dnsSection("Block at Pi-hole","DoH/DoT hostnames &mdash; block these as domains in Pi-hole (the firewall can't match them by IP).","ph",doms);
  body.innerHTML=h;
  wireCopy("fw",ips); wireCopy("ph",doms);
}
function fallbackCopy(text,done,btn){
  const ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
  document.body.appendChild(ta);ta.select();
  try{ document.execCommand("copy"); done(); }
  catch(e){ btn.textContent="Select the list & copy"; }
  document.body.removeChild(ta);
}
document.getElementById("digestBtn").addEventListener("click",()=>{
  const opening=!digestPanel.classList.contains("open");
  digestPanel.classList.toggle("open");
  if(opening)loadDigest();
});
document.getElementById("digestClose").addEventListener("click",()=>digestPanel.classList.remove("open"));
document.querySelectorAll(".dseg button").forEach(b=>b.addEventListener("click",()=>{
  document.querySelectorAll(".dseg button").forEach(x=>x.classList.toggle("on",x===b));
  if(b.dataset.view==="dns"){ loadDNS(); }
  else { digestDays=+b.dataset.days; loadDigest(); }
}));

// ---- Visualizations panel --------------------------------------------------
// Four questions asked of the same window. Device colour is the SAME colour the
// device has on the map (colorFor), so identity carries across every view — a
// filter or a re-sort never repaints a device.
const vizPanel=document.getElementById("viz");
let vizView="constellation", vizHours=24, vizData=null, vizBusy=false;

// sequential ramp: one hue (the series-1 blue), dim -> bright against the dark
// surface. Magnitude is lightness, never a second hue.
const RAMP=["#22303f","#243f5c","#27507b","#2a6199","#2f74bd","#3987e5","#69a6ef","#a3ccf7"];
function rampFor(v,max){
  if(!max||v<=0)return "#1f2a33";
  const t=Math.log2(1+v)/Math.log2(1+max);
  return RAMP[Math.max(0,Math.min(RAMP.length-1,Math.round(t*(RAMP.length-1))))];
}
function shortLabel(s,n){s=String(s||"");return s.length>n?s.slice(0,n-1)+"…":s;}
function hourLabel(ts){const d=new Date(ts*1000);
  return String(d.getHours()).padStart(2,"0")+":00";}
function dayLabel(ts){const d=new Date(ts*1000);
  return (d.getMonth()+1)+"/"+d.getDate();}

async function loadViz(){
  if(vizBusy)return; vizBusy=true;
  const body=document.getElementById("vizBody");
  if(!vizData)body.innerHTML='<div class="vempty">Loading&hellip;</div>';
  try{
    const r=await fetch("/viz?hours="+vizHours,{cache:"no-store"});
    vizData=await r.json();
  }catch(e){ vizData=null; }
  vizBusy=false;
  renderViz();
}
function renderViz(){
  const body=document.getElementById("vizBody");
  const stamp=document.getElementById("vizStamp");
  if(!vizData){ body.innerHTML='<div class="vempty">Could not load visualization data.</div>'; return; }
  stamp.textContent=vizData.generated?("updated "+ago(vizData.generated)):"";
  if(vizView==="constellation")body.innerHTML=vizConstellation(vizData.constellation);
  else if(vizView==="flow")body.innerHTML=vizFlow(vizData.flow);
  else if(vizView==="weather")body.innerHTML=vizWeather(vizData.weather);
  else body.innerHTML=vizFingerprint(vizData.fingerprint);
  body.querySelectorAll("[data-ip]").forEach(el=>el.addEventListener("click",()=>{
    const ip=el.getAttribute("data-ip");
    if(isIP(ip))openDetail(ip,el.getAttribute("data-dev")||null);
  }));
}

// --- Constellation: device -> destination, laid out radially so each device
// owns an angular sector and its destinations fan out inside it.
function vizConstellation(c){
  const devs=(c&&c.devices||[]).filter(d=>d.bytes>0);
  if(!devs.length)return '<div class="vempty">No traffic in this window yet.</div>';
  const links=c.links||[];
  const byDev=new Map();
  for(const l of links){ if(!byDev.has(l.dev))byDev.set(l.dev,[]); byDev.get(l.dev).push(l); }
  const W=580,H=580,cx=W/2,cy=H/2,r1=86,r2=178;
  const maxB=Math.max(...links.map(l=>l.bytes),1);
  const total=devs.reduce((s,d)=>s+Math.max(d.bytes,1),0);
  let a0=-Math.PI/2, marks="", nodes="", labels="";
  marks+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r1+'" fill="none" class="grid" stroke-dasharray="2 4"/>';
  let di=-1;
  for(const d of devs){
    di++;
    const share=Math.max(d.bytes,1)/total;
    const span=Math.max(share*Math.PI*2,0.34);      // floor so a quiet device is still readable
    const mid=a0+span/2;
    const col=colorFor(d.ip);
    const dx=cx+Math.cos(mid)*r1, dy=cy+Math.sin(mid)*r1;
    // home -> device spoke
    marks+='<line x1="'+cx+'" y1="'+cy+'" x2="'+dx.toFixed(1)+'" y2="'+dy.toFixed(1)+
      '" stroke="'+col+'" stroke-width="1.5" opacity=".45"/>';
    const ls=(byDev.get(d.ip)||[]).slice(0,8);
    ls.forEach((l,i)=>{
      const t=ls.length===1?0.5:(i+0.5)/ls.length;
      const ang=a0+span*t;
      const ex=cx+Math.cos(ang)*r2, ey=cy+Math.sin(ang)*r2;
      const bad=!!l.threat;
      const w=Math.max(1,Math.min(1+Math.log2(1+l.bytes/1024)*0.42,7));
      const mx=cx+Math.cos((mid+ang)/2)*((r1+r2)/2);
      const my=cy+Math.sin((mid+ang)/2)*((r1+r2)/2);
      marks+='<path d="M'+dx.toFixed(1)+','+dy.toFixed(1)+' Q'+mx.toFixed(1)+','+my.toFixed(1)+
        ' '+ex.toFixed(1)+','+ey.toFixed(1)+'" fill="none" stroke="'+(bad?"#d03b3b":col)+
        '" stroke-width="'+w.toFixed(2)+'" opacity="'+(bad?".85":".4")+'"/>';
      const rad=Math.max(2.6,Math.min(2.6+Math.log2(1+l.bytes/2048)*0.7,8));
      nodes+='<circle class="hit" data-ip="'+esc(isIP(l.node)?l.node:"")+'" data-dev="'+esc(l.dev)+
        '" cx="'+ex.toFixed(1)+'" cy="'+ey.toFixed(1)+'" r="'+rad.toFixed(1)+'" fill="'+
        (bad?"#d03b3b":col)+'" stroke="var(--surface-2)" stroke-width="2"><title>'+
        esc(l.node)+"\n"+esc(fmtBytes(l.bytes))+(l.cc?" · "+esc(l.cc):"")+
        (bad?"\nON THREAT LIST":"")+'</title></circle>';
      const deg=ang*180/Math.PI, flip=(deg>90||deg<-90);
      const lr=rad+5;
      labels+='<g transform="translate('+ex.toFixed(1)+','+ey.toFixed(1)+') rotate('+
        (flip?deg+180:deg).toFixed(1)+')"><text class="mut" x="'+(flip?-lr:lr)+
        '" y="3" text-anchor="'+(flip?"end":"start")+'" style="font-size:9px">'+
        esc(shortLabel(l.node,15))+"</text></g>";
    });
    nodes+='<circle cx="'+dx.toFixed(1)+'" cy="'+dy.toFixed(1)+'" r="6" fill="'+col+
      '" stroke="var(--surface-2)" stroke-width="2"><title>'+esc(d.name)+"\n"+
      esc(fmtBytes(d.bytes))+" · "+d.ndest+' destinations</title></circle>';
    // Direct-label only the four biggest devices: past that the labels crowd
    // each other in narrow sectors. Every device is still named in the legend
    // and on hover, so identity is never carried by colour alone.
    if(di<4){
      const lr2=r1-16-(di%2)*15;
      const lx=cx+Math.cos(mid)*lr2, ly=cy+Math.sin(mid)*lr2;
      labels+='<text x="'+lx.toFixed(1)+'" y="'+ly.toFixed(1)+
        '" text-anchor="middle" style="font-size:10px;font-weight:600">'+
        esc(shortLabel(d.name,14))+"</text>";
    }
    a0+=span;
  }
  // The white dot is home; it gets no text label because device labels sit just
  // inside the ring and a centre label collides with whichever one points at it.
  nodes+='<circle cx="'+cx+'" cy="'+cy+'" r="7" fill="var(--home)"><title>your LAN</title></circle>';
  const legend=devs.map(d=>'<span><i style="background:'+colorFor(d.ip)+'"></i>'+
    esc(shortLabel(d.name,18))+"</span>").join("");
  return "<h4>Who talks to whom</h4>"+
    '<svg class="vchart" viewBox="0 0 '+W+" "+H+'" role="img" aria-label="Device to destination link graph">'+
    marks+nodes+labels+"</svg>"+
    '<div class="vlegend">'+legend+"</div>"+
    '<div class="vnote">Each spoke is a device; the dots around it are the destinations it '+
    "reached. Line thickness and dot size are data volume. Red marks a destination on a "+
    "threat list. Click a dot to open its details.</div>";
}

// --- Flow: a two-column Sankey of bytes, device -> country.
function vizFlow(f){
  const devs=(f&&f.devices||[]).filter(d=>d.bytes>0);
  const ccs=(f&&f.countries||[]).filter(c=>c.bytes>0);
  const links=(f&&f.links||[]).filter(l=>l.bytes>0);
  if(!devs.length||!ccs.length)return '<div class="vempty">No traffic in this window yet.</div>';
  const W=580,pad=8,barW=13,leftX=118,rightX=W-118-barW;
  const rows=Math.max(devs.length,ccs.length);
  const H=Math.max(220,rows*34);
  const totalL=devs.reduce((s,d)=>s+d.bytes,0)||1;
  const totalR=ccs.reduce((s,c)=>s+c.bytes,0)||1;
  const availL=H-pad*(devs.length-1), availR=H-pad*(ccs.length-1);
  const pos={},cpos={};
  let y=0;
  for(const d of devs){ const h=Math.max(6,d.bytes/totalL*availL); pos[d.ip]={y:y,h:h,cur:y}; y+=h+pad; }
  y=0;
  for(const c of ccs){ const h=Math.max(6,c.bytes/totalR*availR); cpos[c.name]={y:y,h:h,cur:y}; y+=h+pad; }
  let bars="",ribs="",labels="";
  for(const d of devs){
    const p=pos[d.ip],col=d.ip==="other"?"#6f6f68":colorFor(d.ip);
    bars+='<rect x="'+leftX+'" y="'+p.y.toFixed(1)+'" width="'+barW+'" height="'+p.h.toFixed(1)+
      '" rx="3" fill="'+col+'"><title>'+esc(d.name)+"\n"+esc(fmtBytes(d.bytes))+"</title></rect>";
    labels+='<text x="'+(leftX-8)+'" y="'+(p.y+p.h/2+3.5).toFixed(1)+'" text-anchor="end">'+
      esc(shortLabel(d.name,16))+"</text>";
  }
  for(const c of ccs){
    const p=cpos[c.name];
    bars+='<rect x="'+rightX+'" y="'+p.y.toFixed(1)+'" width="'+barW+'" height="'+p.h.toFixed(1)+
      '" rx="3" fill="#6f6f68"><title>'+esc(c.name)+"\n"+esc(fmtBytes(c.bytes))+"</title></rect>";
    labels+='<text x="'+(rightX+barW+8)+'" y="'+(p.y+p.h/2+3.5).toFixed(1)+'">'+
      esc(shortLabel(c.name,16))+"</text>";
  }
  const x0=leftX+barW,x1=rightX,mx=(x0+x1)/2;
  for(const l of links.slice(0,60)){
    const p=pos[l.dev],q=cpos[l.country];
    if(!p||!q)continue;
    const hL=Math.max(1.2,l.bytes/totalL*availL), hR=Math.max(1.2,l.bytes/totalR*availR);
    const y0=p.cur,y1=q.cur; p.cur+=hL; q.cur+=hR;
    const col=l.dev==="other"?"#6f6f68":colorFor(l.dev);
    ribs+='<path d="M'+x0+','+y0.toFixed(1)+' C'+mx+','+y0.toFixed(1)+' '+mx+','+y1.toFixed(1)+
      ' '+x1+','+y1.toFixed(1)+' L'+x1+','+(y1+hR).toFixed(1)+' C'+mx+','+(y1+hR).toFixed(1)+
      ' '+mx+','+(y0+hL).toFixed(1)+' '+x0+','+(y0+hL).toFixed(1)+' Z" fill="'+col+
      '" opacity=".34"><title>'+esc(l.dev==="other"?"other devices":devLabel(l.dev))+
      " → "+esc(l.country)+"\n"+esc(fmtBytes(l.bytes))+"</title></path>";
  }
  const legend=devs.map(d=>'<span><i style="background:'+(d.ip==="other"?"#6f6f68":colorFor(d.ip))+
    '"></i>'+esc(shortLabel(d.name,18))+"</span>").join("");
  return "<h4>Where the bytes go</h4>"+
    '<svg class="vchart" viewBox="0 0 '+W+" "+H+'" role="img" aria-label="Device to country bandwidth flow">'+
    ribs+bars+labels+"</svg>"+
    '<div class="vlegend">'+legend+"</div>"+
    '<div class="vnote">Band thickness is total bytes moved in this window. Devices on the '+
    "left, destination countries on the right.</div>";
}

// --- Weather: activity over time. Short windows get bars; long windows get a
// day x hour heatmap, which is where a routine (or a break in one) shows up.
function vizWeather(w){
  const b=(w&&w.buckets||[]);
  if(!b.length)return '<div class="vempty">No history in this window yet.</div>';
  const peak=Math.max(...b.map(x=>x.bytes),1);
  let html="<h4>When the network is busy</h4>";
  if(b.length<=48){
    const W=580,H=170,padL=52,padB=26,padT=8;
    const n=b.length,bw=(W-padL-8)/n;
    let bars="",axis="";
    b.forEach((x,i)=>{
      const h=x.bytes>0?Math.max(2,(H-padB-padT)*(Math.log2(1+x.bytes)/Math.log2(1+peak))):0;
      const bx=padL+i*bw, by=H-padB-h;
      bars+='<rect x="'+(bx+1).toFixed(1)+'" y="'+by.toFixed(1)+'" width="'+Math.max(1,bw-2).toFixed(1)+
        '" height="'+h.toFixed(1)+'" rx="'+Math.min(4,bw/3).toFixed(1)+'" fill="'+rampFor(x.bytes,peak)+
        '"><title>'+esc(hourLabel(x.ts))+"\n"+esc(fmtBytes(x.bytes))+"\n"+x.devices+
        " devices · "+x.dests+" destinations"+(x.alerts?"\n"+x.alerts+" alerts":"")+"</title></rect>";
      if(n<=12||i%Math.ceil(n/12)===0)
        axis+='<text class="mut" x="'+(bx+bw/2).toFixed(1)+'" y="'+(H-padB+13)+
          '" text-anchor="middle">'+esc(hourLabel(x.ts))+"</text>";
    });
    html+='<svg class="vchart" viewBox="0 0 '+W+" "+H+'" role="img" aria-label="Bytes per hour">'+
      '<line class="grid" x1="'+padL+'" y1="'+(H-padB)+'" x2="'+(W-8)+'" y2="'+(H-padB)+'"/>'+
      '<text class="mut" x="'+(padL-8)+'" y="'+(padT+9)+'" text-anchor="end">'+esc(fmtBytes(peak))+"</text>"+
      '<text class="mut" x="'+(padL-8)+'" y="'+(H-padB)+'" text-anchor="end">0</text>'+
      bars+axis+"</svg>";
  }else{
    // day x hour heatmap
    const days=[];
    const byDay=new Map();
    for(const x of b){
      const d=new Date(x.ts*1000), key=d.getFullYear()+"-"+d.getMonth()+"-"+d.getDate();
      if(!byDay.has(key)){ byDay.set(key,{ts:x.ts,cells:new Array(24).fill(null)}); days.push(key); }
      byDay.get(key).cells[d.getHours()]=x;
    }
    const W=580,padL=48,cell=(W-padL-8)/24,rowH=15;
    const H=days.length*rowH+34;
    let cells="",axis="";
    days.forEach((k,r)=>{
      const row=byDay.get(k);
      cells+='<text class="mut" x="'+(padL-8)+'" y="'+(28+r*rowH+11)+'" text-anchor="end">'+
        esc(dayLabel(row.ts))+"</text>";
      for(let h=0;h<24;h++){
        const x=row.cells[h];
        cells+='<rect x="'+(padL+h*cell+1).toFixed(1)+'" y="'+(28+r*rowH+1)+'" width="'+
          Math.max(1,cell-2).toFixed(1)+'" height="'+(rowH-2)+'" rx="2" fill="'+
          (x?rampFor(x.bytes,peak):"#1f2a33")+'"><title>'+esc(dayLabel(row.ts))+" "+
          String(h).padStart(2,"0")+":00\n"+(x?esc(fmtBytes(x.bytes))+"\n"+x.devices+
          " devices · "+x.dests+" destinations":"no data")+"</title></rect>";
      }
    });
    for(let h=0;h<24;h+=3)
      axis+='<text class="mut" x="'+(padL+h*cell+cell/2).toFixed(1)+'" y="20" text-anchor="middle">'+
        String(h).padStart(2,"0")+"</text>";
    html+='<svg class="vchart" viewBox="0 0 '+W+" "+H+'" role="img" aria-label="Activity heatmap by day and hour">'+
      axis+cells+"</svg>";
    const steps=RAMP.map((c,i)=>'<span><i style="background:'+c+'"></i>'+
      (i===0?"quiet":(i===RAMP.length-1?fmtBytes(peak):""))+"</span>").join("");
    html+='<div class="vlegend">'+steps+"</div>";
  }
  // Alerts get their own chart rather than a second y-axis on the one above.
  // In heatmap mode the hour columns no longer map to a linear x, so the alert
  // bars are aggregated per day to match what is actually on screen.
  if(b.some(x=>x.alerts>0)){
    const daily=b.length>48;
    let series;
    if(daily){
      const m=new Map();
      for(const x of b){
        const d=new Date(x.ts*1000), k=d.getFullYear()+"-"+d.getMonth()+"-"+d.getDate();
        if(!m.has(k))m.set(k,{ts:x.ts,alerts:0});
        m.get(k).alerts+=x.alerts;
      }
      series=[...m.values()];
    }else series=b.map(x=>({ts:x.ts,alerts:x.alerts}));
    const maxA=Math.max(...series.map(x=>x.alerts),1);
    const W=580,H=58,padL=52,padB=16,n=series.length,bw=(W-padL-8)/n;
    let ab="",ax="";
    series.forEach((x,i)=>{
      if(!x.alerts)return;
      const h=Math.max(3,(H-padB-6)*(x.alerts/maxA));
      ab+='<rect x="'+(padL+i*bw+1).toFixed(1)+'" y="'+(H-padB-h).toFixed(1)+'" width="'+
        Math.max(1.5,bw-2).toFixed(1)+'" height="'+h.toFixed(1)+'" rx="2" fill="var(--warn)"><title>'+
        esc(daily?dayLabel(x.ts):hourLabel(x.ts))+"\n"+x.alerts+" alerts</title></rect>";
    });
    const step=Math.max(1,Math.ceil(n/8));
    series.forEach((x,i)=>{
      if(i%step)return;
      ax+='<text class="mut" x="'+(padL+i*bw+bw/2).toFixed(1)+'" y="'+(H-3)+
        '" text-anchor="middle">'+esc(daily?dayLabel(x.ts):hourLabel(x.ts))+"</text>";
    });
    html+='<h4 style="margin-top:14px">Alerts '+(daily?"per day":"per hour")+"</h4>"+
      '<svg class="vchart" viewBox="0 0 '+W+" "+H+'" role="img" aria-label="Alerts over time">'+
      '<line class="grid" x1="'+padL+'" y1="'+(H-padB)+'" x2="'+(W-8)+'" y2="'+(H-padB)+'"/>'+
      '<text class="mut" x="'+(padL-8)+'" y="14" text-anchor="end">'+maxA+"</text>"+ab+ax+"</svg>";
  }
  const filled=b.filter(x=>x.bytes>0).length;
  if(filled<3)
    html+='<div class="vnote">Only '+filled+" hour"+(filled===1?"":"s")+
      " of history so far — this view gets useful once NetWatch has been running "+
      "for a day or so.</div>";
  return html+'<div class="vnote">Colour is the volume moved in that hour. A device with a '+
    "routine makes a visible pattern here — the useful part is when the pattern breaks.</div>";
}

// --- Fingerprint: what normal looks like for each device, and what broke it.
function vizFingerprint(fp){
  const devs=(fp&&fp.devices||[]);
  const devi=(fp&&fp.deviations||[]);
  if(!devs.length)
    return '<div class="vempty">No profiles learned yet.<br><br>NetWatch needs about a day of '+
      "history per device before it can say what is normal for it.</div>";
  let html="";
  if(devi.length){
    html+="<h4>Recent deviations</h4>";
    for(const d of devi.slice(0,12))
      html+='<div class="dv '+esc(d.kind)+'"><b>'+esc(d.name||d.dev)+"</b> "+esc(d.detail)+
        "<small>"+esc(ago(d.ts))+"</small></div>";
  }
  html+='<h4 style="margin-top:14px">Learned profiles</h4>';
  const nowH=new Date().getHours();
  for(const d of devs.slice(0,20)){
    const hod=(d.hod||"").padEnd(24,"0");
    let strip="";
    for(let h=0;h<24;h++)
      strip+='<i class="'+(hod[h]==="1"?"on":"")+(h===nowH?" now":"")+'" title="'+
        String(h).padStart(2,"0")+":00 "+(hod[h]==="1"?"normally active":"never active")+'"></i>';
    const ports=(d.ports||[]).slice(0,12).join(", ")||"none recorded";
    const state=d.mature?(d.hours+" h learned"):("learning · "+d.hours+" h of 24");
    html+='<div class="fpcard"><div class="fh"><b>'+esc(d.name)+"</b><small>"+
      esc(state)+"</small></div>"+
      '<div class="fpstrip">'+strip+"</div>"+
      '<div class="fpmeta">'+(d.mature
        ?("busiest hour <code>"+esc(fmtBytes(d.max_bytes))+"</code> · typical <code>"+
          esc(fmtBytes(Math.round(d.avg_bytes)))+"</code> · widest hour <code>"+
          d.max_dests+" destinations</code>")
        :"<code>no baseline yet</code> — needs a full hour of history before "+
         "there is anything to compare against")+"<br>"+
      "ports <code>"+esc(ports)+(d.nports>12?" (+"+(d.nports-12)+" more)":"")+"</code><br>"+
      "this hour <code>"+esc(fmtBytes(d.cur_bytes))+" · "+d.cur_dests+
      " destinations</code></div></div>";
  }
  return html+'<div class="vnote">The strip is the hours of the day this device is normally '+
    "awake (the outlined cell is the hour now). Deviations fire once a device has enough "+
    "history to have a normal at all.</div>";
}

document.getElementById("vizBtn").addEventListener("click",()=>{
  const opening=!vizPanel.classList.contains("open");
  vizPanel.classList.toggle("open");
  if(opening)loadViz();
});
document.getElementById("vizClose").addEventListener("click",()=>vizPanel.classList.remove("open"));
document.querySelectorAll(".vseg button").forEach(b=>b.addEventListener("click",()=>{
  document.querySelectorAll(".vseg button").forEach(x=>x.classList.toggle("on",x===b));
  vizView=b.dataset.view; renderViz();
}));
document.getElementById("vizHours").addEventListener("change",e=>{
  vizHours=+e.target.value; vizData=null; loadViz();
});

// ---- Detail drawer: everything known about one remote IP -------------------
const detailPanel=document.getElementById("detail");
let detailIP=null;
function closeDetail(){detailPanel.classList.remove("open");detailIP=null;}
document.getElementById("detailClose").addEventListener("click",closeDetail);
document.addEventListener("keydown",e=>{
  if(e.key!=="Escape")return;
  if(detailPanel.classList.contains("open"))closeDetail();
  else if(digestPanel.classList.contains("open"))digestPanel.classList.remove("open");
  else if(alertsPanel.classList.contains("open"))alertsPanel.classList.remove("open");
});
async function openDetail(ip,dev){
  if(!ip)return;
  detailIP=ip;
  document.getElementById("detailTitle").textContent=ip;
  const body=document.getElementById("detailBody");
  body.dataset.sig="";
  body.innerHTML='<div class="dt-empty">Loading&hellip;</div>';
  detailPanel.classList.add("open");
  let d;
  try{
    d=await (await fetch("/detail?ip="+encodeURIComponent(ip)
      +(dev?"&dev="+encodeURIComponent(dev):""),{cache:"no-store"})).json();
  }catch(e){
    body.innerHTML='<div class="dt-empty">Could not load details for this address.</div>';
    return;
  }
  if(detailIP!==ip)return;              // a newer click won the race
  renderDetail(d);
}
function dtRow(inner){return '<div class="dt-row">'+inner+"</div>";}
function renderDetail(d){
  const g=d.geo||{}, t=d.threat||{}, tot=d.totals||{};
  const title=(d.hosts&&d.hosts[0])||d.reverse_dns||d.ip;
  document.getElementById("detailTitle").textContent=title===d.ip?d.ip:title+" ("+d.ip+")";
  let h="";

  // Verdict first: is this thing actually bad, and according to whom?
  if(t.listed){
    h+='<div class="dt-verdict bad"><b>&#9888; On '+t.sources.length+" public blocklist"
      +(t.sources.length===1?"":"s")+"</b>"
      +t.sources.map(s=>'<p><b style="display:inline">'+esc(s.label)+"</b> &mdash; "
        +esc(s.meaning)+"</p>").join("")
      +'<p style="color:var(--text-muted)">Lists last refreshed '
      +(t.lists_refreshed?ago(t.lists_refreshed):"never")+" &middot; "
      +(t.entries||0).toLocaleString()+" entries loaded.</p></div>";
  }else{
    h+='<div class="dt-verdict ok"><b>Not on any loaded blocklist</b>'
      +'<p>This address did not match Tor exit nodes, FireHOL level 1, or Spamhaus '
      +"DROP as of the last refresh"
      +(t.lists_refreshed?" ("+ago(t.lists_refreshed)+")":"")+".</p></div>";
  }

  // Identity
  h+='<dl class="dt-kv">'
    +"<dt>Address</dt><dd class=\"dt-mono\">"+esc(d.ip)+"</dd>"
    +(d.hosts&&d.hosts.length?"<dt>Hostname(s)</dt><dd>"+d.hosts.map(esc).join("<br>")+"</dd>":"")
    +(d.reverse_dns?"<dt>Reverse DNS</dt><dd class=\"dt-mono\">"+esc(d.reverse_dns)+"</dd>":"")
    +"<dt>Location</dt><dd>"+(g.country?flag(g.countryCode)+" "+esc(g.city?g.city+", ":"")
      +esc(g.region?g.region+", ":"")+esc(g.country):"unknown / not geolocated")+"</dd>"
    +(g.isp?"<dt>ISP</dt><dd>"+esc(g.isp)+"</dd>":"")
    +(g.org&&g.org!==g.isp?"<dt>Organisation</dt><dd>"+esc(g.org)+"</dd>":"")
    +"<dt>Total traffic</dt><dd>&#8593; "+fmtBytes(tot.up||0)+" &nbsp; &#8595; "
      +fmtBytes(tot.down||0)+"</dd>"
    +(tot.first_seen?"<dt>First seen</dt><dd>"+ago(tot.first_seen)+"</dd>":"")
    +(tot.last_seen?"<dt>Last seen</dt><dd>"+ago(tot.last_seen)+"</dd>":"")
    +(d.procs&&d.procs.length?"<dt>Process</dt><dd class=\"dt-mono\">"
      +d.procs.map(esc).join("<br>")+"</dd>":"")
    +"</dl>";

  // Your own note about this destination. Saved to netwatch_notes.json, so it
  // survives restarts and shows up next to the address everywhere else.
  h+='<div class="dt-note"><label for="dtNote">Your note on '
    +esc(d.note_key||d.ip)+"</label>"
    +'<div class="dt-noterow"><input id="dtNote" type="text" maxlength="200" '
    +'placeholder="e.g. Syncthing relay — expected" value="'+esc(d.note||"")+'">'
    +'<button data-act="note">Save</button></div>'
    +'<small id="dtNoteMsg"></small></div>';

  h+='<div class="dt-actions">'
    +(g.lat!==undefined?'<button data-act="map">Show on map</button>':"")
    +'<button data-act="filter">Filter the dashboard to this</button>'
    +'<button data-act="copy">Copy address</button></div>';

  // Retained threat events for this address
  h+='<div class="section-hd"><span>Flagged contacts ('+(d.events||[]).length
    +") &middot; last "+(d.retain_h||6)+"h</span></div>";
  h+=(d.events&&d.events.length)?d.events.map(e=>dtRow(
    '<div class="top"><b>'+esc(e.dev_name||e.dev)+"</b><span class=\"sub\">"
    +ago(e.last)+"</span></div>"
    +'<div class="sub">'+(e.dir==="in"?"inbound to this device":"outbound from this device")
    +(e.ports.length?" &middot; port"+(e.ports.length>1?"s":"")+" "+e.ports.join(", "):"")
    +" &middot; first seen "+ago(e.first)+"</div>")).join("")
    :'<div class="dt-empty">No retained flagged contacts for this address.</div>';

  // Live flows right now
  h+='<div class="section-hd"><span>Live flows ('+(d.live||[]).length+")</span></div>";
  h+=(d.live&&d.live.length)?d.live.map(f=>dtRow(
    '<div class="top"><b>'+esc(f.dev_name||f.dev)+"</b><span class=\"sub\">"
    +(f.active?"active":ago(f.last))+"</span></div>"
    +'<div class="sub">'+esc(f.proto)+(f.ports.length?" :"+f.ports.join(" :"):"")
    +" &middot; &#8593; "+fmtBytes(f.up)+" &#8595; "+fmtBytes(f.down)+"</div>")).join("")
    :'<div class="dt-empty">Nothing talking to this address right now.</div>';

  // Unsolicited inbound from this address
  if(d.inbound&&d.inbound.length){
    h+='<div class="section-hd"><span>&#9888; Unsolicited inbound ('+d.inbound.length+")</span></div>";
    h+=d.inbound.map(i=>dtRow(
      '<div class="top"><b>'+esc(i.dev_name||i.dev)+"</b><span class=\"sub\">"
      +ago(i.last)+"</span></div>"
      +'<div class="sub">'+i.count+" attempt"+(i.count===1?"":"s")
      +(i.ports.length?" &middot; port"+(i.ports.length>1?"s":"")+" "+i.ports.join(", "):"")
      +"</div>")).join("");
  }

  // Per-device history over the retention window
  h+='<div class="section-hd"><span>History by device ('+(d.history||[]).length+")</span></div>";
  h+=(d.history&&d.history.length)?d.history.map(r=>dtRow(
    '<div class="top"><b>'+esc(r.dev_name||r.dev)+"</b><span class=\"sub\">"
    +ago(r.last)+"</span></div>"
    +'<div class="sub">&#8593; '+fmtBytes(r.up)+" &#8595; "+fmtBytes(r.down)
    +" &middot; first "+ago(r.first)+(r.threat?" &middot; flagged":"")+"</div>")).join("")
    :'<div class="dt-empty">No stored history for this address.</div>';

  // Alerts that named this address
  h+='<div class="section-hd"><span>Related alerts ('+(d.alerts||[]).length+")</span></div>";
  h+=(d.alerts&&d.alerts.length)?d.alerts.map(a=>
    '<div class="al '+esc(a.level)+'" style="cursor:default"><div class="k">'
    +esc(a.kind.replace(/_/g," "))+" &middot; "+ago(a.ts)+"</div>"
    +'<div class="m"><b>'+esc(a.dev_name||a.dev)+"</b> "+esc(a.msg)+"</div></div>").join("")
    :'<div class="dt-empty">No alerts recorded for this address.</div>';

  const body=document.getElementById("detailBody");
  body.innerHTML=h;
  body.dataset.sig="";
  body.querySelectorAll("[data-act]").forEach(b=>b.addEventListener("click",()=>{
    const act=b.dataset.act;
    if(act==="copy"){
      const done=()=>{b.textContent="Copied!";setTimeout(()=>{b.textContent="Copy address";},1500);};
      if(navigator.clipboard&&navigator.clipboard.writeText)
        navigator.clipboard.writeText(d.ip).then(done).catch(()=>fallbackCopy(d.ip,done,b));
      else fallbackCopy(d.ip,done,b);
    }else if(act==="filter"){
      document.getElementById("q").value=d.ip;
      setMode("live");renderList();closeDetail();
      digestPanel.classList.remove("open");alertsPanel.classList.remove("open");
    }else if(act==="map"){
      const e2=layers.get(d.ip);
      if(e2&&map){map.flyTo(e2.marker.getLatLng(),Math.max(map.getZoom(),5));
        e2.marker.openTooltip();}
      else if(map&&d.geo)map.flyTo([d.geo.lat,d.geo.lon],5);
      closeDetail();digestPanel.classList.remove("open");alertsPanel.classList.remove("open");
    }else if(act==="note"){
      const inp=document.getElementById("dtNote");
      const msg=document.getElementById("dtNoteMsg");
      b.disabled=true; msg.textContent="Saving…";
      fetch("/note",{method:"POST",headers:{"X-NetWatch":"1","Content-Type":"application/json"},
        body:JSON.stringify({key:d.note_key||d.ip,note:inp.value})})
        .then(r=>r.json()).then(j=>{
          msg.textContent=j.ok?(j.note?"Saved.":"Note cleared."):("Failed: "+(j.error||"error"));
          b.disabled=false;
        }).catch(()=>{msg.textContent="Failed to save.";b.disabled=false;});
    }
  }));
}
document.getElementById("alertList").addEventListener("click",e=>{
  const row=e.target.closest("[data-ip]");
  if(row)openDetail(row.dataset.ip,row.dataset.dev||"");
});

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

    print("NetWatch v%s starting..." % VERSION)
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
    db_init()          # create the schema once up front, not per request

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
    threading.Thread(target=notify_worker, name="notify", daemon=True).start()
    threading.Thread(target=digest_worker, name="digest", daemon=True).start()
    threading.Thread(target=notes_worker, name="notes", daemon=True).start()
    threading.Thread(target=fingerprint_worker, name="fingerprint",
                     daemon=True).start()
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
