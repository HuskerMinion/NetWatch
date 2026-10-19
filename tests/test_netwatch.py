"""Unit tests for NetWatch.

Run:  python3 -m pytest tests/        (or)   python3 tests/test_netwatch.py

These are deliberately heavy on the two areas that have regressed before —
manual device naming and inbound-record retention — plus the pure parsers and the
DB/digest layer. No network, no root, no capture: everything runs against in-memory
state or a throwaway sqlite file.
"""
import importlib.util
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Import netwatch.py as a module without running main() (guarded by __main__).
spec = importlib.util.spec_from_file_location("netwatch", os.path.join(ROOT, "netwatch.py"))
nw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nw)


def _fresh_db():
    d = tempfile.mkdtemp()
    nw.DB_FILE = os.path.join(d, "t.db")
    nw._schema_ready = False
    nw.db_init()


# --------------------------------------------------------------------------- #
# Manual device naming  (regressed once — netwatch_names.json silently ignored) #
# --------------------------------------------------------------------------- #

def test_norm_mac_accepts_any_spelling():
    for form in ("AA-BB-CC-DD-EE-FF", "aabbccddeeff", "AA:BB:CC:DD:EE:FF",
                 "aabb.ccdd.eeff"):
        assert nw._norm_mac(form) == "aa:bb:cc:dd:ee:ff"
    assert nw._norm_mac("192.168.1.5") == "192.168.1.5"   # not a MAC -> unchanged


def test_load_names_override_parses_and_skips_junk():
    d = tempfile.mkdtemp()
    nw.NAMES_FILE = os.path.join(d, "netwatch_names.json")
    with open(nw.NAMES_FILE, "w") as f:
        f.write('{"_comment":"skip","AA-BB-CC-DD-EE-FF":"Office PC",'
                '"192.168.1.50":"Garage Cam","BB:BB:BB:BB:BB:BB":"  "}')
    got = nw.load_names_override()
    assert got == {"aa:bb:cc:dd:ee:ff": "Office PC", "192.168.1.50": "Garage Cam"}


def test_override_name_prefers_mac_then_ip():
    nw.NAMES_OVERRIDE = {"aa:bb:cc:dd:ee:ff": "Office PC",
                         "192.168.1.50": "Garage Cam"}
    macs = {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}
    assert nw._override_name("192.168.1.10", macs) == "Office PC"      # by MAC
    assert nw._override_name("192.168.1.50", macs) == "Garage Cam"    # by IP
    assert nw._override_name("192.168.1.99", macs) == ""              # unknown


# --------------------------------------------------------------------------- #
# Inbound-record retention  (regressed once — dropped after 120s not 6h)        #
# --------------------------------------------------------------------------- #

def test_inbound_retained_far_longer_than_flows():
    now = time.time()
    nw.FLOWS = {}
    nw.INBOUND = {
        ("d", "recent"): {"dev": "d", "rem": "recent", "ports": {22},
                          "first": now, "last": now - 5, "count": 1},
        # 200s old: older than DROP_AFTER (120) but well under INBOUND_RETAIN (6h)
        ("d", "mid"): {"dev": "d", "rem": "mid", "ports": {22},
                       "first": now, "last": now - 200, "count": 1},
        # older than INBOUND_RETAIN -> should be dropped
        ("d", "old"): {"dev": "d", "rem": "old", "ports": {22},
                       "first": now, "last": now - nw.INBOUND_RETAIN - 10, "count": 1},
    }
    nw._prune(now)
    remaining = {k[1] for k in nw.INBOUND}
    assert "recent" in remaining
    assert "mid" in remaining, "inbound must survive past DROP_AFTER (regression!)"
    assert "old" not in remaining


def test_inbound_capped_at_max():
    now = time.time()
    nw.FLOWS = {}
    nw.INBOUND = {("d", str(i)): {"dev": "d", "rem": str(i), "ports": {22},
                                  "first": now, "last": now - i, "count": 1}
                  for i in range(nw.INBOUND_MAX + 25)}
    nw._prune(now)
    assert len(nw.INBOUND) == nw.INBOUND_MAX
    # the most-recent (smallest age) survive
    assert ("d", "0") in nw.INBOUND and ("d", str(nw.INBOUND_MAX + 24)) not in nw.INBOUND


# --------------------------------------------------------------------------- #
# DNS blocklist + digest                                                        #
# --------------------------------------------------------------------------- #

def test_bypass_label_covers_all_kinds():
    assert nw._bypass_label("plaintext-dns") == "external DNS"
    assert nw._bypass_label("dot") == "encrypted DNS/DoT"
    assert nw._bypass_label("doh") == "encrypted DNS/DoH"


def test_dns_blocklist_dedups_and_groups():
    _fresh_db()
    con = nw.db_connect()
    now = time.time()
    for _ in range(3):                      # same server 3x -> one row
        con.execute("INSERT INTO dns_targets(server,kind,first,last,hits) VALUES(?,?,?,?,1)"
                    " ON CONFLICT(server) DO UPDATE SET hits=hits+1",
                    ("8.8.8.8", "plaintext-dns", now, now))
    con.execute("INSERT INTO dns_targets VALUES('94.140.14.14','dot',?,?,1)", (now, now))
    con.execute("INSERT INTO dns_targets VALUES('dns.google','doh',?,?,1)", (now, now))
    con.commit(); con.close()
    bl = nw.dns_blocklist()
    fw = sorted(t["server"] for t in bl if t["block_at"] == "firewall")
    ph = sorted(t["server"] for t in bl if t["block_at"] == "pihole")
    assert fw == ["8.8.8.8", "94.140.14.14"]     # IPs (incl DoT) -> firewall
    assert ph == ["dns.google"]                  # hostname (DoH) -> pihole
    hits = {t["server"]: t["hits"] for t in bl}
    assert hits["8.8.8.8"] == 3                  # deduped, counted


def test_backfill_dns_targets_from_history():
    _fresh_db()
    con = nw.db_connect()
    now = time.time()
    con.execute("INSERT INTO alerts(ts,level,kind,dev,dev_name,rem,host,msg) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (now, "warning", "bypass_plaintext-dns", "d", "", "", "",
                 "device using its own external DNS (8.8.8.8), bypassing"))
    con.commit()
    nw._backfill_dns_targets(con)
    con.close()
    assert "8.8.8.8" in [t["server"] for t in nw.dns_blocklist()]


def test_digest_aggregates_in_window():
    _fresh_db()
    con = nw.db_connect()
    now = time.time()
    def s(dev, rem, up, down, last):
        con.execute("INSERT INTO sessions(dev,dev_name,rem,host,country,cc,"
                    "first,last,up,down,threat) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (dev, dev, rem, rem, "US", "US", last, last, up, down, ""))
    s("a", "x", 100, 900, now - 60)
    s("a", "x", 100, 100, now - 30)          # same dev+rem -> summed
    s("b", "y", 50, 50, now - 40 * 86400)    # outside 30d
    con.commit(); con.close()
    d1 = nw.digest_data(1)
    assert d1["devices"] == 1                 # only 'a' within 24h
    assert [t for t in d1["top_devices"] if t["name"] == "a"][0]["total"] == 1200
    assert nw.digest_data(30)["devices"] == 1  # 'b' is 40d out, still excluded


# --------------------------------------------------------------------------- #
# Bypass alert cap (per device+resolver, persistent)                            #
# --------------------------------------------------------------------------- #

def test_bypass_alert_cap_per_pair():
    nw.CONF = {}
    nw.ALERTS.clear(); nw._alert_dedup.clear()
    nw._bypass_alert_count.clear(); nw._bypass_persist_q.clear()
    for srv in ["8.8.8.8", "1.1.1.1", "9.9.9.9"]:
        nw._fire("bypass_plaintext-dns", "dev", srv, "", None, {}, False, "m " + srv)
    a = [x for x in nw.ALERTS if x["dev"] == "dev" and x["rem"] == "8.8.8.8"]
    # fire the same pair 4x: capped at 2
    for _ in range(4):
        nw._fire("bypass_plaintext-dns", "dev", "8.8.8.8", "", None, {}, False, "again")
    got = sum(1 for x in nw.ALERTS if x["dev"] == "dev" and x["rem"] == "8.8.8.8")
    assert got == 2, got


# --------------------------------------------------------------------------- #
# New-device (new MAC) alert                                                    #
# --------------------------------------------------------------------------- #

def test_new_device_alert_fires_once_per_mac():
    nw.CONF = {}
    nw.ALERTS.clear(); nw._alert_dedup.clear()
    nw.SEEN["device"].clear()
    nw._fire("device", "192.168.1.50", "aa:bb:cc:dd:ee:01", "", None, {}, False,
             "new device joined the network (MAC aa:bb:cc:dd:ee:01)")
    assert any(a["dev"] == "192.168.1.50" and a["rem"] == "aa:bb:cc:dd:ee:01"
               for a in nw.ALERTS)
    n_before = len(nw.ALERTS)
    # same MAC shows up under a different IP (DHCP lease renewal) -> no re-alert
    nw._fire("device", "192.168.1.51", "aa:bb:cc:dd:ee:01", "", None, {}, False, "again")
    assert len(nw.ALERTS) == n_before, "known MAC must not re-alert just because its IP changed"


def test_new_device_alert_suppressed_during_learning():
    nw.CONF = {}
    nw.ALERTS.clear(); nw._alert_dedup.clear()
    nw.SEEN["device"].clear()
    nw._fire("device", "192.168.1.60", "aa:bb:cc:dd:ee:02", "", None, {}, True,
             "new device joined the network (MAC aa:bb:cc:dd:ee:02)")
    assert not any(a["rem"] == "aa:bb:cc:dd:ee:02" for a in nw.ALERTS)
    # learning-window devices are baselined even though they didn't alert, so
    # they stay quiet afterward too (they were already on the network)
    nw._fire("device", "192.168.1.60", "aa:bb:cc:dd:ee:02", "", None, {}, False, "again")
    assert not any(a["rem"] == "aa:bb:cc:dd:ee:02" for a in nw.ALERTS)


def test_alert_pass_skips_devices_with_unknown_mac():
    # A device with only inbound/outbound flows but no learned MAC yet must not
    # alert -- the whole point is "new MAC", and alerting on a bare IP first would
    # either miss the real signal or double-alert once the MAC is learned a moment
    # later.
    nw.CONF = {}
    nw.ALERTS.clear(); nw._alert_dedup.clear()
    nw.SEEN["device"].clear()
    nw.DEV_MAC = {}
    now = time.time()
    nw.FLOWS = {("192.168.1.70", "8.8.8.8"): {
        "dev": "192.168.1.70", "rem": "8.8.8.8", "proto": "udp", "ports": {53},
        "first": now, "last": now, "pkts": 1, "up": 10, "down": 0, "host": ""}}
    nw.GEO = {}; nw.DEV_NAMES = {}; nw.BYPASS = {}; nw.INBOUND = {}
    nw._alert_pass(0)
    assert not any(a["kind"] == "device" for a in nw.ALERTS), \
        "must not alert on a device before its MAC is known"
    nw.DEV_MAC = {"192.168.1.70": "aa:bb:cc:dd:ee:03"}
    nw._alert_pass(0)
    assert any(a["kind"] == "device" and a["rem"] == "aa:bb:cc:dd:ee:03"
               for a in nw.ALERTS), "must alert once the MAC becomes known"


def test_digest_includes_per_kind_device_breakdown():
    # The on-screen digest lets you click an alert-kind row (e.g. "bypass doh")
    # to see which devices triggered it -- that relies on alerts_by_kind_dev.
    _fresh_db()
    con = nw.db_connect()
    now = time.time()
    def a(kind, dev, dev_name, ts):
        con.execute("INSERT INTO alerts(ts,level,kind,dev,dev_name,rem,host,msg) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (ts, "warning", kind, dev, dev_name, "", "", "m"))
    a("bypass_doh", "192.168.1.10", "TV", now - 10)
    a("bypass_doh", "192.168.1.10", "TV", now - 5)     # same (kind,dev) -> counted together
    a("bypass_dot", "192.168.1.20", "Phone", now - 8)
    a("dev_country", "192.168.1.10", "TV", now - 3)
    con.commit(); con.close()
    d = nw.digest_data(1)
    assert d["alerts_by_kind"] == {"bypass_doh": 2, "bypass_dot": 1, "dev_country": 1}
    bkd = d["alerts_by_kind_dev"]
    assert bkd["bypass_doh"] == [{"dev": "192.168.1.10", "dev_name": "TV", "count": 2}]
    assert bkd["bypass_dot"] == [{"dev": "192.168.1.20", "dev_name": "Phone", "count": 1}]


def test_dashboard_digest_alerts_are_clickable_and_merge_doh_dot():
    # Regression guard for the digest panel: DoH and DoT bypass rows must be
    # merged into a single "bypass DoH/DoT" row, and every alert-kind row must
    # be expandable (data-gi + a per-kind device list) rather than static text.
    src = open(os.path.join(ROOT, "netwatch.py")).read()
    assert 'bypass DoH/DoT' in src
    assert 'data-gi=' in src
    assert 'kinddevs' in src


def test_dot_bypass_has_distinct_dashboard_badge():
    # Regression guard: bypassBadges() in the embedded dashboard JS once only
    # special-cased "doh", silently lumping "dot" (DoT) in with plaintext DNS
    # under the generic ext-DNS badge even though the backend already treats
    # DoT as its own encrypted-DNS category (_bypass_label).
    src = open(os.path.join(ROOT, "netwatch.py")).read()
    assert '"badge2 dot"' in src, \
        "DoT bypass must render its own badge, not fall through to ext-DNS"


# --------------------------------------------------------------------------- #
# Pure parsers / classifier                                                     #
# --------------------------------------------------------------------------- #

def test_classify_directions():
    assert nw.classify("192.168.1.5", "8.8.8.8") == ("192.168.1.5", "8.8.8.8", "out")
    assert nw.classify("8.8.8.8", "192.168.1.5") == ("192.168.1.5", "8.8.8.8", "in")
    assert nw.classify("192.168.1.5", "192.168.1.6") is None   # LAN<->LAN ignored
    assert nw.classify("10.0.0.1", "notanip") is None


def test_parse_frame_ipv4_udp():
    # Ethernet(14) + IPv4(20) + UDP(8): 192.168.1.10 -> 8.8.8.8, dport 53
    eth = b"\x11\x22\x33\x44\x55\x66" b"\xaa\xbb\xcc\xdd\xee\xff" b"\x08\x00"
    ip = (b"\x45\x00\x00\x1c" b"\x00\x00\x00\x00" b"\x40\x11\x00\x00"
          + bytes([192, 168, 1, 10]) + bytes([8, 8, 8, 8]))
    udp = b"\xc0\x00\x00\x35\x00\x08\x00\x00"     # sport 49152, dport 53
    frame = eth + ip + udp
    pk = nw.parse_frame(frame, len(frame))
    assert pk and pk["src"] == "192.168.1.10" and pk["dst"] == "8.8.8.8"
    assert pk["dport"] == 53 and pk["proto"] == "udp"


# --------------------------------------------------------------------------- #
# Kernel capture filter (classic BPF) — run in a tiny interpreter, no root     #
# --------------------------------------------------------------------------- #

def _bpf_run(code, pkt):
    """Execute packed sock_filter instructions the way the kernel does."""
    import struct
    ins = [struct.unpack("HBBI", code[i:i + 8]) for i in range(0, len(code), 8)]
    a = x = pc = 0

    def load(off, size):
        if off + size > len(pkt):
            raise IndexError
        return int.from_bytes(pkt[off:off + size], "big")
    try:
        while True:
            op, jt, jf, k = ins[pc]
            pc += 1
            if op == 0x28: a = load(k, 2)
            elif op == 0x30: a = load(k, 1)
            elif op == 0x20: a = load(k, 4)
            elif op == 0x48: a = load(x + k, 2)
            elif op == 0xb1: x = (load(k, 1) & 0xf) * 4
            elif op == 0x54: a &= k
            elif op == 0x15: pc += jt if a == k else jf
            elif op == 0x45: pc += jt if a & k else jf
            elif op == 0x05: pc += k
            elif op == 0x06: return k
            else: raise AssertionError("unknown BPF op %#x" % op)
    except IndexError:
        return 0                          # the kernel drops on an out-of-range load


def _frame(src, dst, proto=17, sport=40000, dport=443, vlan=False, v6=False):
    eth = b"\x11\x22\x33\x44\x55\x66" b"\xaa\xbb\xcc\xdd\xee\xff"
    if vlan:
        eth += b"\x81\x00\x00\x0a"
    l4 = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 16
    if v6:
        return (eth + b"\x86\xdd" + b"\x60\x00\x00\x00\x00\x14" + bytes([proto, 64])
                + bytes(16) + bytes(16) + l4)
    ip = (b"\x45\x00\x00\x30" b"\x00\x00\x00\x00" + bytes([64, proto]) + b"\x00\x00"
          + bytes(int(o) for o in src.split("."))
          + bytes(int(o) for o in dst.split(".")))
    return eth + b"\x08\x00" + ip + l4


def test_kernel_filter_keeps_internet_traffic_and_drops_lan_to_lan():
    code = nw._bpf_program()
    keep = lambda f: _bpf_run(code, f) > 0
    for vlan in (False, True):
        assert keep(_frame("192.168.1.14", "142.250.72.14", 6, vlan=vlan))
        assert keep(_frame("142.250.72.14", "10.0.0.5", 6, vlan=vlan))
        assert keep(_frame("172.20.1.1", "8.8.8.8", 17, dport=53, vlan=vlan))
        assert not keep(_frame("192.168.1.71", "192.168.1.14", 6, vlan=vlan))
        assert not keep(_frame("10.1.2.3", "172.16.9.9", 17, vlan=vlan))
        assert not keep(_frame("192.168.1.5", "224.0.0.251", 17, 5353, 5353, vlan=vlan))
        assert not keep(_frame("192.168.1.5", "255.255.255.255", 17, 68, 67, vlan=vlan))
        assert not keep(_frame("169.254.1.1", "192.168.1.1", 6, vlan=vlan))
        # 172.32/12 is public, so 172.16/12 must not be over-matched
        assert keep(_frame("172.32.0.1", "192.168.1.5", 6, vlan=vlan))
        # IPv6 is passed through for the Python side to classify
        assert keep(_frame("", "", 6, v6=True, vlan=vlan))


def test_kernel_filter_keeps_lan_dns_answers_only():
    code = nw._bpf_program()
    keep = lambda f: _bpf_run(code, f) > 0
    # A Pi-hole's answer to a LAN client is how NetWatch names destinations.
    assert keep(_frame("192.168.1.155", "192.168.1.14", 17, sport=53, dport=51000))
    assert keep(_frame("192.168.1.155", "192.168.1.14", 6, sport=53, dport=51000))
    assert keep(_frame("192.168.1.155", "192.168.1.14", 17, sport=53, vlan=True))
    # The query itself, LAN to LAN, carries nothing NetWatch uses.
    assert not keep(_frame("192.168.1.14", "192.168.1.155", 17, 51000, 53))
    assert not keep(_frame("192.168.1.155", "192.168.1.14", 1, sport=53))


def test_kernel_filter_drops_frames_parse_frame_ignores():
    code = nw._bpf_program()
    arp = b"\xff" * 6 + b"\xaa" * 6 + b"\x08\x06" + b"\x00" * 28
    assert _bpf_run(code, arp) == 0
    assert _bpf_run(code, b"\x00" * 10) == 0              # runt frame


# --------------------------------------------------------------------------- #
# Dual-stack LAN: the LAN's own global IPv6 prefix and public IPv4 address     #
# --------------------------------------------------------------------------- #

LAN6 = "2001:db8:aa:1::"           # stands in for an ISP-assigned /64


def _with_lan(fn):
    def run():
        saved = (nw.LAN_V6_NETS, nw.WAN_IPS, dict(nw.DEV_MAC))
        nw.LAN_V6_NETS = (nw.ipaddress.ip_network(LAN6 + "/64"),)
        nw.WAN_IPS = {"93.184.216.34"}
        try:
            fn()
        finally:
            nw.LAN_V6_NETS, nw.WAN_IPS = saved[0], saved[1]
            nw.DEV_MAC.clear(); nw.DEV_MAC.update(saved[2])
            nw._MAC_V4["n"] = -1
    run.__name__ = fn.__name__
    return run


def _frame6(src, dst, proto=17, sport=40000, dport=443, smac=b"\xaa" * 6,
            dmac=b"\x11" * 6):
    a = nw.ipaddress.ip_address
    l4 = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + b"\x00" * 16
    return (dmac + smac + b"\x86\xdd" + b"\x60\x00\x00\x00\x00\x14"
            + bytes([proto, 64]) + a(src).packed + a(dst).packed + l4)


def _handle(frame):
    acc, dns, byp, macs, inb = {}, {}, [], {}, []
    nw._handle_packet(bytearray(frame), len(frame), acc, dns, byp, macs, inb)
    return acc, byp


@_with_lan
def test_classify_treats_the_lan_v6_prefix_as_lan():
    dev = LAN6 + "1234"
    assert nw.classify(dev, "2606:4700::1111") == (dev, "2606:4700::1111", "out")
    assert nw.classify("2606:4700::1111", dev) == (dev, "2606:4700::1111", "in")
    assert nw.classify(dev, LAN6 + "53") is None        # LAN to LAN
    assert nw.classify(dev, "fd7a:115c:a1e0::53") is None


def test_lan_v6_prefix_unknown_means_no_v6_flows():
    saved = nw.LAN_V6_NETS
    nw.LAN_V6_NETS = ()
    try:
        assert nw.classify(LAN6 + "1234", "2606:4700::1111") is None
    finally:
        nw.LAN_V6_NETS = saved


@_with_lan
def test_hairpin_to_our_own_public_address_is_not_a_flow():
    assert nw.classify("192.168.1.10", "93.184.216.34") is None
    assert nw.classify("93.184.216.34", "192.168.1.10") is None
    assert nw.classify("192.168.1.10", "93.184.216.35") is not None


@_with_lan
def test_v6_flows_fold_onto_the_v4_device_with_the_same_mac():
    nw.DEV_MAC["192.168.1.10"] = "aa:aa:aa:aa:aa:aa"
    acc, _ = _handle(_frame6(LAN6 + "1234", "2606:4700::1111", 6))
    assert ("192.168.1.10", "2606:4700::1111") in acc
    # a rotated temporary address lands on the same device
    acc, _ = _handle(_frame6(LAN6 + "beef", "2606:4700::1111", 6))
    assert ("192.168.1.10", "2606:4700::1111") in acc
    # replies arrive addressed to the device's MAC
    acc, _ = _handle(_frame6("2606:4700::1111", LAN6 + "1234", 6, 443, 50000,
                             smac=b"\x11" * 6, dmac=b"\xaa" * 6))
    assert ("192.168.1.10", "2606:4700::1111") in acc
    # an unknown MAC keeps its v6 address as the device
    acc, _ = _handle(_frame6(LAN6 + "9", "2606:4700::1111", 6, smac=b"\xbb" * 6))
    assert (LAN6 + "9", "2606:4700::1111") in acc


@_with_lan
def test_v6_dns_bypass_is_seen_but_the_lan_resolvers_are_not_flagged():
    nw.DEV_MAC["192.168.1.10"] = "aa:aa:aa:aa:aa:aa"
    _, byp = _handle(_frame6(LAN6 + "1234", "2001:4860:4860::8888", 17, 50000, 53))
    assert ("192.168.1.10", "plaintext-dns", "2001:4860:4860::8888") in byp
    _, byp = _handle(_frame6(LAN6 + "1234", "2001:4860:4860::8888", 6, 50000, 853))
    assert ("192.168.1.10", "dot", "2001:4860:4860::8888") in byp
    _, byp = _handle(_frame6(LAN6 + "1234", LAN6 + "53", 17, 50000, 53))
    assert byp == [], "a Pi-hole's own v6 address is not a bypass"


@_with_lan
def test_an_ignored_resolver_stays_ignored_over_ipv6():
    saved = set(nw.IGNORE)
    nw.IGNORE.add("192.168.1.2")
    nw.IGNORE_MAC.clear()
    try:
        # the resolver's own v4 upstream lookup teaches NetWatch its MAC ...
        acc, byp = _handle(_frame("192.168.1.2", "192.5.6.30", 17, 40000, 53))
        assert not acc and not byp
        # ... so its v6 recursive lookups are neither a flow nor a bypass
        smac = b"\xaa\xbb\xcc\xdd\xee\xff"
        acc, byp = _handle(_frame6(LAN6 + "2", "2001:503:a83e::2:30", 17, 40000,
                                   53, smac=smac))
        assert not acc and not byp, (acc, byp)
    finally:
        nw.IGNORE.clear(); nw.IGNORE.update(saved)
        nw.IGNORE_MAC.clear()


def _ra(prefixes, vlan=False):
    a = nw.ipaddress.ip_address
    opts = b""
    for pfx, plen in prefixes:
        opts += (bytes([3, 4, plen, 0xc0]) + b"\x00" * 12 + a(pfx).packed)
    icmp = bytes([134, 0, 0, 0, 64, 0, 0x07, 0x08]) + b"\x00" * 8 + opts
    eth = b"\x33\x33\x00\x00\x00\x01" + b"\xcc" * 6
    if vlan:
        eth += b"\x81\x00\x00\xc8"
    return (eth + b"\x86\xdd" + b"\x60\x00\x00\x00" + len(icmp).to_bytes(2, "big")
            + bytes([58, 255]) + a("fe80::1").packed + a("ff02::1").packed + icmp)


def test_router_advertisement_prefixes_are_parsed():
    got = nw.parse_ra_prefixes(bytearray(_ra([(LAN6, 64)])), len(_ra([(LAN6, 64)])))
    assert got == [nw.ipaddress.ip_network(LAN6 + "/64")]
    f = _ra([("2001:db8:aa:2::", 64), ("2001:db8::", 32)], vlan=True)
    got = nw.parse_ra_prefixes(bytearray(f), len(f))
    assert got == [nw.ipaddress.ip_network("2001:db8:aa:2::/64")], \
        "only /64s are learned from RAs"
    junk = _frame6(LAN6 + "1", "2606:4700::1111")
    assert nw.parse_ra_prefixes(bytearray(junk), len(junk)) == []


def test_router_advertisement_teaches_the_capture_a_prefix():
    saved = nw.LAN_V6_NETS
    nw.LAN_V6_NETS = ()
    try:
        _handle(_ra([("2600:aa:bb:3::", 64)]))
        assert nw.ipaddress.ip_network("2600:aa:bb:3::/64") in nw.LAN_V6_NETS
        _handle(_ra([("2600:aa:bb:3::", 64)]))      # a repeat adds nothing
        assert len(nw.LAN_V6_NETS) == 1
    finally:
        nw.LAN_V6_NETS = saved


def test_lan_state_survives_a_restart():
    saved = (nw.LAN_V6_NETS, set(nw.IGNORE), dict(nw.IGNORE_MAC), nw.LAN_STATE_FILE)
    nw.LAN_STATE_FILE = os.path.join(tempfile.mkdtemp(), "lan.json")
    try:
        nw.LAN_V6_NETS = (nw.ipaddress.ip_network("2600:aa:bb:4::/64"),)
        nw.IGNORE.clear(); nw.IGNORE.update({"192.168.1.2", "192.168.1.3"})
        nw.IGNORE_MAC.clear()
        nw.IGNORE_MAC.update({"aa:aa:aa:aa:aa:02": "192.168.1.2",
                              "aa:aa:aa:aa:aa:03": "192.168.1.3"})
        nw._save_lan_state()
        # restart: state empty, and one device is no longer ignored
        nw.LAN_V6_NETS = ()
        nw.IGNORE_MAC.clear()
        nw.IGNORE.discard("192.168.1.3")
        nw._load_lan_state()
        assert nw.ipaddress.ip_network("2600:aa:bb:4::/64") in nw.LAN_V6_NETS
        assert nw.IGNORE_MAC == {"aa:aa:aa:aa:aa:02": "192.168.1.2"}
    finally:
        nw.LAN_V6_NETS = saved[0]
        nw.IGNORE.clear(); nw.IGNORE.update(saved[1])
        nw.IGNORE_MAC.clear(); nw.IGNORE_MAC.update(saved[2])
        nw.LAN_STATE_FILE = saved[3]


def test_learn_v6_prefix_rejects_non_lan_ranges():
    for bad in ("fd00::/64", "2001:db8::/16", "10.0.0.0/8"):
        try:
            nw.learn_v6_prefix(nw.ipaddress.ip_network(bad), "test")
        except ValueError:
            continue
        raise AssertionError("%s should be rejected" % bad)


def test_digest_lists_threats_in_window():
    # digest_data swallows SQL errors, so a bad index hint would show up only
    # as an empty list here.
    _fresh_db()
    con = nw.db_connect()
    now = time.time()
    for dev, rem, last, th in (("a", "x", now - 60, "feodo"),
                               ("a", "x", now - 30, "feodo"),
                               ("b", "y", now - 50, ""),
                               ("c", "z", now - 40 * 86400, "feodo")):
        con.execute("INSERT INTO sessions(dev,dev_name,rem,host,country,cc,"
                    "first,last,up,down,threat) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (dev, dev, rem, rem, "US", "US", last, last, 10, 10, th))
    con.commit(); con.close()
    th = nw.digest_data(7)["threats"]
    assert [(t["dev_ip"], t["ip"], t["total"]) for t in th] == [("a", "x", 40)]


@_with_lan
def test_saved_mac_links_fold_v6_before_the_device_is_seen_on_v4():
    saved = dict(nw.MAC_V4_SAVED)
    nw.DEV_MAC.clear(); nw._MAC_V4["n"] = -1
    nw.MAC_V4_SAVED.clear()
    nw.MAC_V4_SAVED.update({"aa:aa:aa:aa:aa:aa": "192.168.1.10",
                            "cc:cc:cc:cc:cc:cc": "192.168.1.30"})
    try:
        acc, _ = _handle(_frame6(LAN6 + "1234", "2606:4700::1111", 6))
        assert ("192.168.1.10", "2606:4700::1111") in acc
        # .30 now belongs to another MAC, so the saved link is not used
        nw.DEV_MAC["192.168.1.30"] = "dd:dd:dd:dd:dd:dd"
        acc, _ = _handle(_frame6(LAN6 + "c", "2606:4700::1111", 6, smac=b"\xcc" * 6))
        assert (LAN6 + "c", "2606:4700::1111") in acc
        # a live link beats a saved one
        nw.DEV_MAC["192.168.1.11"] = "aa:aa:aa:aa:aa:aa"
        acc, _ = _handle(_frame6(LAN6 + "1234", "2606:4700::1111", 6))
        assert ("192.168.1.11", "2606:4700::1111") in acc
    finally:
        nw.MAC_V4_SAVED.clear(); nw.MAC_V4_SAVED.update(saved)


@_with_lan
def test_mac_links_survive_a_restart():
    saved = (dict(nw.MAC_V4_SAVED), nw.LAN_STATE_FILE)
    nw.LAN_STATE_FILE = os.path.join(tempfile.mkdtemp(), "lan.json")
    try:
        nw.DEV_MAC.clear(); nw._MAC_V4["n"] = -1
        nw.DEV_MAC.update({"192.168.1.10": "aa:aa:aa:aa:aa:aa",
                           "192.168.1.20": "bb:bb:bb:bb:bb:bb",
                           LAN6 + "1": "aa:aa:aa:aa:aa:aa"})
        nw.MAC_V4_SAVED.clear()
        nw.MAC_V4_SAVED.update({"cc:cc:cc:cc:cc:cc": "192.168.1.30",   # kept
                                "ee:ee:ee:ee:ee:ee": "192.168.1.20"})  # .20 moved
        nw._save_lan_state()
        with open(nw.LAN_STATE_FILE, encoding="utf-8") as f:
            st = nw.json.load(f)
        st["mac_v4"]["ff:ff:ff:ff:ff:ff"] = "8.8.8.8"          # junk is dropped
        st["mac_v4"]["11:11:11:11:11:11"] = LAN6 + "2"
        with open(nw.LAN_STATE_FILE, "w", encoding="utf-8") as f:
            nw.json.dump(st, f)
        nw.MAC_V4_SAVED.clear()
        nw._load_lan_state()
        assert nw.MAC_V4_SAVED == {"aa:aa:aa:aa:aa:aa": "192.168.1.10",
                                   "bb:bb:bb:bb:bb:bb": "192.168.1.20",
                                   "cc:cc:cc:cc:cc:cc": "192.168.1.30"}
    finally:
        nw.MAC_V4_SAVED.clear(); nw.MAC_V4_SAVED.update(saved[0])
        nw.LAN_STATE_FILE = saved[1]


def test_an_address_given_to_another_device_is_relearned():
    saved = (dict(nw.DEV_MAC), dict(nw.DEV_NAMES))
    try:
        nw.DEV_MAC.clear(); nw.DEV_NAMES.clear()
        nw.DEV_MAC["192.168.1.40"] = "aa:aa:aa:aa:aa:aa"
        nw.DEV_NAMES["192.168.1.40"] = "Smoke Alarm"
        macs = {}
        frame = _frame("192.168.1.40", "93.184.216.35", 6, 50000, 443)
        nw._handle_packet(bytearray(frame), len(frame), {}, {}, [], macs, [])
        assert macs == {"192.168.1.40": "aa:bb:cc:dd:ee:ff"}
        nw._learn_macs(macs)
        assert nw.DEV_MAC["192.168.1.40"] == "aa:bb:cc:dd:ee:ff"
        assert "192.168.1.40" not in nw.DEV_NAMES, "old device's name is dropped"
        # the same MAC again is not re-reported
        macs = {}
        nw._handle_packet(bytearray(frame), len(frame), {}, {}, [], macs, [])
        assert macs == {}
    finally:
        nw.DEV_MAC.clear(); nw.DEV_MAC.update(saved[0])
        nw.DEV_NAMES.clear(); nw.DEV_NAMES.update(saved[1])
        nw._MAC_V4["n"] = -1


def test_viz_names_use_the_current_device_not_an_old_label():
    _fresh_db()
    saved = (dict(nw.DEV_MAC), dict(nw.DEV_NAMES))
    con = nw.db_connect()
    now = time.time()
    for name, last in (("Nest Labs Inc.", now - 7200), ("", now - 60)):
        con.execute("INSERT INTO sessions(dev,dev_name,rem,host,country,cc,"
                    "first,last,up,down,threat) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("192.168.1.31", name, "93.184.216.35", "", "US", "US",
                     last, last, 10, 10, ""))
    con.execute("INSERT INTO deviations(ts,dev,kind,detail,value,baseline) "
                "VALUES(?,?,?,?,?,?)", (now, "192.168.1.31", "volume", "x", 1, 1))
    con.commit(); con.close()
    try:
        nw.DEV_MAC.clear(); nw.DEV_NAMES.clear()
        name = lambda: nw.viz_data(24)["fingerprint"]["deviations"][0]["name"]
        assert name() == "192.168.1.31", "the newest session has no label"
        nw.DEV_NAMES["192.168.1.31"] = "Phone"
        assert name() == "Phone", "the live name wins"
    finally:
        nw.DEV_MAC.clear(); nw.DEV_MAC.update(saved[0])
        nw.DEV_NAMES.clear(); nw.DEV_NAMES.update(saved[1])


def test_an_unlinked_ipv6_address_gets_no_new_country_alerts():
    nw.CONF = {}
    nw.ALERTS.clear(); nw._alert_dedup.clear()
    nw.SEEN["dev_country"].clear()
    now = time.time()
    v6 = "2600:aa:bb:3::77"
    nw.FLOWS = {(d, "93.184.216.35"): {
        "dev": d, "rem": "93.184.216.35", "proto": "tcp", "ports": {443},
        "first": now, "last": now, "pkts": 1, "up": 10, "down": 0, "host": ""}
        for d in (v6, "192.168.1.70")}
    nw.GEO = {"93.184.216.35": {"status": "ok", "countryCode": "CA",
                                "country": "Canada"}}
    nw.DEV_NAMES = {}; nw.BYPASS = {}; nw.INBOUND = {}
    nw._alert_pass(0)
    got = [a["dev"] for a in nw.ALERTS if a["kind"] == "dev_country"]
    assert got == ["192.168.1.70"], got


if __name__ == "__main__":
    fns = sorted(n for n in globals() if n.startswith("test_"))
    passed = 0
    for n in fns:
        globals()[n]()
        print("PASS", n)
        passed += 1
    print("\n%d/%d tests passed" % (passed, len(fns)))
