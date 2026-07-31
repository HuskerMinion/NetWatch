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
        f.write('{"_comment":"skip","AA-BB-CC-DD-EE-FF":"Starlord",'
                '"192.168.34.50":"Garage Cam","BB:BB:BB:BB:BB:BB":"  "}')
    got = nw.load_names_override()
    assert got == {"aa:bb:cc:dd:ee:ff": "Starlord", "192.168.34.50": "Garage Cam"}


def test_override_name_prefers_mac_then_ip():
    nw.NAMES_OVERRIDE = {"aa:bb:cc:dd:ee:ff": "Starlord",
                         "192.168.34.50": "Garage Cam"}
    macs = {"192.168.34.10": "aa:bb:cc:dd:ee:ff"}
    assert nw._override_name("192.168.34.10", macs) == "Starlord"      # by MAC
    assert nw._override_name("192.168.34.50", macs) == "Garage Cam"    # by IP
    assert nw._override_name("192.168.34.99", macs) == ""              # unknown


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


if __name__ == "__main__":
    fns = sorted(n for n in globals() if n.startswith("test_"))
    passed = 0
    for n in fns:
        globals()[n]()
        print("PASS", n)
        passed += 1
    print("\n%d/%d tests passed" % (passed, len(fns)))
