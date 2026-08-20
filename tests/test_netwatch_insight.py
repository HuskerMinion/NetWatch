"""Unit tests for the v2026.08.20 insight features.

Covers the four things added on top of the flow map:

  * destination notes      — annotate an IP / hostname / domain suffix
  * process attribution    — the optional per-PC agent's socket->process table
  * IPv6 leak detection    — v6 is meant to be off on this network
  * device fingerprinting  — learned per-device baseline + deviation detection

Run:  python3 -m pytest tests/     (or)   python3 tests/test_netwatch_insight.py

No network, no root, no capture: everything runs against in-memory state or a
throwaway sqlite file.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

spec = importlib.util.spec_from_file_location("netwatch", os.path.join(ROOT, "netwatch.py"))
nw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nw)


def _fresh_db():
    d = tempfile.mkdtemp()
    nw.DB_FILE = os.path.join(d, "t.db")
    nw._schema_ready = False
    nw.db_init()
    return d


def _reset():
    nw.FLOWS.clear()
    nw.INBOUND.clear()
    nw.THREAT_HITS.clear()
    nw.IPV6.clear()
    nw.PROCS.clear()
    nw.AGENTS.clear()
    nw.NOTES.clear()
    nw.PROFILE.clear()
    del nw.DEVIATIONS[:]
    del nw.ALERTS[:]
    nw._alert_dedup.clear()


# --------------------------------------------------------------------------- #
# Destination notes                                                           #
# --------------------------------------------------------------------------- #

def test_note_key_accepts_ips_hosts_and_suffixes():
    assert nw._note_key("8.8.8.8") == "8.8.8.8"
    assert nw._note_key("  Example.COM. ") == "example.com"
    assert nw._note_key("*.amazonaws.com") == "*.amazonaws.com"
    # junk is rejected rather than silently stored under a nonsense key
    assert nw._note_key("not a key!") == ""
    assert nw._note_key("") == ""
    assert nw._note_key("x" * 300) == ""


def test_note_lookup_prefers_ip_then_host_then_longest_suffix():
    notes = {"1.2.3.4": "by ip", "media.example.com": "by host",
             "*.example.com": "short suffix",
             "*.cdn.example.com": "long suffix"}
    assert nw.note_for("1.2.3.4", "media.example.com", notes) == "by ip"
    assert nw.note_for("9.9.9.9", "media.example.com", notes) == "by host"
    # the more specific suffix rule wins over the shorter one
    assert nw.note_for("9.9.9.9", "edge.cdn.example.com", notes) == "long suffix"
    assert nw.note_for("9.9.9.9", "other.example.com", notes) == "short suffix"
    assert nw.note_for("9.9.9.9", "nothing.invalid", notes) == ""


def test_suffix_rule_matches_the_bare_domain_too():
    # "*.example.com" should cover example.com itself — otherwise every note
    # needs writing twice.
    assert nw.note_for("9.9.9.9", "example.com", {"*.example.com": "n"}) == "n"


def test_save_note_round_trips_and_delete_clears_it():
    d = tempfile.mkdtemp()
    nw.NOTES_FILE = os.path.join(d, "notes.json")
    _reset()
    nw.save_note("8.8.8.8", "  Google DNS  ")
    assert nw.NOTES["8.8.8.8"] == "Google DNS"        # trimmed
    with open(nw.NOTES_FILE) as fh:
        assert json.load(fh)["8.8.8.8"] == "Google DNS"
    nw.save_note("8.8.8.8", "")                       # empty text deletes
    assert "8.8.8.8" not in nw.NOTES
    with open(nw.NOTES_FILE) as fh:
        assert "8.8.8.8" not in json.load(fh)


def test_save_note_rejects_a_bad_key():
    d = tempfile.mkdtemp()
    nw.NOTES_FILE = os.path.join(d, "notes.json")
    try:
        nw.save_note("!!! nope !!!", "x")
    except ValueError:
        return
    raise AssertionError("a malformed key should be refused, not written")


def test_load_notes_skips_comments_and_blanks():
    d = tempfile.mkdtemp()
    nw.NOTES_FILE = os.path.join(d, "notes.json")
    with open(nw.NOTES_FILE, "w") as fh:
        json.dump({"_comment": "ignore me", "8.8.8.8": "ok",
                   "1.1.1.1": "   ", "9.9.9.9": 42}, fh)
    loaded = nw.load_notes()
    assert loaded == {"8.8.8.8": "ok"}


def test_notes_reach_the_dashboard_snapshot():
    _reset()
    nw.NOTES["203.0.113.7"] = "known good"
    nw._record("192.168.1.10", "203.0.113.7", "tcp", 443, up=10, down=20)
    snap = nw.snapshot()
    dest = [d for d in snap["dests"] if d["ip"] == "203.0.113.7"][0]
    assert dest["note"] == "known good"
    assert snap["stats"]["notes"] == 1


# --------------------------------------------------------------------------- #
# Process attribution (per-PC agent)                                          #
# --------------------------------------------------------------------------- #

def test_agent_ingest_keeps_public_destinations_only():
    _reset()
    n = nw.agent_ingest("192.168.1.10", {"host": "deskpc", "os": "Windows", "conns": [
        {"rem": "140.82.121.4", "port": 443, "proc": "chrome.exe", "pid": 42},
        {"rem": "192.168.1.9", "port": 445, "proc": "explorer.exe", "pid": 7},
        {"rem": "", "port": 80, "proc": "nothing"},
    ]})
    assert n == 1, "only the public destination should be recorded"
    assert nw.PROCS[("192.168.1.10", "140.82.121.4", 443)]["proc"] == "chrome.exe"
    assert nw.AGENTS["192.168.1.10"]["host"] == "deskpc"


def test_proc_for_matches_by_port_then_by_pair():
    _reset()
    nw.agent_ingest("192.168.1.10", {"conns": [
        {"rem": "140.82.121.4", "port": 443, "proc": "chrome.exe", "pid": 1}]})
    assert nw.proc_for("192.168.1.10", "140.82.121.4", [443]) == "chrome.exe"
    # a flow whose port set didn't line up still resolves via the pair
    assert nw.proc_for("192.168.1.10", "140.82.121.4", [8443]) == "chrome.exe"
    # a different device never inherits another machine's process names
    assert nw.proc_for("192.168.1.99", "140.82.121.4", [443]) == ""


def test_stale_agent_data_is_pruned_and_never_served():
    _reset()
    nw.agent_ingest("192.168.1.10", {"conns": [
        {"rem": "140.82.121.4", "port": 443, "proc": "chrome.exe", "pid": 1}]})
    old = time.time() - nw.AGENT_TTL - 60
    nw.PROCS[("192.168.1.10", "140.82.121.4", 443)]["ts"] = old
    nw.AGENTS["192.168.1.10"]["last"] = old
    assert nw.proc_for("192.168.1.10", "140.82.121.4", [443]) == ""
    nw._prune_procs(time.time())
    assert not nw.PROCS and not nw.AGENTS


def test_process_name_lands_on_the_destination_in_the_snapshot():
    _reset()
    nw._record("192.168.1.10", "140.82.121.4", "tcp", 443, up=100, down=200)
    nw.agent_ingest("192.168.1.10", {"host": "deskpc", "conns": [
        {"rem": "140.82.121.4", "port": 443, "proc": "chrome.exe", "pid": 1}]})
    snap = nw.snapshot()
    dest = [d for d in snap["dests"] if d["ip"] == "140.82.121.4"][0]
    assert dest["procs"] == ["chrome.exe"]
    dev = [d for d in snap["devices"] if d["ip"] == "192.168.1.10"][0]
    assert dev["agent"] == "deskpc"
    assert snap["stats"]["agents"] == 1


def test_agent_mappings_are_capped():
    _reset()
    saved = nw.AGENT_MAX
    nw.AGENT_MAX = 10
    try:
        nw.agent_ingest("192.168.1.10", {"conns": [
            {"rem": "140.82.121.%d" % (i % 250), "port": 1000 + i,
             "proc": "p%d" % i, "pid": i} for i in range(1, 60)]})
        assert len(nw.PROCS) <= 10
    finally:
        nw.AGENT_MAX = saved


# --------------------------------------------------------------------------- #
# IPv6 leak detection                                                         #
# --------------------------------------------------------------------------- #

def test_v6_prefix_groups_addresses_by_64():
    a = nw.v6_prefix("2606:4700:4700::1111")
    b = nw.v6_prefix("2606:4700:4700::9999")
    assert a == b, "two addresses in one /64 must share a prefix key"
    assert nw.v6_prefix("2001:db8:1:2::5") != a
    assert nw.v6_prefix("not-an-address") == "not-an-address"


def test_ipv6_flow_alerts_once_per_prefix_and_shows_on_the_device():
    _reset()
    nw.CONF = {"alert_ipv6": True}
    nw._record("192.168.1.10", "2606:4700:4700::1111", "tcp", 443, up=1, down=1)
    nw._record("192.168.1.10", "2606:4700:4700::9999", "tcp", 443, up=1, down=1)
    nw._alert_pass(warmup=0)
    v6 = [a for a in nw.ALERTS if a["kind"] == "ipv6"]
    assert len(v6) == 1, "both addresses share a /64, so one alert: %r" % v6
    assert "IPv6" in v6[0]["msg"]
    assert nw.IPV6["192.168.1.10"]["count"] == 2
    snap = nw.snapshot()
    dev = [d for d in snap["devices"] if d["ip"] == "192.168.1.10"][0]
    assert dev["ipv6"] == 2
    assert snap["stats"]["ipv6"] == 1


def test_ipv6_detection_can_be_switched_off():
    _reset()
    nw.CONF = {"alert_ipv6": False}
    nw._record("192.168.1.10", "2606:4700:4700::1111", "tcp", 443, up=1, down=1)
    nw._alert_pass(warmup=0)
    assert not [a for a in nw.ALERTS if a["kind"] == "ipv6"]
    nw.CONF = {}


def test_ipv4_traffic_never_trips_the_v6_alert():
    _reset()
    nw.CONF = {"alert_ipv6": True}
    nw._record("192.168.1.10", "203.0.113.5", "tcp", 443, up=1, down=1)
    nw._alert_pass(warmup=0)
    assert not [a for a in nw.ALERTS if a["kind"] == "ipv6"]
    nw.CONF = {}


# --------------------------------------------------------------------------- #
# Device fingerprint / deviation detection                                    #
# --------------------------------------------------------------------------- #

def _seed_hours(con, dev, hours, bytes_each, dests_each, end_hour):
    """Give a device `hours` completed hours of boring, consistent history."""
    for i in range(hours):
        con.execute("INSERT OR REPLACE INTO dev_hourly(dev,hour,bytes,dests,flows)"
                    " VALUES(?,?,?,?,?)",
                    (dev, end_hour - 1 - i, bytes_each, dests_each, 3))
    con.commit()


def test_no_deviation_before_a_device_has_a_baseline():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    # only a couple of hours of history: not mature, so a spike says nothing yet
    _seed_hours(con, "192.168.1.10", 2, 1000, 2, cur)
    con.execute("INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) VALUES(?,?,?,?,?)",
                ("192.168.1.10", cur, 500 * 1024 * 1024, 400, 9))
    con.commit()
    found = nw.profile_pass(con, now)
    assert not found, "an immature device must not raise deviations: %r" % found
    con.close()


def test_volume_spike_is_flagged_once_the_device_is_mature():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.20", nw.PROFILE_MIN_HOURS + 5, 2 * 1024 * 1024, 4, cur)
    con.execute("INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) VALUES(?,?,?,?,?)",
                ("192.168.1.20", cur, 500 * 1024 * 1024, 4, 9))
    con.commit()
    kinds = [d["kind"] for d in nw.profile_pass(con, now)]
    assert "volume" in kinds, kinds
    con.close()


def test_a_normal_hour_is_not_flagged():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.21", nw.PROFILE_MIN_HOURS + 5, 20 * 1024 * 1024, 6, cur)
    con.execute("INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) VALUES(?,?,?,?,?)",
                ("192.168.1.21", cur, 21 * 1024 * 1024, 7, 4))
    con.commit()
    assert not nw.profile_pass(con, now)
    con.close()


def test_destination_fanout_is_flagged():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.22", nw.PROFILE_MIN_HOURS + 5, 50 * 1024 * 1024, 5, cur)
    # same volume as always, but suddenly reaching hundreds of hosts
    con.execute("INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) VALUES(?,?,?,?,?)",
                ("192.168.1.22", cur, 50 * 1024 * 1024, 400, 400))
    con.commit()
    kinds = [d["kind"] for d in nw.profile_pass(con, now)]
    assert "dests" in kinds, kinds
    con.close()


def test_a_brand_new_port_is_reported_exactly_once():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.23", nw.PROFILE_MIN_HOURS + 5, 1024, 2, cur)
    con.execute("INSERT INTO sessions(dev,rem,first,last,up,down,ports) "
                "VALUES(?,?,?,?,?,?,?)",
                ("192.168.1.23", "203.0.113.9", now - 30, now - 10, 10, 10, "4444"))
    con.commit()
    first = [d["kind"] for d in nw.profile_pass(con, now)]
    assert "port" in first, first
    # the port is learned during that pass, so a second pass stays quiet
    second = [d["kind"] for d in nw.profile_pass(con, now)]
    assert "port" not in second, second
    con.close()


def test_profile_is_persisted_and_exposed_to_the_viz_endpoint():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.24", nw.PROFILE_MIN_HOURS + 2, 3 * 1024 * 1024, 5, cur)
    nw.profile_pass(con, now)
    row = con.execute("SELECT hours, hod, max_bytes FROM dev_profile "
                      "WHERE dev=?", ("192.168.1.24",)).fetchone()
    assert row and row[0] >= nw.PROFILE_MIN_HOURS
    assert len(row[1]) == 24 and "1" in row[1], "hour-of-day bitmap should be learned"
    con.close()
    viz = nw.viz_data(48)
    devs = {d["ip"]: d for d in viz["fingerprint"]["devices"]}
    assert "192.168.1.24" in devs
    assert devs["192.168.1.24"]["mature"] is True
    assert len(devs["192.168.1.24"]["hod"]) == 24


def test_deviations_are_recorded_for_the_ui():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    cur = int(now // 3600)
    _seed_hours(con, "192.168.1.25", nw.PROFILE_MIN_HOURS + 5, 1024 * 1024, 3, cur)
    con.execute("INSERT INTO dev_hourly(dev,hour,bytes,dests,flows) VALUES(?,?,?,?,?)",
                ("192.168.1.25", cur, 900 * 1024 * 1024, 3, 9))
    con.commit()
    nw.profile_pass(con, now)
    con.close()
    viz = nw.viz_data(24)
    assert any(d["dev"] == "192.168.1.25" for d in viz["fingerprint"]["deviations"])
    assert nw.DEVIATIONS, "deviations should also be held in memory for the panel"


# --------------------------------------------------------------------------- #
# Visualization aggregates                                                    #
# --------------------------------------------------------------------------- #

def test_viz_data_shapes_all_four_views():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    for i, (dev, country, b) in enumerate([
            ("192.168.1.10", "United States", 5000),
            ("192.168.1.10", "Ireland", 2000),
            ("192.168.1.11", "United States", 900)]):
        con.execute("INSERT INTO sessions(dev,dev_name,rem,host,country,cc,first,"
                    "last,up,down,threat,ports) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (dev, "pc%d" % i, "203.0.113.%d" % (i + 1), "h%d.example.com" % i,
                     country, "US", now - 600, now - 10, b, b, "", "443"))
    con.commit()
    con.close()
    v = nw.viz_data(24)
    assert v.get("error") is None, v.get("error")
    assert len(v["constellation"]["devices"]) == 2
    assert v["constellation"]["links"], "each device should carry its destinations"
    assert {c["name"] for c in v["flow"]["countries"]} == {"United States", "Ireland"}
    assert sum(l["bytes"] for l in v["flow"]["links"]) == 2 * (5000 + 2000 + 900)
    assert len(v["weather"]["buckets"]) >= 24
    assert v["weather"]["peak"] > 0


def test_viz_window_is_respected():
    _fresh_db()
    _reset()
    con = nw.db_connect()
    now = time.time()
    con.execute("INSERT INTO sessions(dev,rem,country,first,last,up,down) "
                "VALUES(?,?,?,?,?,?,?)",
                ("192.168.1.10", "203.0.113.1", "Chad", now - 5 * 86400,
                 now - 5 * 86400, 10, 10))
    con.commit()
    con.close()
    assert not nw.viz_data(24)["constellation"]["devices"], \
        "a 5-day-old session must not appear in a 24-hour window"
    assert nw.viz_data(24 * 7)["constellation"]["devices"], \
        "...but should appear in a 7-day window"


# --------------------------------------------------------------------------- #
# Hourly rollup (the input the whole profile depends on)                      #
# --------------------------------------------------------------------------- #

def test_rollup_counts_byte_deltas_not_running_totals():
    _reset()
    nw._flow_bytes.clear()
    nw._hour_dests["hour"] = 0
    now = time.time()
    # session row layout matches what db_worker builds: (dev,name,rem,host,
    # country,cc,first,last,up,down,threat,ports)
    row = ["192.168.1.10", "pc", "203.0.113.5", "", "", "", now - 100, now,
           1000, 500, "", "443"]
    _, out = nw._rollup_hourly([row], now)
    assert out[0][2] == 1500, "first sighting counts the whole total"
    row[8], row[9] = 1200, 700          # the same flow grew by 400 bytes
    _, out = nw._rollup_hourly([row], now)
    assert out[0][2] == 400, "a growing flow must contribute only its delta"


def test_rollup_forgets_flows_that_have_gone_away():
    _reset()
    nw._flow_bytes.clear()
    now = time.time()
    row = ["192.168.1.10", "pc", "203.0.113.5", "", "", "", now, now,
           100, 100, "", "443"]
    nw._rollup_hourly([row], now)
    assert nw._flow_bytes
    nw._rollup_hourly([], now)
    assert not nw._flow_bytes, "dropped flows must not leak into the delta map"


if __name__ == "__main__":
    fns = sorted(n for n in globals() if n.startswith("test_"))
    passed = 0
    for n in fns:
        globals()[n]()
        print("PASS", n)
        passed += 1
    print("\n%d/%d tests passed" % (passed, len(fns)))
