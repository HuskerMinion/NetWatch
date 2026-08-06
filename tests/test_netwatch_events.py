#!/usr/bin/env python3
"""Tests for NetWatch's security-EVENT model (flagged + inbound retention),
blocklist attribution, and the /detail aggregation.

The behaviour under test is the fix for "the flagged box at the top resets too
quickly": a threat-list hit must stay on the counter for the full retention
window (the same one inbound uses), not disappear when the flow ages out of the
live table after DROP_AFTER seconds.

No root, no network, no capture needed. Run either of:
    python3 -m pytest tests/
    python3 tests/test_netwatch_events.py
"""

import ipaddress
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netwatch as nw  # noqa: E402


def reset_state():
    """Blank every module global the tests touch, so ordering can't matter."""
    nw.FLOWS.clear()
    nw.INBOUND.clear()
    nw.THREAT_HITS.clear()
    nw.ALERTS.clear()
    nw.GEO.clear()
    nw.DEV_NAMES.clear()
    nw.DEV_MAC.clear()
    nw.IPDOMAIN.clear()
    nw.BYPASS.clear()
    del nw._alert_persist_q[:]
    del nw._notify_q[:]
    nw._alert_dedup.clear()
    nw._threat_verdict.clear()
    nw._threat_verdict_gen = -1
    nw.THREAT["exact"] = {}
    nw.THREAT["nets"] = []
    nw.THREAT["loaded"] = 0
    nw.THREAT["ts"] = 0
    nw.THREAT["gen"] += 1


def listed(ip, sources="spamhaus"):
    """Put `ip` on the blocklist and invalidate the verdict memo."""
    nw.THREAT["exact"][ip] = sources
    nw.THREAT["loaded"] = len(nw.THREAT["exact"]) + len(nw.THREAT["nets"])
    nw.THREAT["ts"] = time.time()
    nw.THREAT["gen"] += 1


class ThreatAttribution(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_clean_ip_is_none(self):
        listed("5.5.5.5")
        self.assertIsNone(nw.threat_match("8.8.8.8"))

    def test_single_source_is_named(self):
        listed("5.5.5.5", "tor")
        self.assertEqual(nw.threat_match("5.5.5.5"), "tor")
        self.assertEqual([s["label"] for s in nw.threat_sources("5.5.5.5")],
                         ["Tor exit node"])

    def test_multiple_sources_are_all_kept(self):
        listed("5.5.5.5", "spamhaus,tor")
        self.assertEqual(nw.threat_match("5.5.5.5"), "spamhaus,tor")
        labels = sorted(s["label"] for s in nw.threat_sources("5.5.5.5"))
        self.assertEqual(labels, ["Spamhaus DROP", "Tor exit node"])

    def test_cidr_match_carries_its_source(self):
        nw.THREAT["nets"] = [(ipaddress.ip_network("203.0.113.0/24"), "firehol")]
        nw.THREAT["loaded"] = 1
        nw.THREAT["gen"] += 1
        self.assertEqual(nw.threat_match("203.0.113.9"), "firehol")

    def test_ipv6_against_ipv4_netlist_does_not_explode(self):
        nw.THREAT["nets"] = [(ipaddress.ip_network("203.0.113.0/24"), "firehol")]
        nw.THREAT["loaded"] = 1
        nw.THREAT["gen"] += 1
        self.assertIsNone(nw.threat_match("2606:4700::1111"))

    def test_parse_netset_tags_every_entry(self):
        exact, nets = nw._parse_netset("1.2.3.4\n# comment\n10.0.0.0/8\n", "tor")
        self.assertEqual(exact, {"1.2.3.4": "tor"})
        self.assertEqual([s for _, s in nets], ["tor"])

    def test_verdict_is_not_cached_before_the_lists_load(self):
        """The bug: an IP checked during the seconds before the blocklists finish
        downloading used to be memoised as clean FOREVER — a silent false
        negative on every restart."""
        self.assertIsNone(nw.threat_match("6.6.6.6"))   # lists still empty
        listed("6.6.6.6", "spamhaus")                   # download completes
        self.assertEqual(nw.threat_match("6.6.6.6"), "spamhaus")

    def test_verdict_memo_is_invalidated_when_lists_reload(self):
        listed("6.6.6.6", "spamhaus")
        self.assertEqual(nw.threat_match("6.6.6.6"), "spamhaus")
        nw.THREAT["exact"] = {"6.6.6.6": "tor"}         # refreshed lists
        nw.THREAT["gen"] += 1
        self.assertEqual(nw.threat_match("6.6.6.6"), "tor")


class FlaggedRetention(unittest.TestCase):
    """The user-reported bug and its fix."""

    def setUp(self):
        reset_state()

    def test_flagged_survives_the_flow_being_dropped(self):
        listed("77.88.8.8", "spamhaus")
        nw._record("192.168.1.44", "77.88.8.8", "tcp", 443, up=100, down=900)
        nw._alert_pass(warmup=0)
        self.assertEqual(nw.snapshot()["stats"]["flagged"], 1)

        # Age the flow well past DROP_AFTER and prune: the live flow goes away...
        for f in nw.FLOWS.values():
            f["last"] -= nw.DROP_AFTER + 60
        nw._prune(time.time())
        self.assertEqual(len(nw.FLOWS), 0)

        # ...but the flagged EVENT (and therefore the header tile) remains.
        snap = nw.snapshot()
        self.assertEqual(snap["stats"]["flagged"], 1,
                         "flagged must not reset when the flow ages out")
        self.assertEqual(len(snap["flagged_events"]), 1)
        self.assertEqual(snap["flagged_events"][0]["list_labels"],
                         ["Spamhaus DROP"])

    def test_flagged_and_inbound_share_one_retention_window(self):
        self.assertEqual(nw.INBOUND_RETAIN, nw.EVENT_RETAIN)
        listed("185.220.101.5", "tor")
        nw._record_inbound("192.168.1.20", "185.220.101.5", 22)
        nw._alert_pass(warmup=0)
        snap = nw.snapshot()
        self.assertEqual(snap["stats"]["inbound"], 1)
        self.assertEqual(snap["stats"]["flagged"], 1)

        # Just inside the window: both still counted.
        inside = nw.EVENT_RETAIN - 30
        for store in (nw.INBOUND, nw.THREAT_HITS):
            for v in store.values():
                v["last"] -= inside
        nw._prune(time.time())
        snap = nw.snapshot()
        self.assertEqual(snap["stats"]["inbound"], 1)
        self.assertEqual(snap["stats"]["flagged"], 1)

        # Past the window: they expire together, never flagged first.
        for store in (nw.INBOUND, nw.THREAT_HITS):
            for v in store.values():
                v["last"] -= 120
        nw._prune(time.time())
        snap = nw.snapshot()
        self.assertEqual(snap["stats"]["inbound"], 0)
        self.assertEqual(snap["stats"]["flagged"], 0)

    def test_inbound_from_a_listed_ip_counts_as_flagged(self):
        listed("185.220.101.5", "tor")
        nw._record_inbound("192.168.1.20", "185.220.101.5", 22)
        nw._alert_pass(warmup=0)
        dirs = {e["dir"] for e in nw.snapshot()["flagged_events"]}
        self.assertEqual(dirs, {"in"})

    def test_flagged_counts_distinct_ips_not_flows(self):
        listed("77.88.8.8", "spamhaus")
        for dev in ("192.168.1.10", "192.168.1.11", "192.168.1.12"):
            nw._record(dev, "77.88.8.8", "tcp", 443, up=10, down=10)
        nw._alert_pass(warmup=0)
        snap = nw.snapshot()
        self.assertEqual(snap["stats"]["flagged"], 1)        # one bad address
        self.assertEqual(len(snap["flagged_events"]), 3)     # three devices hit it

    def test_repeated_passes_do_not_inflate_the_count(self):
        listed("77.88.8.8", "spamhaus")
        nw._record("192.168.1.44", "77.88.8.8", "tcp", 443)
        for _ in range(5):
            nw._alert_pass(warmup=0)
        self.assertEqual(len(nw.THREAT_HITS), 1)
        self.assertEqual(nw.snapshot()["stats"]["flagged"], 1)

    def test_event_store_is_capped(self):
        for i in range(nw.THREAT_HIT_MAX + 25):
            nw._record_threat_hit("192.168.1.%d" % (i % 250), "9.9.9.%d" % (i % 250),
                                  "out", "tor", ts=time.time() + i)
        nw._prune(time.time() + nw.THREAT_HIT_MAX + 100)
        self.assertLessEqual(len(nw.THREAT_HITS), nw.THREAT_HIT_MAX)

    def test_snapshot_exposes_the_window_to_the_ui(self):
        self.assertEqual(nw.snapshot()["stats"]["event_retain_h"],
                         round(nw.EVENT_RETAIN / 3600.0, 1))


class EventPersistence(unittest.TestCase):
    """Events must survive a service restart, like their alerts do."""

    def setUp(self):
        reset_state()
        self.tmp = tempfile.mkdtemp()
        self._db = nw.DB_FILE
        nw.DB_FILE = os.path.join(self.tmp, "t.db")
        nw._schema_ready = False
        nw.db_init()

    def tearDown(self):
        nw.DB_FILE = self._db
        nw._schema_ready = False

    def test_round_trip_through_sqlite(self):
        now = time.time()
        nw._record_threat_hit("192.168.1.44", "77.88.8.8", "out", "spamhaus",
                              ports=(443,), host="yandex.ru", ts=now)
        nw._record_inbound("192.168.1.20", "185.220.101.5", 22)
        con = nw.db_connect()
        con.execute("INSERT INTO threat_hits(dev,rem,dir,ports,hosts,lists,first,"
                    "last,count) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("192.168.1.44", "77.88.8.8", "out", "443", "yandex.ru",
                     "spamhaus", now, now, 3))
        con.execute("INSERT INTO inbound_hits(dev,rem,ports,first,last,count) "
                    "VALUES(?,?,?,?,?,?)",
                    ("192.168.1.20", "185.220.101.5", "22", now, now, 7))
        con.commit()

        nw.THREAT_HITS.clear()
        nw.INBOUND.clear()
        nw.db_load_baselines(con)          # simulates a restart
        con.close()

        self.assertIn(("192.168.1.44", "77.88.8.8", "out"), nw.THREAT_HITS)
        e = nw.THREAT_HITS[("192.168.1.44", "77.88.8.8", "out")]
        self.assertEqual(e["ports"], {443})
        self.assertEqual(e["hosts"], {"yandex.ru"})
        self.assertEqual(e["lists"], "spamhaus")
        self.assertEqual(e["count"], 3)
        self.assertEqual(nw.INBOUND[("192.168.1.20", "185.220.101.5")]["count"], 7)

    def test_events_older_than_the_window_are_not_restored(self):
        old = time.time() - nw.EVENT_RETAIN - 600
        con = nw.db_connect()
        con.execute("INSERT INTO threat_hits(dev,rem,dir,ports,hosts,lists,first,"
                    "last,count) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("192.168.1.44", "1.1.1.1", "out", "", "", "tor", old, old, 1))
        con.commit()
        nw.THREAT_HITS.clear()
        nw.db_load_baselines(con)
        con.close()
        self.assertEqual(len(nw.THREAT_HITS), 0)


class DetailAggregation(unittest.TestCase):
    def setUp(self):
        reset_state()
        self.tmp = tempfile.mkdtemp()
        self._db = nw.DB_FILE
        nw.DB_FILE = os.path.join(self.tmp, "t.db")
        nw._schema_ready = False
        nw.db_init()
        nw._rdns_cache["77.88.8.8"] = ""      # skip the live PTR lookup

    def tearDown(self):
        nw.DB_FILE = self._db
        nw._schema_ready = False

    def test_detail_explains_a_flagged_address(self):
        listed("77.88.8.8", "spamhaus,tor")
        nw.DEV_NAMES["192.168.1.44"] = "pixel-phone"
        nw.GEO["77.88.8.8"] = {"status": "ok", "lat": 55.7, "lon": 37.6,
                               "city": "Moscow", "region": "", "country": "Russia",
                               "countryCode": "RU", "isp": "Yandex", "org": ""}
        nw._record("192.168.1.44", "77.88.8.8", "tcp", 443, up=100, down=900,
                   host="yandex.ru")
        nw._alert_pass(warmup=0)

        d = nw.detail_data("77.88.8.8", "192.168.1.44")
        self.assertTrue(d["threat"]["listed"])
        self.assertEqual(sorted(s["label"] for s in d["threat"]["sources"]),
                         ["Spamhaus DROP", "Tor exit node"])
        self.assertTrue(all(s["meaning"] for s in d["threat"]["sources"]))
        self.assertEqual(d["geo"]["country"], "Russia")
        self.assertEqual(len(d["live"]), 1)
        self.assertEqual(d["live"][0]["dev_name"], "pixel-phone")
        self.assertEqual(len(d["events"]), 1)
        self.assertIn("yandex.ru", d["hosts"])
        self.assertEqual(d["focus_dev"], "192.168.1.44")

    def test_detail_of_a_clean_address_is_explicit_about_it(self):
        listed("5.5.5.5", "tor")
        nw._rdns_cache["8.8.8.8"] = ""
        d = nw.detail_data("8.8.8.8")
        self.assertFalse(d["threat"]["listed"])
        self.assertEqual(d["threat"]["sources"], [])
        self.assertEqual(d["live"], [])

    def test_digest_threats_keep_the_raw_ip_for_click_through(self):
        now = time.time()
        con = nw.db_connect()
        con.execute("INSERT INTO sessions(dev,dev_name,rem,host,country,cc,first,"
                    "last,up,down,threat) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("192.168.1.44", "pixel-phone", "77.88.8.8", "yandex.ru",
                     "Russia", "RU", now, now, 10, 20, "spamhaus"))
        con.commit()
        con.close()
        t = nw.digest_data(1)["threats"]
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0]["ip"], "77.88.8.8")          # needed by the drawer
        self.assertEqual(t[0]["dev_ip"], "192.168.1.44")
        self.assertEqual(t[0]["lists"], ["Spamhaus DROP"])


class NotifyQueue(unittest.TestCase):
    def setUp(self):
        reset_state()

    def test_alerts_are_queued_not_threaded(self):
        for i in range(5):
            nw._emit_alert("critical", "threat", "192.168.1.%d" % i,
                           "9.9.9.9", "", "test")
        self.assertEqual(len(nw._notify_q), 5)

    def test_queue_is_bounded(self):
        for i in range(nw.NOTIFY_QUEUE_MAX + 50):
            nw._emit_alert("info", "dev_rem", "192.168.1.1", "9.9.9.9", "", "x")
        self.assertEqual(len(nw._notify_q), nw.NOTIFY_QUEUE_MAX)


class ConfigKnob(unittest.TestCase):
    def test_event_retain_hours_is_honoured_and_clamped(self):
        orig = nw.EVENT_RETAIN
        try:
            tmp = tempfile.mkdtemp()
            conf = os.path.join(tmp, "netwatch.conf")
            _orig_conf = nw.CONF_FILE
            nw.CONF_FILE = conf
            with open(conf, "w") as f:
                f.write('{"event_retain_hours": 24}')
            nw.load_config()
            self.assertEqual(nw.EVENT_RETAIN, 24 * 3600)
            self.assertEqual(nw.INBOUND_RETAIN, 24 * 3600)
            with open(conf, "w") as f:                 # absurd value gets clamped
                f.write('{"event_retain_hours": 99999}')
            nw.load_config()
            self.assertEqual(nw.EVENT_RETAIN, 30 * 86400)
            nw.CONF_FILE = _orig_conf
        finally:
            nw.EVENT_RETAIN = orig
            nw.INBOUND_RETAIN = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)
