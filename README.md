# NetWatch

**A live, network-wide world map of every device's internet connections — with
alerts, threat-intelligence flagging, history, and Pi-hole-bypass detection.**

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20(Raspberry%20Pi)-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none%20(stdlib)-brightgreen)

NetWatch runs on a small always-on Linux box (a Raspberry Pi is ideal), watches a
**mirrored switch port**, and maps the real outbound connections of *every* device
on your LAN — phones, TVs, IoT and all — with the true remote IP, destination port,
and (for most HTTPS) the site's hostname read from the TLS SNI. It geolocates each
destination and plots it, colored by which device is responsible.

It also **alerts** on unusual activity, **flags known-bad IPs** against public
blocklists, keeps **30 days of history**, tracks **data volume** per device, and
detects devices trying to **bypass your Pi-hole** with their own external or
encrypted (DoH) DNS.

Pure Python 3 standard library — **nothing to install**.

> Just want to map a **single computer** without any switch setup? See the sibling
> project **[NetMap](../../netmap)**.

---

## Screenshots

![NetWatch live map](docs/netwatch-map.png)

*A live world map with animated arcs from your network to every remote endpoint,
colored by device — flagged/threat destinations glow red.*

| Devices & destinations | Alerts feed |
|---|---|
| ![devices](docs/netwatch-devices.png) | ![alerts](docs/netwatch-alerts.png) |

*Devices are color-coded with upload/download totals and badges for threats or
Pi-hole bypass; the alerts feed is severity-coded.*

---

## Features

- **Whole-network visibility** from one mirrored port — every device, all protocols
- **Real endpoints + hostnames** (TLS SNI), not just DNS domains — catches traffic
  that never does a DNS lookup (hardcoded IPs, IoT phone-homes)
- **Alerts** on a device reaching a new country, hitting a known-bad IP, or
  bypassing your Pi-hole — in-app plus optional phone push (ntfy), webhook, or email.
  Each device's DNS-bypass to a given resolver alerts **twice, then goes quiet for
  good** (survives clearing alerts and restarts); a *new* resolver alerts again.
  Every attempt is still logged and rolled up in the digest's DNS-server list
- **Threat-intelligence flagging** against Tor exit nodes, FireHOL level-1, and
  Spamhaus DROP (auto-refreshed); flagged destinations turn red
- **Digest** (on-screen panel + optional weekly email) with top talkers, countries,
  alert counts, threat hits, and a **deduplicated list of every DNS server/resolver
  devices tried to reach** — a ready-made blocklist for your firewall or ACLs
- **History** saved to SQLite with a 24-hour look-back view; 30-day retention
- **Data volume** (↑ upload / ↓ download) per device and destination
- **Pi-hole bypass detection** — flags devices doing their own external DNS,
  DoT (port 853), or DoH; the digest's **DNS list** tab is a cumulative, deduplicated
  blocklist split into firewall-blockable IPs and Pi-hole-blockable domains
- **Friendly device names** — reverse-DNS/MAC-vendor by default, plus an optional
  manual name map (any switch/controller that can export a client list works)
- **Unsolicited-inbound detection** — flags TCP connections opened *to* your devices
  from the internet
- Per-device map filtering, a searchable side panel, and a dark themed UI

## How it works (and its limits)

- The switch **mirrors** every packet crossing your internet uplink to a spare
  port; the Pi's wired NIC reads the copies.
- NetWatch parses only packet **headers** — addresses, ports, TLS SNI hostnames,
  and DNS answers. **No payloads are stored.** The only data leaving your network
  is the set of remote IPs sent to [ip-api.com](https://ip-api.com) for
  geolocation (cached locally).
- It records **outbound** flows (a LAN device → a public IP), and separately flags
  **unsolicited inbound** TCP connections opened *to* your devices from the internet.
- HTTPS/TLS-over-TCP usually reveals the hostname via SNI. QUIC (UDP/443) is
  encrypted, so those show the real IP + reverse-DNS but not always a clean host.
- Under a fully saturated gigabit transfer the Pi may drop some mirrored packets
  (shown in the header). Harmless here — we only need *which* endpoints, not bytes.

## Requirements

- A Linux capture box with two network paths (a Raspberry Pi 4/5 is perfect: wired
  Ethernet for the mirror, Wi-Fi for its normal connection)
- A **managed switch with port mirroring** (also called **SPAN** or a
  **monitor/mirror port**). This is the one hard requirement — it's what lets the
  Pi see other devices' traffic. Most managed/"smart" switches from any vendor
  support it; consult your switch's manual for the exact menu name.
- Python 3.9+ and root (raw packet capture)

---

## Setup

### 1. Wire it up

- **Pi Ethernet (eth0)** → the switch's **mirror/monitor port** (a receive-only
  copy of traffic).
- **Pi Wi-Fi (wlan0)** → your normal network (for geolocation and serving the map).
  Connect Wi-Fi first so the Pi stays reachable.

**Which port to mirror?** Mirror the port carrying all internet traffic — the link
between your switch and your router. If devices are split across two switches,
mirror on the switch the router plugs into and add the inter-switch link as a
second source port.

### 2. Enable port mirroring on the switch

Every managed switch calls this something slightly different — **port mirroring**,
**SPAN**, or a **monitor session** — but the concept is identical: pick a
**destination/monitor port** (where the Pi plugs in) and one or more **source
ports** to copy, and set the direction to **both** (ingress + egress). Apply, and
the Pi's mirror NIC will start seeing copies of that traffic.

General steps (adapt to your switch's UI/CLI):

1. Find the mirroring/SPAN feature in your switch's management interface.
2. Set the **destination** (monitor) port to the port the Pi's Ethernet is on.
3. Set the **source** port(s) to the uplink identified in step 1 (plus any
   inter-switch link).
4. Set direction to **both**, then apply/save.

If you're not sure whether your switch supports it, look for "mirror," "SPAN," or
"monitor" in its manual. Unmanaged switches do **not** support this.

### 3. Put it on the Pi

```bash
sudo mkdir -p /opt/netwatch
sudo cp netwatch.py /opt/netwatch/
sudo ip link set eth0 up          # the mirror port won't get an IP; that's fine
```

### 4. Run it

```bash
sudo python3 /opt/netwatch/netwatch.py --iface eth0 --pihole 192.168.1.2
```

Open **`http://<pi-wifi-ip>:8339`** from any browser on your network. The header's
**capture** pill should show packets-per-second climbing. Pass `--pihole` with each
Pi-hole IP so bypass detection knows which resolvers are sanctioned.

Preview the UI with fake traffic (no mirror, no root):

```bash
python3 netwatch.py --demo --host 127.0.0.1
```

| Flag | Description |
|------|-------------|
| `--iface NAME` | Capture interface (default `eth0`) |
| `--pihole IP` | Your Pi-hole IP(s); repeatable |
| `--port N` | Web server port (default 8339) |
| `--home LAT,LON` | Set map location manually |
| `--no-alerts` | Collect data but never send notifications |
| `--demo` | Synthesize traffic to preview the UI |

### 5. Run as a service (always-on)

```bash
sudo cp netwatch.service /etc/systemd/system/
# edit the ExecStart path/flags if needed (add your --pihole IP here)
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch
```

### 6. Alerts & config (optional)

In-app alerts always work. For phone/email/webhook notifications and tuning, copy
[`netwatch.conf.example`](netwatch.conf.example) to `netwatch.conf` next to the
script and edit it (Pi-hole IPs, warm-up window, ntfy/webhook/email channels).
The config stays on your Pi and is read locally.

Alert severities: **critical** (threat-list hit), **warning** (Pi-hole bypass),
**notice** (new country), **info** (new destination, if enabled).

To keep the feed readable, a device's **DNS-bypass to any given resolver alerts
twice, then stops permanently** — the count is remembered across clearing alerts
and across restarts, so you won't keep seeing the same device→resolver pair. A
device reaching a *brand-new* resolver alerts again (twice). This only limits the
*alerts*; every bypass attempt is still recorded, and every resolver ends up in
the digest's DNS-server list below (your ready-made blocklist).

### 7. The digest & the DNS-server blocklist

Click **☰ digest** in the header for an on-screen summary of the last 24 hours /
7 / 30 days: top talkers, destinations, countries, alert counts, threat hits, and
a **deduplicated list of every DNS server or resolver your devices tried to reach**
while bypassing your sanctioned DNS. That list is exactly what you'd paste into a
firewall rule or ACL/IP group to block them. Enable `weekly_digest` (with email
configured) in `netwatch.conf` to also receive this as a weekly email.

### 8. Naming your devices (optional)

By default NetWatch names each device by reverse-DNS (the hostname it registered
via DHCP), falling back to its MAC vendor, then its IP. To show your own friendly
names instead — handy for IoT gadgets that announce nothing — copy
[`netwatch_names.json.example`](netwatch_names.json.example) to `netwatch_names.json`
next to the script and map each device's **MAC** (any spelling) or **IP** to a
name. These take top priority. A MAC key is best since it survives IP changes.
Adding a name applies within a few seconds; removing one needs a restart. If your
switch or controller can export a client list, you can build this file from that
export rather than typing names by hand.

---

## Responsible use

NetWatch captures traffic metadata from a mirrored port. **Only deploy it on a
network you own or administer, and where users have appropriate notice.** Capturing
others' network traffic without authorization may be illegal in your jurisdiction.
NetWatch deliberately stores only connection metadata (addresses, ports, hostnames)
and never packet contents, but you are responsible for using it lawfully.

## Security & access

The dashboard is an **unauthenticated LAN service** — anyone who can reach
`http://<pi>:8339` can view it. That's by design for a home network, but be aware:

- **Keep it on a trusted LAN.** Don't port-forward it to the internet or expose it
  on an untrusted/guest network. If you need remote access, reach it over a VPN
  (e.g. Tailscale/WireGuard), not a public port.
- **Built-in protections.** The action endpoints (clear alerts, quit) require a
  same-origin request header, so a malicious web page a LAN user visits can't fire
  them cross-site (CSRF). All endpoints also validate the `Host` header to block
  DNS-rebinding attempts against the read APIs. If you reach the dashboard by a
  public DNS name, add it to `allow_hosts` in `netwatch.conf`; `host_check` can be
  turned off there if needed (not recommended).

## License

[MIT](LICENSE) © 2026 huskerminion
