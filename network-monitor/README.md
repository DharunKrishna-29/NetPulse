# 🛡️ NetPulse SOC — Network Traffic Monitor & Anomaly Alert Tool

> **A real-time Security Operations Center (SOC) web application built with Python, Flask, Scapy, SQLite, and Flask-SocketIO that sniffs network packets, analyzes anomaly signatures, and visualizes live telemetry on an interactive dark dashboard.**

---

## 💼 Resume / Portfolio Project Summary

*Paste this paragraph directly into your resume, GitHub profile, or portfolio:*
> **Network Traffic Monitor & Anomaly Alert Engine:** Developed a full-stack Security Operations Center (SOC) monitoring tool using Python, Flask, Scapy, and Flask-SocketIO to perform live packet capture and deep packet inspection across local network interfaces. Architected an in-memory rolling-window rules engine utilizing thread-safe deques to detect DDoS traffic bursts, TCP port scans (>20 ports/10s), and static blocklist communications with automated 60-second flood cooldown suppression. Designed a mission-control dark web dashboard with vanilla JavaScript, Chart.js, and WebSockets for real-time traffic rate graphing (~5 batch/sec throttling), interactive anomaly alert expansion, dynamic IP blocklist management, and automated ReportLab PDF daily security report generation.

---

## 📸 Dashboard Screenshots (Placeholders)

| **SOC Mission Control Dashboard** | **Real-Time Anomaly Alert Feed** | **Raw Packet Telemetry Inspector** |
| :---: | :---: | :---: |
| `[Screenshot: Dark SOC Dashboard with KPI Stat Cards and Live Line Chart]` | `[Screenshot: Color-Coded Anomaly Feed with Expanded Threat Analysis]` | `[Screenshot: Filterable Bottom Drawer with Raw Packet Stream]` |

---

## 🏗️ Project Architecture & File Structure

```text
network-monitor/
├── backend/
│   ├── sniffer.py        # Scapy packet capture, background daemon thread + batch throttling
│   ├── database.py       # SQLite setup, thread-safe connection locking & KPI helpers
│   ├── rules_engine.py   # Anomaly detection logic (Port Scans, Spikes, Blocklist + Cooldowns)
│   ├── app.py            # Flask app, REST API + Flask-SocketIO for live WebSocket updates
│   └── config.py         # Detection thresholds, blocklist array, interface & cooldown timers
├── frontend/
│   ├── templates/
│   │   └── index.html    # SOC mission control dashboard (Single-page, 3-zone layout)
│   └── static/
│       ├── css/style.css # SOC dark theme styles + light/dark theme toggle CSS variables
│       └── js/dashboard.js # Vanilla JS + Chart.js + Socket.io client (Framework-free)
├── data/
│   └── traffic.db        # SQLite archive (auto-created on initialization)
├── tests/
│   └── test_rules_engine.py # Pytest suite for deterministic anomaly & cooldown verification
├── requirements.txt      # Python package dependencies
└── README.md             # Project documentation & setup instructions
```

---

## ⚡ Quick Start & Running the Application

### 1. Install Dependencies
Ensure you have Python 3.9+ installed. Install required packages using `pip`:
```bash
pip install -r network-monitor/requirements.txt
```

### 2. Start the Server (Elevated Privileges Note)
> **⚠️ CRITICAL NOTE ON PERMISSIONS:**  
> Capturing live network packets from network interface cards (NICs) requires elevated administrative privileges (raw socket access).

* **Linux / macOS:** Run with `sudo`:
  ```bash
  sudo python3 network-monitor/backend/app.py
  ```
* **Windows:** Open PowerShell or Command Prompt **as Administrator** and run:
  ```cmd
  python network-monitor/backend/app.py
  ```
  *(Note for Windows users: Install [Npcap](https://npcap.com/) with "WinPcap API-compatible mode" enabled if Scapy cannot locate your network adapters).*

### 3. Open the Dashboard
Navigate your browser to:  
👉 **http://localhost:3000**

---

## 🌟 Intelligent Fallback: Live Simulation Mode

If you start the application **without** `sudo` / Administrator permissions (such as inside Docker containers, restricted sandbox cloud environments, or standard user terminals), Scapy will be unable to open raw sockets (`OSError: [Errno 93] Protocol not supported` or `PermissionError`).

Rather than crashing, **NetPulse SOC automatically switches to Live Simulation Mode**!
* Generates realistic background TCP/UDP/ICMP traffic from common subnet IP ranges.
* Periodically emits synthetic port scans, traffic spikes, and blocklist hits so you can test the SOC dashboard animations and real-time Chart.js line graphs instantly without root access.

---

## 🎯 How to Trigger Test Alerts for Demos

You can trigger security alerts in three ways during presentations or demos:

### Method 1: Instant Dashboard Demo Buttons (Easiest)
Click any of the **"⚡ Trigger Demo Alert"** buttons at the top of the SOC dashboard:
* **[Port Scan]**: Simulates an attacker probing 25 distinct destination ports within 1 second.
* **[Spike]**: Simulates a UDP traffic flood exceeding 100 packets in 5 seconds.
* **[Blocklist Hit]**: Simulates internal communication with a flagged malicious IP (`203.0.113.1`).

### Method 2: Running `nmap` Against Localhost (Real Packet Testing)
If running with `sudo` / Admin permissions, open a second terminal and execute an `nmap` port scan against your machine:
```bash
nmap -p 1-100 localhost
# or scan TCP SYN specifically:
sudo nmap -sS -p 1-100 127.0.0.1
```
Within milliseconds, the **Rules Engine** will detect >20 distinct ports probed within 10 seconds, log the threat to SQLite, and emit a WebSocket `'new_alert'` event that slides down into the dashboard feed!

### Method 3: Dynamic Blocklist API (Week 2 Feature)
Use the **Static Blocklist Panel** on the left side of the dashboard to dynamically add any IP (e.g., `8.8.8.8` or `185.220.101.5`). Any subsequent packet sent to or from that IP will immediately trigger a High Severity alert.

---

## 🧪 Running Unit Tests (Week 2 Hardening)

To verify the rules engine detection logic and the 60-second duplicate flood cooldown suppression without needing network hardware, run the deterministic `pytest` suite:
```bash
pytest network-monitor/tests/test_rules_engine.py -v
```
**Test Coverage Includes:**
1. `test_blocklist_hit`: Verifies static blocklist matching and high severity tagging.
2. `test_port_scan_detection`: Proves that probing 20 ports does not trigger an alert, but the 21st distinct port within 10 seconds fires `PORT_SCAN`.
3. `test_traffic_spike_detection`: Verifies rolling window volume thresholds (>100 pkts/5s).
4. `test_cooldown_suppression`: Proves that subsequent identical alerts within 60 seconds are suppressed from spamming the DB while incrementing the `cooldown_suppressed_count` tracker.

---

## 📄 Daily Report PDF Export (Week 3 Feature)

Click the **"Export Daily Report"** button in the top navigation bar to download a professional, publication-quality PDF summary generated on the fly via ReportLab. The PDF includes:
* **Executive Summary KPIs:** Total packets logged, average packets/sec, and active alert totals.
* **Severity Breakdown Table:** Categorized High, Medium, and Low threat counts with recommended SOC remediation steps.
* **Top Talker Leaderboard:** Ranked list of the highest traffic source IP addresses.

---

## 🔌 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/stats` | Returns real-time KPIs (pkts/sec, total pkts, active alerts, top talker). |
| `GET` | `/api/traffic-history?minutes=5` | Returns second-bucketed traffic counts for Chart.js initialization. |
| `GET` | `/api/alerts?page=1&limit=50` | Returns paginated historical security alerts. |
| `GET` | `/api/packets?limit=50&ip=...` | Returns raw captured packet telemetry with IP/protocol filtering. |
| `GET` | `/api/blocklist` | Retrieves the list of currently blocked static IP addresses. |
| `POST` | `/api/blocklist` | Adds a new IP address to the active blocklist (`{"ip": "1.2.3.4"}`). |
| `DELETE`| `/api/blocklist` | Removes an IP from the blocklist (`{"ip": "1.2.3.4"}`). |
| `POST` | `/api/simulate-alert` | Generates synthetic anomaly bursts for demo testing (`{"type": "port_scan"}`). |
| `GET` | `/api/export` | Compiles and downloads the Daily SOC Summary Report as a styled PDF. |

---

## 🎨 UI/UX Design Specifications
* **Theme:** Dark SOC Mission Control aesthetic (`#0B0F14` background, `#121821` panels, `#38BDF8` cyan glow).
* **Typography:** `JetBrains Mono` for IP addresses, ports, and telemetry counters; `Inter` for headers and labels.
* **Animations:** Seamless CSS keyframe transitions (`slide-down-fade`) for incoming SocketIO security alerts and pulsing status badges.
* **Responsive:** Scaled layouts supporting desktops, SOC monitoring walls, and laptops down to 1024px.
