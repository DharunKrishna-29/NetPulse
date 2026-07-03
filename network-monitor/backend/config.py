"""
Configuration for Network Traffic Monitor & Anomaly Alert Tool.
"""
import os

# Interface name: None = scapy default interface (e.g. eth0 or Wi-Fi), can be overridden
INTERFACE = os.environ.get("MONITOR_INTERFACE", None)

# Detection Thresholds
PORT_SCAN_THRESHOLD = 20      # More than 20 distinct destination ports
PORT_SCAN_WINDOW_SEC = 10     # Within a 10 second rolling window

TRAFFIC_SPIKE_THRESHOLD = 100 # More than 100 packets
TRAFFIC_SPIKE_WINDOW_SEC = 5  # Within a 5 second rolling window

# Week 2: Cooldown timer per (ip, rule_type) to prevent alert flooding
ALERT_COOLDOWN_SEC = 60

# Static Blocklist (seeded with example placeholder IPs and common suspicious test IPs)
BLOCKLIST = [
    "203.0.113.1",
    "198.51.100.23",
    "10.0.0.66",
    "192.0.2.146",
    "172.16.0.99"
]

# Database Path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "traffic.db")

# Server Configuration
PORT = 3000
HOST = "0.0.0.0"
DEBUG = False
