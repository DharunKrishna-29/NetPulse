"""
Unit Tests for Rules Engine using pytest.
Tests port scan, traffic spike, blocklist hit, and Week 2 cooldown suppression deterministically.
"""
import sys
import os
import time
import pytest

# Add parent directory to sys.path so 'backend' can be imported regardless of where pytest is run
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import config, database, rules_engine

@pytest.fixture(autouse=True)
def setup_engine():
    """Reset rules engine and config before each test."""
    database.init_db()
    rules_engine.engine.clear_history()
    # Save original blocklist and restore after test
    orig_blocklist = list(config.BLOCKLIST)
    config.BLOCKLIST = ["203.0.113.1", "198.51.100.23"]
    yield
    config.BLOCKLIST = orig_blocklist
    rules_engine.engine.clear_history()

def test_blocklist_hit():
    """Test that communication involving a blocked IP triggers a HIGH severity alert."""
    pkt = {
        "timestamp": time.time(),
        "src_ip": "192.168.1.50",
        "dst_ip": "203.0.113.1", # In blocklist
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 100
    }
    alerts = rules_engine.engine.check_packet(pkt)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "BLOCKLIST_HIT"
    assert alerts[0]["severity"] == "high"
    assert "203.0.113.1" in alerts[0]["details"]

def test_port_scan_detection():
    """Test that >20 distinct dst_ports within 10s triggers a PORT_SCAN alert."""
    now = time.time()
    attacker_ip = "10.0.0.99"
    target_ip = "192.168.1.1"
    
    # Send 20 packets to distinct ports (should NOT trigger yet, threshold is >20)
    for port in range(1, 21):
        pkt = {
            "timestamp": now + (port * 0.1),
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 50000,
            "dst_port": port,
            "protocol": "TCP",
            "length": 64
        }
        alerts = rules_engine.engine.check_packet(pkt)
        assert len(alerts) == 0

    # 21st distinct port should trigger the PORT_SCAN alert!
    trigger_pkt = {
        "timestamp": now + 2.5,
        "src_ip": attacker_ip,
        "dst_ip": target_ip,
        "src_port": 50000,
        "dst_port": 21,
        "protocol": "TCP",
        "length": 64
    }
    alerts = rules_engine.engine.check_packet(trigger_pkt)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "high"

def test_traffic_spike_detection():
    """Test that >100 packets within 5 seconds triggers a TRAFFIC_SPIKE alert."""
    now = time.time()
    spiker_ip = "172.16.0.88"
    
    # Send 100 packets (should NOT trigger yet, threshold is >100)
    for i in range(100):
        pkt = {
            "timestamp": now + (i * 0.01),
            "src_ip": spiker_ip,
            "dst_ip": "192.168.1.10",
            "src_port": 30000 + i,
            "dst_port": 8080,
            "protocol": "UDP",
            "length": 512
        }
        alerts = rules_engine.engine.check_packet(pkt)
        assert len(alerts) == 0

    # 101st packet within the 5s window should trigger!
    trigger_pkt = {
        "timestamp": now + 1.1,
        "src_ip": spiker_ip,
        "dst_ip": "192.168.1.10",
        "src_port": 40000,
        "dst_port": 8080,
        "protocol": "UDP",
        "length": 512
    }
    alerts = rules_engine.engine.check_packet(trigger_pkt)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "TRAFFIC_SPIKE"
    assert alerts[0]["severity"] == "medium"

def test_cooldown_suppression():
    """Test Week 2 requirement: same alert type is suppressed for 60 seconds."""
    now = time.time()
    ip = "203.0.113.1" # In blocklist
    
    # First packet triggers alert
    pkt1 = {
        "timestamp": now,
        "src_ip": ip,
        "dst_ip": "192.168.1.1",
        "src_port": 1000,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 100
    }
    alerts1 = rules_engine.engine.check_packet(pkt1)
    assert len(alerts1) == 1
    
    # Second packet 5 seconds later should be suppressed by cooldown!
    pkt2 = {
        "timestamp": now + 5,
        "src_ip": ip,
        "dst_ip": "192.168.1.1",
        "src_port": 1001,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 100
    }
    alerts2 = rules_engine.engine.check_packet(pkt2)
    assert len(alerts2) == 0 # Suppressed!
    
    # Check that suppressed counter incremented
    assert rules_engine.engine.active_counters[(ip, "BLOCKLIST_HIT")] == 1
    
    # Packet after 61 seconds should trigger alert again!
    pkt3 = {
        "timestamp": now + 61,
        "src_ip": ip,
        "dst_ip": "192.168.1.1",
        "src_port": 1002,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 100
    }
    alerts3 = rules_engine.engine.check_packet(pkt3)
    assert len(alerts3) == 1
    assert "1 identical events suppressed" in alerts3[0]["details"]
