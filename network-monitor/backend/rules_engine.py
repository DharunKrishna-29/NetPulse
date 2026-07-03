"""
Anomaly Detection Rules Engine for Network Traffic Monitor.
Implements rolling window checks using in-memory collections.deque.
Includes Week 2 hardening: cooldown per (ip, rule_type) to prevent spamming.
"""
import sys
import os
import time
import threading
from collections import deque, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend import config, database

class RulesEngine:
    def __init__(self, alert_callback=None):
        """
        alert_callback: optional function(alert_dict) called immediately when a new alert is triggered,
        used to emit SocketIO events.
        """
        self.alert_callback = alert_callback
        self.lock = threading.Lock()
        
        # In-memory rolling window deques
        # port_history[src_ip] -> deque of (timestamp, dst_port)
        self.port_history = defaultdict(deque)
        
        # packet_history[src_ip] -> deque of timestamps
        self.packet_history = defaultdict(deque)
        
        # Week 2: Cooldown tracking
        # cooldowns[(ip, rule_type)] -> timestamp of last fired alert
        self.cooldowns = {}
        # active_counters[(ip, rule_type)] -> count of suppressed occurrences during cooldown
        self.active_counters = defaultdict(int)

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def _is_in_cooldown(self, ip, rule_type, now):
        """Checks if an alert type for an IP is within the cooldown window."""
        key = (ip, rule_type)
        last_time = self.cooldowns.get(key, 0)
        if now - last_time < config.ALERT_COOLDOWN_SEC:
            # We are in cooldown! Increment suppressed counter
            self.active_counters[key] += 1
            return True
        return False

    def _trigger_alert(self, alert_type, source_ip, details, severity, now):
        """Helper to record cooldown, save to SQLite, and emit SocketIO event."""
        key = (source_ip, alert_type)
        suppressed = self.active_counters.get(key, 0)
        
        # Reset cooldown and counter
        self.cooldowns[key] = now
        self.active_counters[key] = 0
        
        if suppressed > 0:
            details += f" (Note: {suppressed} identical events suppressed during 60s cooldown)"
            
        alert_record = database.insert_alert(
            alert_type=alert_type,
            source_ip=source_ip,
            details=details,
            severity=severity,
            suppressed_count=suppressed
        )
        
        # Emit via callback if registered (e.g. SocketIO emit)
        if self.alert_callback:
            try:
                self.alert_callback(alert_record)
            except Exception as e:
                print(f"[RULES ENGINE] Error in alert callback: {e}")
                
        return alert_record

    def check_packet(self, pkt):
        """
        Evaluates a single packet against all detection rules:
        1. BLOCKLIST HIT -> severity high
        2. PORT SCAN -> severity high
        3. TRAFFIC SPIKE -> severity medium
        Returns list of generated alert dictionaries (empty if none triggered or in cooldown).
        """
        triggered_alerts = []
        now = pkt.get('timestamp', time.time())
        src_ip = pkt.get('src_ip', '')
        dst_ip = pkt.get('dst_ip', '')
        dst_port = pkt.get('dst_port', 0)
        
        if not src_ip or src_ip == 'Unknown':
            return triggered_alerts

        with self.lock:
            # -------------------------------------------------------------
            # RULE 1: BLOCKLIST HIT
            # src_ip or dst_ip matches static list in config.py
            # -------------------------------------------------------------
            if src_ip in config.BLOCKLIST or dst_ip in config.BLOCKLIST:
                matched_ip = src_ip if src_ip in config.BLOCKLIST else dst_ip
                rule_type = "BLOCKLIST_HIT"
                if not self._is_in_cooldown(matched_ip, rule_type, now):
                    alert = self._trigger_alert(
                        alert_type=rule_type,
                        source_ip=src_ip,
                        details=f"Communication detected with blocked IP: {matched_ip} (dst: {dst_ip})",
                        severity="high",
                        now=now
                    )
                    triggered_alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 2: PORT SCAN
            # same src_ip connects to > PORT_SCAN_THRESHOLD distinct dst_ports within PORT_SCAN_WINDOW_SEC
            # -------------------------------------------------------------
            if dst_port and dst_port > 0:
                p_deque = self.port_history[src_ip]
                p_deque.append((now, dst_port))
                
                # Evict old timestamps outside window
                window_start = now - config.PORT_SCAN_WINDOW_SEC
                while p_deque and p_deque[0][0] < window_start:
                    p_deque.popleft()
                    
                # Count distinct ports
                distinct_ports = {port for t, port in p_deque}
                if len(distinct_ports) > config.PORT_SCAN_THRESHOLD:
                    rule_type = "PORT_SCAN"
                    if not self._is_in_cooldown(src_ip, rule_type, now):
                        sample_ports = sorted(list(distinct_ports))
                        ports_str = ", ".join(map(str, sample_ports[:8]))
                        if len(sample_ports) > 8:
                            ports_str += f", +{len(sample_ports)-8} more"
                        alert = self._trigger_alert(
                            alert_type=rule_type,
                            source_ip=src_ip,
                            details=f"Port scan detected! {len(distinct_ports)} distinct ports probed in {config.PORT_SCAN_WINDOW_SEC}s window. Target ports: [{ports_str}].",
                            severity="high",
                            now=now
                        )
                        triggered_alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 3: TRAFFIC SPIKE
            # same src_ip sends > TRAFFIC_SPIKE_THRESHOLD packets within TRAFFIC_SPIKE_WINDOW_SEC
            # -------------------------------------------------------------
            t_deque = self.packet_history[src_ip]
            t_deque.append(now)
            
            # Evict old timestamps outside window
            window_start = now - config.TRAFFIC_SPIKE_WINDOW_SEC
            while t_deque and t_deque[0] < window_start:
                t_deque.popleft()
                
            if len(t_deque) > config.TRAFFIC_SPIKE_THRESHOLD:
                rule_type = "TRAFFIC_SPIKE"
                if not self._is_in_cooldown(src_ip, rule_type, now):
                    rate = round(len(t_deque) / max(1, config.TRAFFIC_SPIKE_WINDOW_SEC), 1)
                    alert = self._trigger_alert(
                        alert_type=rule_type,
                        source_ip=src_ip,
                        details=f"Traffic volume anomaly! {len(t_deque)} packets sent in {config.TRAFFIC_SPIKE_WINDOW_SEC}s ({rate} pkts/sec | Threshold: {config.TRAFFIC_SPIKE_THRESHOLD}). High bandwidth UDP/TCP storm.",
                        severity="medium",
                        now=now
                    )
                    triggered_alerts.append(alert)

        return triggered_alerts

    def clear_history(self):
        """Clears in-memory histories (useful for testing)."""
        with self.lock:
            self.port_history.clear()
            self.packet_history.clear()
            self.cooldowns.clear()
            self.active_counters.clear()

# Global singleton rules engine instance
engine = RulesEngine()
