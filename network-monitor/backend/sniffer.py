"""
Packet Sniffer Module for Network Traffic Monitor.
Uses Scapy in a background daemon thread.
Includes graceful fallback to Live Simulation Mode when elevated permissions (sudo/admin) are missing.
Batches captured packets to throttle SocketIO updates (~5/sec) to avoid flooding the browser.
"""
import sys
import time
import threading
import queue
import random
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend import config, database, rules_engine

# Try importing scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PacketSniffer:
    def __init__(self, socketio_instance=None):
        self.socketio = socketio_instance
        self.running = False
        self.thread = None
        self.is_simulation_mode = False
        self.packet_queue = queue.Queue()
        self.batch_thread = None

    def set_socketio(self, socketio_instance):
        self.socketio = socketio_instance

    def start(self):
        """Starts the background packet capture thread and batch emitter thread."""
        if self.running:
            return
            
        self.running = True
        
        # Start batch emitter thread (throttled to ~5 batches/sec)
        self.batch_thread = threading.Thread(target=self._emit_batches_loop, name="PacketBatchEmitter", daemon=True)
        self.batch_thread.start()
        
        # Start capture thread
        self.thread = threading.Thread(target=self._sniff_loop, name="ScapySnifferThread", daemon=True)
        self.thread.start()
        print("[SNIFFER] Background sniffer service initiated.")

    def stop(self):
        self.running = False

    def _process_packet(self, pkt_dict):
        """Saves to DB, checks anomaly rules, and queues for SocketIO batch emission."""
        try:
            # 1. Insert into SQLite
            db_id = database.insert_packet(pkt_dict)
            pkt_dict['id'] = db_id
            
            # 2. Check rules engine for anomalies
            rules_engine.engine.check_packet(pkt_dict)
            
            # 3. Add to queue for batch SocketIO emission
            self.packet_queue.put(pkt_dict)
        except Exception as e:
            print(f"[SNIFFER ERROR] Failed processing packet: {e}")

    def _emit_batches_loop(self):
        """Throttles SocketIO 'new_packet' emissions to ~5/sec by sending batches."""
        while self.running:
            batch = []
            try:
                # Collect up to 20 packets from queue without blocking indefinitely
                while not self.packet_queue.empty() and len(batch) < 20:
                    batch.append(self.packet_queue.get_nowait())
            except queue.Empty:
                pass

            if batch and self.socketio:
                try:
                    self.socketio.emit('new_packet', {"packets": batch, "is_simulated": self.is_simulation_mode})
                except Exception as e:
                    pass

            time.sleep(0.2)  # 5 batches per second (0.2s interval)

    def _scapy_callback(self, pkt):
        """Callback executed by scapy for each captured raw packet."""
        if not self.running:
            return
            
        try:
            timestamp = time.time()
            src_ip = "Unknown"
            dst_ip = "Unknown"
            src_port = 0
            dst_port = 0
            protocol = "Other"
            length = len(pkt)
            
            if IP in pkt:
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                if TCP in pkt:
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                elif ICMP in pkt:
                    protocol = "ICMP"
                else:
                    protocol = f"IP-{ip_layer.proto}"
            else:
                # Handle ARP or Ethernet only packets
                protocol = pkt.summary().split()[0] if hasattr(pkt, 'summary') else "Eth"
                
            pkt_dict = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(src_port),
                "dst_port": int(dst_port),
                "protocol": protocol,
                "length": int(length)
            }
            self._process_packet(pkt_dict)
        except Exception as e:
            pass

    def _sniff_loop(self):
        """Main sniffing loop. Tries real scapy capture; falls back to live simulation if sudo/admin needed."""
        if SCAPY_AVAILABLE:
            try:
                if config.INTERFACE:
                    print(f"[*] Starting Scapy packet capture on interface: {config.INTERFACE}...")
                    sniff(iface=config.INTERFACE, prn=self._scapy_callback, store=0, stop_filter=lambda x: not self.running)
                else:
                    print("[*] Starting Scapy packet capture on default interface...")
                    sniff(prn=self._scapy_callback, store=0, stop_filter=lambda x: not self.running)
                return
            except (PermissionError, OSError, RuntimeError) as e:
                print("\n" + "="*70)
                print("⚠️  [SNIFFER PERMISSION WARNING] Raw packet sniffing failed!")
                print(f"    Reason: {e}")
                print("    👉 Sniffing live packets requires elevated privileges (sudo / Administrator).")
                print("    👉 AUTOMATICALLY SWITCHING TO LIVE SIMULATION MODE for instant dashboard previewing!")
                print("="*70 + "\n")
                self.is_simulation_mode = True
        else:
            print("⚠️  [SNIFFER WARNING] Scapy library not installed. Using LIVE SIMULATION MODE.")
            self.is_simulation_mode = True

        # -------------------------------------------------------------
        # LIVE SIMULATION MODE (Fallback when sudo/admin is missing)
        # Generates realistic SOC network telemetry so the dashboard is alive!
        # -------------------------------------------------------------
        print("[*] Live Simulation Mode active. Generating realistic network telemetry...")
        sim_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.22", "192.168.1.100",
            "10.0.0.5", "10.0.0.12", "172.16.0.4", "8.8.8.8", "1.1.1.1",
            "140.82.112.3", "34.117.59.81", "104.16.132.229"
        ]
        common_ports = [80, 443, 22, 53, 8080, 3306, 5432, 6379, 25]
        protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
        
        tick = 0
        while self.running:
            tick += 1
            now = time.time()
            
            # Generate 1 to 4 normal background packets per cycle
            num_pkts = random.randint(1, 4)
            for _ in range(num_pkts):
                proto = random.choice(protocols)
                pkt = {
                    "timestamp": now + random.uniform(0, 0.05),
                    "src_ip": random.choice(sim_ips),
                    "dst_ip": random.choice(sim_ips[:4] + ["192.168.1.1"]),
                    "src_port": random.randint(1024, 65535) if proto in ["TCP", "UDP"] else 0,
                    "dst_port": random.choice(common_ports) if proto in ["TCP", "UDP"] else 0,
                    "protocol": proto,
                    "length": random.choice([64, 128, 256, 512, 1024, 1500])
                }
                self._process_packet(pkt)
                
            # Every ~45 seconds, generate a simulated anomaly so user sees SOC alerts automatically!
            if tick % 220 == 0:
                anomaly_type = random.choice(["port_scan", "traffic_spike", "blocklist_hit"])
                self.trigger_simulated_anomaly(anomaly_type)

            time.sleep(0.2)  # 5 ticks per second

    def trigger_simulated_anomaly(self, anomaly_type):
        """Generates a burst of packets to trigger rules_engine deterministically."""
        now = time.time()
        print(f"[SIMULATOR] Triggering simulated anomaly: {anomaly_type}")
        
        if anomaly_type == "port_scan":
            attacker_ip = "192.168.1.133" # Attacker IP probing ports
            target_ip = "10.0.0.5"
            # Send 25 packets to distinct ports within 1 second (> threshold of 20)
            for i in range(25):
                pkt = {
                    "timestamp": now + (i * 0.02),
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": 54321,
                    "dst_port": 2000 + i, # Distinct destination port
                    "protocol": "TCP",
                    "length": 64
                }
                self._process_packet(pkt)
                
        elif anomaly_type == "traffic_spike":
            spiker_ip = "172.16.0.44" # IP sending massive burst
            target_ip = "192.168.1.10"
            # Send 105 packets in rapid succession (> threshold of 100)
            for i in range(105):
                pkt = {
                    "timestamp": now + (i * 0.01),
                    "src_ip": spiker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(10000, 60000),
                    "dst_port": 80,
                    "protocol": "UDP",
                    "length": 1024
                }
                self._process_packet(pkt)
                
        elif anomaly_type == "blocklist_hit":
            # Pick a blocked IP from config.BLOCKLIST
            blocked_ip = config.BLOCKLIST[0] if config.BLOCKLIST else "203.0.113.1"
            internal_ip = "192.168.1.100"
            pkt = {
                "timestamp": now,
                "src_ip": internal_ip,
                "dst_ip": blocked_ip, # Destination is blocked!
                "src_port": 49152,
                "dst_port": 443,
                "protocol": "TCP",
                "length": 512
            }
            self._process_packet(pkt)

# Global sniffer singleton
sniffer = PacketSniffer()
