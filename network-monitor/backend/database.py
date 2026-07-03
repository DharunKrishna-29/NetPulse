"""
SQLite Database setup and helper functions for Network Traffic Monitor.
Thread-safe implementation with connection locking.
"""
import sys
import os
import sqlite3
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend import config

# Thread lock for SQLite writes to avoid database locked errors across threads
db_lock = threading.Lock()

def get_db_connection():
    """Returns a connection to the SQLite database."""
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database tables if they do not exist."""
    with db_lock:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                length INTEGER
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                alert_type TEXT,
                source_ip TEXT,
                details TEXT,
                severity TEXT,
                cooldown_suppressed_count INTEGER DEFAULT 0
            )
        ''')
        
        # Indexes for fast querying on dashboards
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)')
        
        conn.commit()
        conn.close()

def insert_packet(pkt_dict):
    """Inserts a single packet record into SQLite."""
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                pkt_dict.get('timestamp', time.time()),
                pkt_dict.get('src_ip', 'Unknown'),
                pkt_dict.get('dst_ip', 'Unknown'),
                pkt_dict.get('src_port', 0),
                pkt_dict.get('dst_port', 0),
                pkt_dict.get('protocol', 'Other'),
                pkt_dict.get('length', 0)
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

def insert_alert(alert_type, source_ip, details, severity, suppressed_count=0):
    """Inserts an alert record into SQLite and returns the inserted alert dict."""
    timestamp = time.time()
    with db_lock:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, source_ip, details, severity, cooldown_suppressed_count)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, alert_type, source_ip, details, severity, suppressed_count))
            alert_id = cursor.lastrowid
            conn.commit()
            return {
                "id": alert_id,
                "timestamp": timestamp,
                "alert_type": alert_type,
                "source_ip": source_ip,
                "details": details,
                "severity": severity,
                "cooldown_suppressed_count": suppressed_count
            }
        finally:
            conn.close()

def get_recent_packets(limit=50, ip_filter=None, protocol_filter=None):
    """Retrieves the most recent packets, with optional filtering."""
    conn = get_db_connection()
    try:
        query = "SELECT * FROM packets WHERE 1=1"
        params = []
        if ip_filter and ip_filter.strip():
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ?)"
            params.extend([f"%{ip_filter.strip()}%", f"%{ip_filter.strip()}%"])
        if protocol_filter and protocol_filter.strip() and protocol_filter != "ALL":
            query += " AND protocol = ?"
            params.append(protocol_filter.strip())
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_recent_alerts(limit=50, page=1):
    """Retrieves recent alerts paginated."""
    offset = (page - 1) * limit
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def get_traffic_stats(window_seconds=10):
    """Calculates live stats: packets/sec, total packets, active alerts count, top talker."""
    conn = get_db_connection()
    try:
        now = time.time()
        window_start = now - window_seconds
        
        # Packets in last window_seconds
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM packets WHERE timestamp >= ?", (window_start,))
        row = cursor.fetchone()
        window_packets = row['cnt'] if row else 0
        packets_per_sec = round(window_packets / max(window_seconds, 1), 1)
        
        # Total packets ever
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM packets")
        row = cursor.fetchone()
        total_packets = row['cnt'] if row else 0
        
        # Active alerts in last 1 hour (or total active alerts)
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM alerts")
        row = cursor.fetchone()
        active_alerts = row['cnt'] if row else 0
        
        # Top talker IP in last 5 minutes
        talker_start = now - 300
        cursor = conn.execute('''
            SELECT src_ip, COUNT(*) as cnt FROM packets 
            WHERE timestamp >= ? AND src_ip != 'Unknown' 
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 1
        ''', (talker_start,))
        talker_row = cursor.fetchone()
        top_talker = talker_row['src_ip'] if talker_row else "None"
        top_talker_count = talker_row['cnt'] if talker_row else 0
        
        return {
            "packets_per_sec": packets_per_sec,
            "total_packets": total_packets,
            "active_alerts": active_alerts,
            "top_talker": top_talker,
            "top_talker_count": top_talker_count
        }
    finally:
        conn.close()

def get_traffic_history(minutes=5):
    """
    Returns last N minutes of packet counts bucketed per second for Chart.js.
    Returns list of {timestamp_sec: int, count: int, label: str}
    """
    conn = get_db_connection()
    try:
        now = time.time()
        start_time = now - (minutes * 60)
        
        cursor = conn.execute('''
            SELECT CAST(timestamp AS INTEGER) as sec, COUNT(*) as cnt 
            FROM packets 
            WHERE timestamp >= ? 
            GROUP BY sec ORDER BY sec ASC
        ''', (start_time,))
        
        rows = cursor.fetchall()
        data_map = {row['sec']: row['cnt'] for row in rows}
        
        # Fill in zero counts for empty seconds so line chart is smooth
        history = []
        current_sec = int(start_time)
        end_sec = int(now)
        while current_sec <= end_sec:
            cnt = data_map.get(current_sec, 0)
            time_label = time.strftime("%H:%M:%S", time.localtime(current_sec))
            history.append({
                "timestamp": current_sec,
                "label": time_label,
                "count": cnt
            })
            current_sec += 1
            
        return history
    finally:
        conn.close()

def get_alert_counts_by_severity():
    """For Week 3 PDF report: counts alerts by severity."""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity
        ''')
        rows = cursor.fetchall()
        counts = {"high": 0, "medium": 0, "low": 0}
        for r in rows:
            sev = r['severity'].lower() if r['severity'] else "low"
            counts[sev] = r['cnt']
        return counts
    finally:
        conn.close()

def get_top_talkers(limit=5):
    """For Week 3 PDF report: top N talker IPs."""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT src_ip, COUNT(*) as cnt FROM packets 
            WHERE src_ip != 'Unknown' 
            GROUP BY src_ip ORDER BY cnt DESC LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        return [{"ip": r['src_ip'], "count": r['cnt']} for r in rows]
    finally:
        conn.close()
