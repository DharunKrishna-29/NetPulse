"""
Main Flask and SocketIO application for Network Traffic Monitor & Anomaly Alert Tool.
Serves REST API endpoints, real-time SocketIO telemetry events, and SOC frontend dashboard.
Includes Week 2 Blocklist API and Week 3 PDF Report Export.
"""
import sys
import os
import time
import io
import json

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, render_template, send_from_directory, send_file
from flask_socketio import SocketIO, emit

from backend import config, database, rules_engine, sniffer

# Initialize Flask app pointing to ../frontend/templates and ../frontend/static
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "frontend", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config['SECRET_KEY'] = 'soc_secret_netpulse_key_2026'

# Initialize SocketIO (try eventlet first, fall back to threading)
try:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
except Exception:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Link SocketIO to sniffer and rules engine
sniffer.sniffer.set_socketio(socketio)

def alert_socket_callback(alert_dict):
    """Callback triggered by RulesEngine when a new alert is generated."""
    socketio.emit('new_alert', alert_dict)

rules_engine.engine.set_alert_callback(alert_socket_callback)

# Initialize database and start background sniffer on startup
database.init_db()
sniffer.sniffer.start()

# -------------------------------------------------------------------------
# FRONTEND ROUTING
# -------------------------------------------------------------------------
@app.route('/')
def index():
    """Serves the main SOC mission control dashboard."""
    return render_template('index.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    """Serves static CSS/JS assets."""
    return send_from_directory(STATIC_DIR, filename)

# -------------------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------------------
@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Returns live SOC KPIs: packets/sec, total packets, active alerts count, top talker."""
    stats = database.get_traffic_stats(window_seconds=10)
    stats['is_simulation_mode'] = sniffer.sniffer.is_simulation_mode
    stats['interface'] = config.INTERFACE or "default (eth0/en0)"
    return jsonify(stats)

@app.route('/api/traffic-history', methods=['GET'])
def get_traffic_history():
    """Returns last N minutes of packet counts bucketed per second for Chart.js pre-population."""
    minutes = request.args.get('minutes', 5, type=int)
    history = database.get_traffic_history(minutes=minutes)
    return jsonify(history)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Returns recent anomaly alerts paginated."""
    limit = request.args.get('limit', 50, type=int)
    page = request.args.get('page', 1, type=int)
    alerts = database.get_recent_alerts(limit=limit, page=page)
    return jsonify({"alerts": alerts, "page": page, "limit": limit})

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Returns recent raw captured packets with filtering."""
    limit = request.args.get('limit', 50, type=int)
    ip_filter = request.args.get('ip', None)
    protocol_filter = request.args.get('protocol', None)
    packets = database.get_recent_packets(limit=limit, ip_filter=ip_filter, protocol_filter=protocol_filter)
    return jsonify({"packets": packets, "count": len(packets)})

# -------------------------------------------------------------------------
# WEEK 2: DYNAMIC BLOCKLIST API
# -------------------------------------------------------------------------
@app.route('/api/blocklist', methods=['GET', 'POST', 'DELETE'])
def manage_blocklist():
    """GET/POST/DELETE endpoint to manage static IP blocklist without editing config.py."""
    if request.method == 'GET':
        return jsonify({"blocklist": config.BLOCKLIST, "count": len(config.BLOCKLIST)})
        
    elif request.method == 'POST':
        data = request.get_json(silent=True) or {}
        ip = data.get('ip', '').strip()
        if not ip:
            return jsonify({"error": "Valid IP address is required"}), 400
        if ip not in config.BLOCKLIST:
            config.BLOCKLIST.append(ip)
            # Trigger instant alert if desired or just log
        return jsonify({"status": "success", "message": f"IP {ip} added to blocklist.", "blocklist": config.BLOCKLIST})
        
    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        ip = data.get('ip', '').strip()
        if not ip and request.args.get('ip'):
            ip = request.args.get('ip').strip()
        if ip in config.BLOCKLIST:
            config.BLOCKLIST.remove(ip)
            return jsonify({"status": "success", "message": f"IP {ip} removed from blocklist.", "blocklist": config.BLOCKLIST})
        return jsonify({"error": "IP not found in blocklist"}), 404

# -------------------------------------------------------------------------
# RULES ENGINE CONFIGURATION API (Dynamic threshold tuning)
# -------------------------------------------------------------------------
@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    """GET/POST endpoint to adjust rules engine sensitivity live without restarting."""
    if request.method == 'GET':
        return jsonify({
            "port_scan_threshold": config.PORT_SCAN_THRESHOLD,
            "port_scan_window_sec": config.PORT_SCAN_WINDOW_SEC,
            "traffic_spike_threshold": config.TRAFFIC_SPIKE_THRESHOLD,
            "traffic_spike_window_sec": config.TRAFFIC_SPIKE_WINDOW_SEC,
            "alert_cooldown_sec": config.ALERT_COOLDOWN_SEC
        })
    elif request.method == 'POST':
        data = request.get_json(silent=True) or {}
        if 'port_scan_threshold' in data:
            config.PORT_SCAN_THRESHOLD = max(5, int(data['port_scan_threshold']))
        if 'port_scan_window_sec' in data:
            config.PORT_SCAN_WINDOW_SEC = max(1, int(data['port_scan_window_sec']))
        if 'traffic_spike_threshold' in data:
            config.TRAFFIC_SPIKE_THRESHOLD = max(10, int(data['traffic_spike_threshold']))
        if 'traffic_spike_window_sec' in data:
            config.TRAFFIC_SPIKE_WINDOW_SEC = max(1, int(data['traffic_spike_window_sec']))
        if 'alert_cooldown_sec' in data:
            config.ALERT_COOLDOWN_SEC = max(0, int(data['alert_cooldown_sec']))
            
        return jsonify({
            "status": "success",
            "message": "SOC detection rules updated live.",
            "config": {
                "port_scan_threshold": config.PORT_SCAN_THRESHOLD,
                "port_scan_window_sec": config.PORT_SCAN_WINDOW_SEC,
                "traffic_spike_threshold": config.TRAFFIC_SPIKE_THRESHOLD,
                "traffic_spike_window_sec": config.TRAFFIC_SPIKE_WINDOW_SEC,
                "alert_cooldown_sec": config.ALERT_COOLDOWN_SEC
            }
        })

# -------------------------------------------------------------------------
# SIMULATION TRIGGER ENDPOINT (For demos and testing)
# -------------------------------------------------------------------------
@app.route('/api/simulate-alert', methods=['POST'])
def simulate_alert():
    """Triggers a simulated anomaly (port_scan, traffic_spike, blocklist_hit) for demo purposes."""
    data = request.get_json(silent=True) or {}
    anomaly_type = data.get('type', 'port_scan')
    if anomaly_type not in ['port_scan', 'traffic_spike', 'blocklist_hit']:
        return jsonify({"error": "Invalid anomaly type. Must be: port_scan, traffic_spike, or blocklist_hit"}), 400
        
    sniffer.sniffer.trigger_simulated_anomaly(anomaly_type)
    return jsonify({"status": "success", "message": f"Simulated {anomaly_type} triggered successfully."})

# -------------------------------------------------------------------------
# WEEK 3: EXPORT DAILY REPORT PDF ENDPOINT
# -------------------------------------------------------------------------
@app.route('/api/export', methods=['GET'])
def export_report():
    """Generates and downloads a clean SOC Daily Summary PDF Report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    except ImportError:
        # Fallback if reportlab not installed yet
        return jsonify({
            "error": "ReportLab package not installed. Please run `pip install reportlab` to enable PDF export.",
            "stats": database.get_traffic_stats(600),
            "severity_counts": database.get_alert_counts_by_severity(),
            "top_talkers": database.get_top_talkers(5)
        }), 501

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#0B0F14'), spaceAfter=8)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontSize=11, leading=14, textColor=colors.HexColor('#4B5563'), spaceAfter=16)
    h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor('#1E293B'), spaceBefore=12, spaceAfter=8)
    body_style = styles['Normal']
    
    # Title & Header
    story.append(Paragraph("🛡️ NetPulse SOC — Daily Network Security & Traffic Report", title_style))
    story.append(Paragraph(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S UTC')} | Monitoring Scope: Local Network / Simulation", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#38BDF8'), spaceAfter=15))
    
    # 1. Executive Summary Stats
    stats = database.get_traffic_stats(window_seconds=3600)
    story.append(Paragraph("1. Executive Summary KPIs", h2_style))
    
    summary_data = [
        ["Metric", "Value", "Status / Notes"],
        ["Total Packets Logged", f"{stats['total_packets']:,}", "Accumulated during active monitoring session"],
        ["Current Live Traffic Rate", f"{stats['packets_per_sec']} pkts/sec", "Real-time rolling average"],
        ["Active Security Alerts", f"{stats['active_alerts']:,}", "Anomalies detected across rules engine"],
        ["Primary Top Talker IP", str(stats['top_talker']), f"{stats['top_talker_count']:,} packets in recent window"]
    ]
    t_summary = Table(summary_data, colWidths=[180, 120, 240])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 15))
    
    # 2. Alerts by Severity
    story.append(Paragraph("2. Anomaly Alert Breakdown by Severity", h2_style))
    sev_counts = database.get_alert_counts_by_severity()
    sev_data = [
        ["Severity Level", "Alert Count", "Recommended Action"],
        ["HIGH (Port Scans / Blocklist)", str(sev_counts.get('high', 0)), "Immediate firewall block or subnet isolation recommended."],
        ["MEDIUM (Traffic Spikes / Floods)", str(sev_counts.get('medium', 0)), "Rate limit source IP and monitor bandwidth consumption."],
        ["LOW (Informational / Minor)", str(sev_counts.get('low', 0)), "Log and monitor for recurring patterns."]
    ]
    t_sev = Table(sev_data, colWidths=[180, 100, 260])
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#DC2626')), # Red for High
        ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#D97706')), # Amber for Medium
        ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#16A34A')), # Green for Low
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 15))
    
    # 3. Top 5 Talker IPs
    story.append(Paragraph("3. Top 5 Talker IPs (Highest Volume Sources)", h2_style))
    top_talkers = database.get_top_talkers(limit=5)
    talker_data = [["Rank", "Source IP Address", "Packet Volume Logged"]]
    for idx, t in enumerate(top_talkers, 1):
        talker_data.append([f"#{idx}", t['ip'], f"{t['count']:,} pkts"])
    if len(talker_data) == 1:
        talker_data.append(["-", "No packet data available", "0 pkts"])
        
    t_talker = Table(talker_data, colWidths=[80, 260, 200])
    t_talker.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')])
    ]))
    story.append(t_talker)
    story.append(Spacer(1, 20))
    
    # Footer note
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E2E8F0'), spaceAfter=10))
    story.append(Paragraph("Report automatically generated by NetPulse SOC rules engine. Confidential security monitoring telemetry.", ParagraphStyle('Foot', fontSize=8, textColor=colors.HexColor('#64748B'))))
    
    doc.build(story)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"NetPulse_SOC_Report_{time.strftime('%Y%m%d_%H%M%S')}.pdf",
        mimetype='application/pdf'
    )

# -------------------------------------------------------------------------
# SOCKETIO CLIENT CONNECTION EVENTS
# -------------------------------------------------------------------------
@socketio.on('connect')
def handle_connect():
    """On client connect, send initial welcome status and current alerts."""
    emit('status', {
        "connected": True, 
        "is_simulation": sniffer.sniffer.is_simulation_mode,
        "interface": config.INTERFACE or "default"
    })

@socketio.on('disconnect')
def handle_disconnect():
    pass

if __name__ == '__main__':
    print(f"\n🚀 NetPulse SOC Server launching on http://{config.HOST}:{config.PORT}...")
    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG, allow_unsafe_werkzeug=True)
