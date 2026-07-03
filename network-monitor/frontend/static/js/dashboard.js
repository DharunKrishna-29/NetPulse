/*
 * NetPulse SOC — Vanilla JS Dashboard Engine
 * Connects to Flask-SocketIO, updates Chart.js live telemetry,
 * animates incoming SOC alerts, and manages static IP blocklists.
 */

// Global State
let socket = null;
let trafficChart = null;
let allLoadedPackets = [];
let activeAlertsCount = 0;
let currentSecondPacketCount = 0;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    initSocket();
    fetchInitialStats();
    fetchBlocklist();
    fetchRecentAlerts();
    fetchRecentPackets();
    fetchSocConfig();
    
    // Poll KPI stats every 3 seconds to keep averages fresh
    setInterval(fetchInitialStats, 3000);
});

/* -------------------------------------------------------------------------
   1. CHART.JS INITIALIZATION & PRE-POPULATION
------------------------------------------------------------------------- */
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    // Gradient fill under the line
    const gradient = ctx.createLinearGradient(0, 0, 0, 240);
    gradient.addColorStop(0, 'rgba(56, 189, 248, 0.4)'); // Cyan
    gradient.addColorStop(1, 'rgba(56, 189, 248, 0.0)');
    
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets / sec',
                data: [],
                borderColor: '#38BDF8',
                backgroundColor: gradient,
                borderWidth: 2,
                fill: true,
                tension: 0.3, // Smooth curve as requested
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: '#38BDF8',
                pointHoverBorderColor: '#fff',
                pointHoverBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 300 // Smooth transitioning
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#121821',
                    titleFont: { family: 'JetBrains Mono', size: 12 },
                    bodyFont: { family: 'JetBrains Mono', size: 12 },
                    borderColor: '#1F2937',
                    borderWidth: 1,
                    displayColors: false,
                    callbacks: {
                        label: (context) => `${context.parsed.y} pkts/sec`
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(31, 41, 55, 0.4)', drawBorder: false },
                    ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 10 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(31, 41, 55, 0.4)', drawBorder: false },
                    ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 5 }
                }
            }
        }
    });

    // Pre-populate from /api/traffic-history so chart doesn't start empty!
    fetch('/api/traffic-history?minutes=5')
        .then(res => res.json())
        .then(history => {
            if (Array.isArray(history) && history.length > 0) {
                const labels = history.map(h => h.label);
                const counts = history.map(h => h.count);
                trafficChart.data.labels = labels;
                trafficChart.data.datasets[0].data = counts;
                trafficChart.update('none');
            }
        })
        .catch(err => console.error("Error fetching traffic history:", err));
        
    // Start continuous regular interval ticker (1000ms strict 1-second pulse)
    setInterval(updateLiveTrafficChart, 1000);
}

/* -------------------------------------------------------------------------
   2. SOCKET.IO CONNECTION & REAL-TIME EVENT HANDLING
------------------------------------------------------------------------- */
function initSocket() {
    // Connect to same host/port
    socket = io();

    socket.on('connect', () => {
        updateStatusPill(true, "Connecting...");
    });

    socket.on('status', (data) => {
        const modeText = data.is_simulation ? "● LIVE — Simulation Mode (Sudo Needed for Raw NIC)" : `● LIVE — Monitoring ${data.interface || 'eth0'}`;
        updateStatusPill(true, modeText);
    });

    socket.on('disconnect', () => {
        updateStatusPill(false, "○ OFFLINE — Disconnected from Sniffer");
    });

    // Handle incoming packet batches (throttled ~5/sec)
    socket.on('new_packet', (data) => {
        const packets = data.packets || [];
        if (packets.length === 0) return;

        // Accumulate packet counts for our strict 1-second regular interval ticker
        currentSecondPacketCount += packets.length;

        // If packet drawer is open, append new packets live!
        const drawer = document.getElementById('packetDrawer');
        if (drawer && drawer.classList.contains('open')) {
            prependPacketsToTable(packets);
        }
    });

    // Handle immediate anomaly alert emission (The "Wow" Moment!)
    socket.on('new_alert', (alert) => {
        renderAlertRow(alert, true);
        
        // Update active alerts KPI
        activeAlertsCount++;
        updateAlertsCard(activeAlertsCount);
    });
}

function updateStatusPill(connected, text) {
    const pill = document.getElementById('statusPill');
    const label = document.getElementById('statusText');
    if (pill && label) {
        label.textContent = text;
        if (connected) {
            pill.className = "status-pill healthy";
        } else {
            pill.className = "status-pill alerting";
        }
    }
}

/* -------------------------------------------------------------------------
   3. KPI STATS & ALERTS FETCHING
------------------------------------------------------------------------- */
function fetchInitialStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(stats => {
            document.getElementById('valPacketsSec').textContent = stats.packets_per_sec || "0.0";
            document.getElementById('valTotalPackets').textContent = (stats.total_packets || 0).toLocaleString();
            document.getElementById('valTopTalker').textContent = stats.top_talker || "None";
            document.getElementById('topTalkerCount').textContent = `${(stats.top_talker_count || 0).toLocaleString()} pkts logged`;
            
            activeAlertsCount = stats.active_alerts || 0;
            updateAlertsCard(activeAlertsCount);
        })
        .catch(() => {});
}

function updateAlertsCard(count) {
    const valElem = document.getElementById('valActiveAlerts');
    const cardElem = document.getElementById('cardActiveAlerts');
    const footerElem = document.getElementById('alertsFooterText');
    const defconBadge = document.getElementById('defconBadge');
    const defconText = document.getElementById('defconText');
    
    if (valElem) valElem.textContent = count.toLocaleString();
    if (cardElem) {
        if (count > 0) {
            cardElem.classList.add('alert-active');
            if (footerElem) footerElem.textContent = "⚠️ Security threats require inspection";
            if (defconBadge) defconBadge.className = 'defcon-badge alerting';
            if (defconText) defconText.textContent = `DEFCON 2 — ${count} THREAT${count > 1 ? 'S' : ''} ACTIVE`;
        } else {
            cardElem.classList.remove('alert-active');
            if (footerElem) footerElem.textContent = "All clear — no threats detected";
            if (defconBadge) defconBadge.className = 'defcon-badge normal';
            if (defconText) defconText.textContent = 'DEFCON 5 — ALL CLEAR';
        }
    }
}

function fetchRecentAlerts() {
    fetch('/api/alerts?limit=30')
        .then(res => res.json())
        .then(data => {
            const listElem = document.getElementById('alertsList');
            const emptyElem = document.getElementById('alertsEmptyState');
            if (!listElem) return;

            const alerts = data.alerts || [];
            if (alerts.length > 0) {
                if (emptyElem) emptyElem.style.display = 'none';
                listElem.innerHTML = '';
                alerts.forEach(a => renderAlertRow(a, false));
            } else {
                if (emptyElem) emptyElem.style.display = 'flex';
            }
        })
        .catch(() => {});
}

function renderAlertRow(alert, animate = false) {
    const listElem = document.getElementById('alertsList');
    const emptyElem = document.getElementById('alertsEmptyState');
    if (!listElem) return;

    if (emptyElem) emptyElem.style.display = 'none';

    // Choose SVG Icon and badge style based on rule type and severity
    let iconSvg = '';
    let badgeClass = 'badge-low';
    let sevClass = 'sev-low';
    
    const sev = (alert.severity || 'low').toLowerCase();
    if (sev === 'high') {
        badgeClass = 'badge-high';
        sevClass = 'sev-high';
    } else if (sev === 'medium') {
        badgeClass = 'badge-medium';
        sevClass = 'sev-medium';
    }

    const type = alert.alert_type || 'ANOMALY';
    if (type === 'PORT_SCAN') {
        // Radar / scan icon
        iconSvg = `<svg class="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`;
    } else if (type === 'TRAFFIC_SPIKE') {
        // Spike line icon
        iconSvg = `<svg class="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>`;
    } else if (type === 'BLOCKLIST_HIT') {
        // Shield icon
        iconSvg = `<svg class="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
    } else {
        iconSvg = `<svg class="stat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    }

    const timeStr = new Date((alert.timestamp || Date.now()) * 1000).toLocaleTimeString();
    
    // Create Row element
    const row = document.createElement('div');
    row.className = `alert-row ${sevClass} ${animate ? 'animate-in' : ''}`;
    row.innerHTML = `
        <div class="alert-col-type">
            ${iconSvg}
            <span class="alert-type-badge ${badgeClass}">${type.replace('_', ' ')}</span>
        </div>
        <div class="alert-col-ip">
            ${alert.source_ip || 'Unknown'}
        </div>
        <div class="alert-col-details" title="${alert.details}">
            ${alert.details}
            ${alert.source_ip && alert.source_ip !== 'Unknown' ? `
                <br>
                <button class="btn-instant-block" onclick="instantBlockIp('${alert.source_ip}', event)">
                    ⚡ Block Source IP (${alert.source_ip})
                </button>
            ` : ''}
        </div>
        <div class="alert-col-time">
            ${timeStr}
        </div>
        <div class="alert-expanded-content">
            <strong>🛡️ SOC THREAT ANALYSIS & LOG DATA:</strong><br>
            • Alert ID: #${alert.id || 'N/A'} | Severity: ${sev.toUpperCase()}<br>
            • Source IP Address: ${alert.source_ip}<br>
            • Triggered Rule: ${type}<br>
            • Exact Payload Details: ${alert.details}<br>
            • Cooldown Suppressed Duplicate Events: ${alert.cooldown_suppressed_count || 0} events suppressed in 60s window<br>
            • Recommended SOC Action: ${sev === 'high' ? 'Isolate IP immediately and check firewall ACLs.' : 'Monitor traffic rate and check for DDoS amplification patterns.'}
        </div>
    `;

    // Click to expand/collapse inline
    row.addEventListener('click', () => {
        row.classList.toggle('expanded');
    });

    // Prepend to top of feed
    if (listElem.firstChild) {
        listElem.insertBefore(row, listElem.firstChild);
    } else {
        listElem.appendChild(row);
    }

    // Keep max 50 visible alerts
    while (listElem.children.length > 50) {
        listElem.removeChild(listElem.lastChild);
    }
}

function clearAlertFeed() {
    const listElem = document.getElementById('alertsList');
    const emptyElem = document.getElementById('alertsEmptyState');
    if (listElem) {
        listElem.innerHTML = '';
        if (emptyElem) {
            emptyElem.style.display = 'flex';
            listElem.appendChild(emptyElem);
        }
    }
}

/* -------------------------------------------------------------------------
   4. WEEK 2: BLOCKLIST MANAGEMENT
------------------------------------------------------------------------- */
function fetchBlocklist() {
    fetch('/api/blocklist')
        .then(res => res.json())
        .then(data => {
            renderBlocklistTags(data.blocklist || []);
        })
        .catch(() => {});
}

function renderBlocklistTags(ips) {
    const container = document.getElementById('ipTagsContainer');
    const badge = document.getElementById('blocklistCountBadge');
    if (!container) return;

    if (badge) badge.textContent = `${ips.length} IPs`;
    container.innerHTML = '';

    if (ips.length === 0) {
        container.innerHTML = `<span class="loading-text">No IPs currently blocked.</span>`;
        return;
    }

    ips.forEach(ip => {
        const tag = document.createElement('span');
        tag.className = 'ip-tag';
        tag.innerHTML = `
            <span>${ip}</span>
            <span class="tag-remove" onclick="removeBlocklistIp('${ip}', event)" title="Remove IP from blocklist">×</span>
        `;
        container.appendChild(tag);
    });
}

function addBlocklistIp(event) {
    event.preventDefault();
    const input = document.getElementById('newIpInput');
    if (!input) return;

    const ip = input.value.trim();
    if (!ip) return;

    fetch('/api/blocklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        if (data.blocklist) {
            renderBlocklistTags(data.blocklist);
            input.value = '';
            // Trigger a quick test hit against the new IP to show it works!
            triggerDemo('blocklist_hit');
        }
    })
    .catch(err => alert("Error adding IP: " + err));
}

function removeBlocklistIp(ip, event) {
    if (event) event.stopPropagation();
    
    fetch('/api/blocklist', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        if (data.blocklist) {
            renderBlocklistTags(data.blocklist);
        }
    })
    .catch(err => alert("Error removing IP: " + err));
}

/* -------------------------------------------------------------------------
   5. BOTTOM COLLAPSIBLE DRAWER & RAW PACKET TABLE
------------------------------------------------------------------------- */
function toggleDrawer() {
    const drawer = document.getElementById('packetDrawer');
    if (!drawer) return;
    
    drawer.classList.toggle('open');
    if (drawer.classList.contains('open') && allLoadedPackets.length === 0) {
        fetchRecentPackets();
    }
}

function fetchRecentPackets() {
    fetch('/api/packets?limit=50')
        .then(res => res.json())
        .then(data => {
            allLoadedPackets = data.packets || [];
            renderPacketTable(allLoadedPackets);
            updateDrawerBadge(allLoadedPackets.length);
        })
        .catch(() => {});
}

function renderPacketTable(packets) {
    const tbody = document.getElementById('packetTableBody');
    if (!tbody) return;

    if (packets.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No packet telemetry matches the filter criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = packets.map(p => {
        const timeStr = new Date((p.timestamp || Date.now()) * 1000).toLocaleTimeString();
        return `
            <tr>
                <td>#${p.id || '-'}</td>
                <td>${timeStr}</td>
                <td style="color: #38BDF8; font-weight: 600;">${p.src_ip}</td>
                <td>${p.src_port || '-'}</td>
                <td>${p.dst_ip}</td>
                <td>${p.dst_port || '-'}</td>
                <td><span class="proto-badge proto-${p.protocol}">${p.protocol}</span></td>
                <td>${p.length} B</td>
            </tr>
        `;
    }).join('');
}

function prependPacketsToTable(newPackets) {
    // Add to global archive
    allLoadedPackets = [...newPackets.reverse(), ...allLoadedPackets].slice(0, 100);
    renderPacketTable(allLoadedPackets);
    updateDrawerBadge(allLoadedPackets.length);
}

function filterPacketTable() {
    const input = document.getElementById('packetFilterInput');
    if (!input) return;

    const query = input.value.toLowerCase().trim();
    if (!query) {
        renderPacketTable(allLoadedPackets);
        return;
    }

    const filtered = allLoadedPackets.filter(p => {
        return (p.src_ip && p.src_ip.toLowerCase().includes(query)) ||
               (p.dst_ip && p.dst_ip.toLowerCase().includes(query)) ||
               (p.protocol && p.protocol.toLowerCase().includes(query)) ||
               (p.dst_port && String(p.dst_port).includes(query)) ||
               (p.src_port && String(p.src_port).includes(query));
    });
    renderPacketTable(filtered);
}

function updateDrawerBadge(count) {
    const badge = document.getElementById('drawerPacketCount');
    if (badge) badge.textContent = `${count} rows buffered`;
}

/* -------------------------------------------------------------------------
   6. DEMO ANOMALY TRIGGER
------------------------------------------------------------------------- */
function triggerDemo(type) {
    fetch('/api/simulate-alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: type })
    })
    .then(res => res.json())
    .then(data => {
        console.log("Simulated anomaly triggered:", data.message);
    })
    .catch(err => console.error("Error triggering demo:", err));
}

/* -------------------------------------------------------------------------
   7. WEEK 3: DARK / LIGHT THEME TOGGLE
------------------------------------------------------------------------- */
function toggleTheme() {
    const htmlElem = document.documentElement;
    const currentTheme = htmlElem.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    htmlElem.setAttribute('data-theme', newTheme);
    localStorage.setItem('soc_theme', newTheme);
    
    // Update Chart.js colors based on theme
    if (trafficChart) {
        const isLight = newTheme === 'light';
        trafficChart.options.scales.x.grid.color = isLight ? 'rgba(203, 213, 225, 0.6)' : 'rgba(31, 41, 55, 0.4)';
        trafficChart.options.scales.y.grid.color = isLight ? 'rgba(203, 213, 225, 0.6)' : 'rgba(31, 41, 55, 0.4)';
        trafficChart.options.scales.x.ticks.color = isLight ? '#475569' : '#64748B';
        trafficChart.options.scales.y.ticks.color = isLight ? '#475569' : '#64748B';
        trafficChart.options.plugins.tooltip.backgroundColor = isLight ? '#FFFFFF' : '#121821';
        trafficChart.options.plugins.tooltip.titleColor = isLight ? '#0F172A' : '#F8FAFC';
        trafficChart.options.plugins.tooltip.bodyColor = isLight ? '#334155' : '#E2E8F0';
        trafficChart.options.plugins.tooltip.borderColor = isLight ? '#CBD5E1' : '#1F2937';
        trafficChart.update('none');
    }
}

// Check saved theme on startup
const savedTheme = localStorage.getItem('soc_theme');
if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
}

/* -------------------------------------------------------------------------
   8. NEW: REGULAR INTERVAL LIVE TRAFFIC TICKER & SOC TUNING
------------------------------------------------------------------------- */
function updateLiveTrafficChart() {
    if (!trafficChart) return;
    
    const now = new Date();
    const timeLabel = now.toTimeString().split(' ')[0];
    
    // Calculate exact packets per second rate over the last 1000ms interval
    let rate = currentSecondPacketCount;
    
    // If rate is 0 in simulation mode or low-traffic container, provide realistic rhythmic pulse (1 to 4 pkts/sec) so chart stays alive and dynamic
    if (rate === 0 && document.getElementById('statusText')?.textContent.includes('Simulation')) {
        rate = Math.floor(Math.random() * 4) + 1;
    }
    
    trafficChart.data.labels.push(timeLabel);
    trafficChart.data.datasets[0].data.push(rate);
    
    // Keep sliding window of last 60 points (~1 minute of strict 1-second resolution)
    if (trafficChart.data.labels.length > 60) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
    }
    trafficChart.update('none');
    
    // Update live KPI rate instantly
    const valElem = document.getElementById('valPacketsSec');
    if (valElem) {
        valElem.textContent = rate.toFixed(1);
    }
    
    // Reset counter for next 1-second interval
    currentSecondPacketCount = 0;
}

function fetchSocConfig() {
    fetch('/api/config')
        .then(res => res.json())
        .then(cfg => {
            if (cfg.port_scan_threshold) {
                document.getElementById('sliderPortScan').value = cfg.port_scan_threshold;
                document.getElementById('lblPortScan').textContent = cfg.port_scan_threshold;
            }
            if (cfg.traffic_spike_threshold) {
                document.getElementById('sliderTrafficSpike').value = cfg.traffic_spike_threshold;
                document.getElementById('lblTrafficSpike').textContent = cfg.traffic_spike_threshold;
            }
            if (cfg.alert_cooldown_sec !== undefined) {
                document.getElementById('sliderCooldown').value = cfg.alert_cooldown_sec;
                document.getElementById('lblCooldown').textContent = cfg.alert_cooldown_sec;
            }
        })
        .catch(() => {});
}

function updateSliderLabel(id, val) {
    const elem = document.getElementById(id);
    if (elem) elem.textContent = val;
}

function saveSocConfig() {
    const pScan = parseInt(document.getElementById('sliderPortScan').value, 10);
    const tSpike = parseInt(document.getElementById('sliderTrafficSpike').value, 10);
    const cool = parseInt(document.getElementById('sliderCooldown').value, 10);
    
    fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            port_scan_threshold: pScan,
            traffic_spike_threshold: tSpike,
            alert_cooldown_sec: cool
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            alert(`⚡ SOC Rule Thresholds Updated Live!\n• Port Scan Sensitivity: >${pScan} ports / 10s\n• Traffic Spike Limit: >${tSpike} pkts / 5s\n• Cooldown Shield: ${cool} seconds`);
        }
    })
    .catch(err => alert("Error updating SOC rules: " + err));
}

function instantBlockIp(ip, event) {
    if (event) event.stopPropagation();
    if (!ip || ip === 'Unknown') return;
    
    fetch('/api/blocklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {
        if (data.blocklist) {
            renderBlocklistTags(data.blocklist);
            alert(`⚡ Source IP ${ip} has been instantly neutralized and added to SOC Blocklist!`);
        }
    })
    .catch(err => alert("Error blocking IP: " + err));
}

