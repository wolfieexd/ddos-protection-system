import re

with open('web-app/app.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Protection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-color: #f0f4f8;
            --bg-gradient: linear-gradient(135deg, #f6f8fd 0%, #f1f5f9 100%);
            --card-bg: rgba(255, 255, 255, 0.7);
            --card-border: rgba(255, 255, 255, 0.8);
            --text-color: #1e293b;
            --text-muted: #64748b;
            --line-color: rgba(0, 0, 0, 0.08);
            --shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.07);
            --glass-blur: blur(16px);
            --btn-danger: linear-gradient(145deg, #ef4444, #dc2626);
            --btn-success: linear-gradient(145deg, #10b981, #059669);
            --input-bg: rgba(255, 255, 255, 0.9);
            --btn-text: #fff;
            
            --status-ok: #10b981;
            --status-warn: #f59e0b;
            --status-crit: #ef4444;
        }

        [data-theme="dark"] {
            --bg-color: #0f172a;
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --card-bg: rgba(30, 41, 59, 0.7);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --line-color: rgba(255, 255, 255, 0.08);
            --shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            --input-bg: rgba(15, 23, 42, 0.8);
            --btn-danger: linear-gradient(145deg, #ef4444, #b91c1c);
            --btn-success: linear-gradient(145deg, #10b981, #047857);
        }

        * { box-sizing: border-box; transition: background-color 0.3s, color 0.3s, border-color 0.3s; }
        
        body {
            margin: 0;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-gradient);
            background-attachment: fixed;
            color: var(--text-color);
            min-height: 100vh;
        }

        .shell { width: min(1460px, 96vw); margin: 20px auto; }
        
        .glass {
            background: var(--card-bg);
            backdrop-filter: var(--glass-blur);
            -webkit-backdrop-filter: var(--glass-blur);
            border: 1px solid var(--card-border);
            box-shadow: var(--shadow);
            border-radius: 16px;
        }

        .topbar {
            display: flex; justify-content: space-between; align-items: center; gap: 14px;
            padding: 16px 24px; margin-bottom: 24px;
        }
        
        .brand { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        
        .shield {
            width: 40px; height: 40px; border-radius: 12px; display: grid; place-items: center;
            background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3);
            font-size: 1.2rem;
        }
        
        .brand h1 { margin: 0; font-size: 1.6rem; font-weight: 700; }
        
        .site-chip {
            border: 1px solid var(--line-color); background: rgba(0,0,0,0.03);
            padding: 6px 12px; border-radius: 8px; font-size: 0.9rem;
        }
        [data-theme="dark"] .site-chip { background: rgba(255,255,255,0.03); }

        .actions { display: flex; gap: 16px; align-items: center; }
        
        .theme-toggle {
            background: var(--card-bg); border: 1px solid var(--card-border);
            color: var(--text-color); padding: 8px 12px; border-radius: 8px; cursor: pointer;
            font-weight: 500; font-size: 0.9rem;
        }
        .theme-toggle:hover { opacity: 0.8; }

        .status-wrap { display: flex; flex-direction: column; gap: 4px; align-items: flex-end; }
        
        .status-pill {
            display: inline-flex; align-items: center; gap: 8px; border-radius: 999px;
            border: 1px solid var(--card-border); background: var(--card-bg);
            padding: 6px 14px; font-size: 0.85rem; font-weight: 600;
        }
        
        .status-critical { color: var(--status-crit); border-color: rgba(239, 68, 68, 0.3); background: rgba(239, 68, 68, 0.1); }
        .status-degraded { color: var(--status-warn); border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.1); }
        .status-unknown { color: var(--text-muted); }
        .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--status-ok); box-shadow: 0 0 8px var(--status-ok); }
        
        .local-time { color: var(--text-muted); font-size: 0.8rem; }

        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px; margin-bottom: 24px; }
        
        .metric { padding: 20px 24px; }
        
        .metric-label { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
        .metric-value { margin-top: 12px; font-size: 2.2rem; font-weight: 700; line-height: 1; color: var(--text-color); }

        .layout-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 24px; }
        
        .card { padding: 20px 24px; }
        .card-head { font-size: 1.1rem; font-weight: 600; margin-bottom: 20px; color: var(--text-color); }
        .sub { color: var(--text-muted); font-size: 0.85rem; font-weight: 400; }

        .chart-shell, .pie-shell { position: relative; height: 320px; width: 100%; }

        .controls {
            display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 16px 24px;
            margin-bottom: 24px;
        }
        
        .ip-input {
            flex: 1; min-width: 220px; border: 1px solid var(--line-color); background: var(--input-bg);
            color: var(--text-color); border-radius: 8px; padding: 10px 14px; outline: none;
        }
        .ip-input:focus { border-color: rgba(59, 130, 246, 0.5); }
        
        .btn {
            border: none; border-radius: 8px; padding: 10px 18px; font-weight: 600; font-size: 0.9rem;
            cursor: pointer; color: var(--btn-text); transition: transform 0.2s, opacity 0.2s;
        }
        .btn:hover { transform: translateY(-1px); opacity: 0.9; }
        .btn-danger { background: var(--btn-danger); }
        .btn-success { background: var(--btn-success); }
        
        .btn-inline {
            border: 1px solid var(--line-color); background: transparent; color: var(--text-color);
            padding: 4px 12px; border-radius: 6px; font-size: 0.8rem; cursor: pointer; font-weight: 500;
        }
        .btn-inline:hover { background: rgba(0,0,0,0.05); }
        [data-theme="dark"] .btn-inline:hover { background: rgba(255,255,255,0.05); }

        .tables { display: grid; grid-template-columns: 1fr 1.5fr; gap: 20px; }
        
        .table-wrap { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 12px 16px; border-bottom: 1px solid var(--line-color); }
        th { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        td { font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }

        .badge {
            border-radius: 999px; font-size: 0.7rem; padding: 4px 10px; font-weight: 600; letter-spacing: 0.5px;
        }
        .badge-critical { background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }
        .badge-high { background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); }
        .badge-medium { background: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.2); }
        .badge-low { background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); }
        .badge-safe { background: rgba(20, 184, 166, 0.15); color: #14b8a6; border: 1px solid rgba(20, 184, 166, 0.2); }

        .footer { margin-top: 24px; text-align: center; color: var(--text-muted); font-size: 0.8rem; }

        @media (max-width: 1024px) {
            .layout-grid, .tables { grid-template-columns: 1fr; }
            .topbar { flex-direction: column; align-items: stretch; gap: 20px; }
            .brand { justify-content: center; }
            .actions { justify-content: space-between; flex-wrap: wrap; }
        }
    </style>
</head>
<body>
<div class="shell">
    <div class="topbar glass">
        <div class="brand">
            <div class="shield">&#128737;</div>
            <h1>Dashboard</h1>
            <div id="siteChip" class="site-chip">Protected Site: --</div>
        </div>
        <div class="actions">
            <button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">🌓 Dark Mode</button>
            <div class="status-wrap">
                <div id="systemStatus" class="status-pill status-unknown"><span class="dot"></span>System Status: Loading...</div>
                <div id="localTime" class="local-time">Local time: --:--:--</div>
                <a href="/admin/logout" style="color:var(--text-color);font-size:0.85rem;text-decoration:none;opacity:0.7;margin-top:4px;display:inline-block;">Logout</a>
            </div>
        </div>
    </div>

    <div class="metrics">
        <div class="metric glass"><div class="metric-label">Total Requests</div><div id="totalRequests" class="metric-value">0</div></div>
        <div class="metric glass"><div class="metric-label">Attacks Detected</div><div id="attacksDetected" class="metric-value">0</div></div>
        <div class="metric glass"><div class="metric-label">IP Blocked</div><div id="ipsBlocked" class="metric-value">0</div></div>
        <div class="metric glass"><div class="metric-label">System Uptime</div><div id="uptime" class="metric-value">0s</div></div>
    </div>

    <div class="layout-grid">
        <div class="card glass">
            <div class="card-head">Network Traffic Flow <span class="sub">(today 00:00-23:59)</span></div>
            <div class="chart-shell"><canvas id="trafficChart"></canvas></div>
        </div>
        <div class="card glass">
            <div class="card-head">Attack Types</div>
            <div class="pie-shell"><canvas id="attackTypeChart"></canvas></div>
        </div>
    </div>

    <div class="controls glass">
        <input type="text" id="ipInput" class="ip-input" placeholder="Enter IP address to block/unblock">
        <button class="btn btn-danger" onclick="blockIP()">Block IP</button>
        <button class="btn btn-success" onclick="unblockIP()">Unblock IP</button>
    </div>

    <div class="tables">
        <div class="card glass">
            <div class="card-head">Blocked IPs</div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>IP Address</th><th>Location</th><th>Action</th></tr></thead>
                    <tbody id="blockedTable"></tbody>
                </table>
            </div>
        </div>

        <div class="card glass">
            <div class="card-head">Recent Attacks</div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Time</th><th>Attack Type</th><th>Source IP</th><th>Location</th><th>Duration</th><th>Severity</th></tr></thead>
                    <tbody id="attacksTable"></tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="footerText" class="footer">Data source: /admin/stats, /admin/attacks - Updated: --</div>
</div>

<script>
// Theme toggling
function toggleTheme() {
    const body = document.body;
    const current = body.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    body.setAttribute('data-theme', next);
    localStorage.setItem('dashboardTheme', next);
    document.getElementById('themeBtn').textContent = next === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    if (trafficChart) updateChartColors(next);
}

const savedTheme = localStorage.getItem('dashboardTheme') || 'dark';
document.body.setAttribute('data-theme', savedTheme);
document.getElementById('themeBtn').textContent = savedTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';

function updateChartColors(theme) {
    if (!trafficChart || !attackTypeChart) return;
    const color = theme === 'dark' ? '#94a3b8' : '#64748b';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)';
    
    Chart.defaults.color = color;
    Chart.defaults.borderColor = gridColor;
    
    trafficChart.options.scales.x.grid.color = gridColor;
    trafficChart.options.scales.y.grid.color = gridColor;
    trafficChart.options.scales.x.ticks.color = color;
    trafficChart.options.scales.y.ticks.color = color;
    trafficChart.update();
    attackTypeChart.update();
}

let trafficChart = null;
let attackTypeChart = null;
const DAY_LABELS = Array.from({ length: 24 }, (_, h) => `${String(h).padStart(2, '0')}:00`);
const trafficData = { labels: DAY_LABELS.slice(), requests: Array(24).fill(0), attacks: Array(24).fill(0), blocked: Array(24).fill(0) };
let chartDayKey = '';
let prevTotal = 0;
let prevAttacks = 0;
let prevBlocked = 0;

function getLocalDayKey(d) {
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
}

function resetDailySeries(now) {
    chartDayKey = getLocalDayKey(now);
    trafficData.labels = DAY_LABELS.slice();
    trafficData.requests = Array(24).fill(0);
    trafficData.attacks = Array(24).fill(0);
    trafficData.blocked = Array(24).fill(0);
    if (trafficChart) {
        trafficChart.data.labels = trafficData.labels;
        trafficChart.data.datasets[0].data = trafficData.requests;
        trafficChart.data.datasets[1].data = trafficData.attacks;
        trafficChart.update();
    }
}

function ensureTodaySeries(now, total, attacks, blocked) {
    const todayKey = getLocalDayKey(now);
    if (!chartDayKey || chartDayKey !== todayKey) {
        resetDailySeries(now);
        prevTotal = total;
        prevAttacks = attacks;
        prevBlocked = blocked;
    }
}

function fmtUptime(totalSeconds) {
    const secs = Math.max(0, Math.floor(totalSeconds || 0));
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function fmtDuration(durationSeconds) {
    const total = Math.max(0, Math.floor(durationSeconds || 0));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function toStatusClass(status) {
    const st = (status || '').toLowerCase();
    if (st === 'healthy') return 'status-pill';
    if (st === 'critical') return 'status-pill status-critical';
    if (st === 'degraded') return 'status-pill status-degraded';
    return 'status-pill status-unknown';
}

function updateClock() {
    const now = new Date();
    const t = now.toLocaleTimeString();
    const el = document.getElementById('localTime');
    const footer = document.getElementById('footerText');
    if (el) el.textContent = `Local time: ${t}`;
    if (footer) footer.textContent = `Data source: /admin/stats, /admin/attacks - Updated: ${now.toLocaleDateString()} ${t}`;
}

const donutCenterText = {
    id: 'donutCenterText',
    afterDraw(chart) {
        if (chart.config.type !== 'doughnut') return;
        const total = chart.data.datasets[0].data.reduce((a, b) => a + (Number(b) || 0), 0);
        const meta = chart.getDatasetMeta(0);
        if (!meta || !meta.data || !meta.data.length) return;
        const x = meta.data[0].x;
        const y = meta.data[0].y;
        const ctx = chart.ctx;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.fillStyle = document.body.getAttribute('data-theme') === 'dark' ? '#94a3b8' : '#64748b';
        ctx.font = '600 12px "Segoe UI", sans-serif';
        ctx.fillText('TOTAL ATTACKS', x, y - 5);
        ctx.fillStyle = document.body.getAttribute('data-theme') === 'dark' ? '#f8fafc' : '#1e293b';
        ctx.font = '700 28px "Segoe UI", sans-serif';
        ctx.fillText(String(total), x, y + 24);
        ctx.restore();
    }
};
Chart.register(donutCenterText);

function initCharts() {
    if (typeof Chart === 'undefined') return false;

    const theme = document.body.getAttribute('data-theme');
    const color = theme === 'dark' ? '#94a3b8' : '#64748b';
    const gridColor = theme === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)';

    Chart.defaults.color = color;
    Chart.defaults.borderColor = gridColor;
    Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";

    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');

    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: trafficData.labels,
            datasets: [
                {
                    label: 'Requests (daily cumulative)',
                    data: trafficData.requests,
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                },
                {
                    label: 'Attacks (daily cumulative)',
                    data: trafficData.attacks,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 5
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    grid: { color: gridColor, drawBorder: false },
                    ticks: {
                        color: color,
                        autoSkip: false,
                        maxRotation: 0,
                        callback: function(value, index) {
                            return index % 2 === 0 ? this.getLabelForValue(value) : '';
                        }
                    }
                },
                y: { 
                    beginAtZero: true,
                    grid: { color: gridColor, drawBorder: false },
                    ticks: { color: color, precision: 0 }
                }
            },
            plugins: { 
                legend: { labels: { boxWidth: 12, usePointStyle: true, pointStyle: 'circle' } },
                tooltip: { backgroundColor: 'rgba(15, 23, 42, 0.9)', titleColor: '#fff', bodyColor: '#fff', padding: 12, cornerRadius: 8 }
            }
        }
    });

    attackTypeChart = new Chart(attackTypeCtx, {
        type: 'doughnut',
        data: {
            labels: ['IP Flooding', 'Distributed', 'Behavioral'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: { 
                legend: { position: 'bottom', labels: { padding: 20, boxWidth: 10, usePointStyle: true, pointStyle: 'circle' } },
                tooltip: { backgroundColor: 'rgba(15, 23, 42, 0.9)', padding: 12, cornerRadius: 8 }
            }
        }
    });

    resetDailySeries(new Date());
    return true;
}

async function fetchStats() {
    try {
        const res = await fetch('/admin/stats', { credentials: 'same-origin' });
        if (res.status === 401) {
            window.location.href = '/admin/login';
            return;
        }
        const data = await res.json();

        const total = data.detection.total_requests || 0;
        const attacksDetected = data.detection.attacks_detected || 0;
        const blockedCount = data.detection.blocked_ips_count || 0;

        document.getElementById('totalRequests').textContent = total.toLocaleString();
        document.getElementById('attacksDetected').textContent = attacksDetected.toLocaleString();
        document.getElementById('ipsBlocked').textContent = blockedCount.toLocaleString();
        document.getElementById('uptime').textContent = fmtUptime(data.uptime || 0);

        const status = (data.health.status || 'unknown').toUpperCase();
        const statusEl = document.getElementById('systemStatus');
        statusEl.className = toStatusClass(status);
        statusEl.innerHTML = '<span class="dot"></span>System Status: ' + status;

        if (trafficChart) {
            const now = new Date();
            const blockedRequests = data.detection.blocked_requests || 0;
            ensureTodaySeries(now, total, attacksDetected, blockedRequests);
            const hourIndex = now.getHours();
            const reqDelta = Math.max(0, total - prevTotal);
            const atkDelta = Math.max(0, attacksDetected - prevAttacks);
            const blkDelta = Math.max(0, blockedRequests - prevBlocked);
            trafficData.requests[hourIndex] = Math.max(trafficData.requests[hourIndex] + reqDelta, total);
            trafficData.attacks[hourIndex] = Math.max(trafficData.attacks[hourIndex] + atkDelta, attacksDetected);
            trafficData.blocked[hourIndex] = Math.max(trafficData.blocked[hourIndex] + blkDelta, blockedRequests);
            prevTotal = total;
            prevAttacks = attacksDetected;
            prevBlocked = blockedRequests;
            trafficChart.update();
        }

        if (attackTypeChart) {
            const types = data.attacks.attack_types || {};
            attackTypeChart.data.datasets[0].data = [
                types['IP_FLOODING'] || 0,
                types['DDOS_DISTRIBUTED'] || 0,
                types['BEHAVIORAL_BLOCK'] || 0
            ];
            attackTypeChart.update();
        }

        const blockedTbody = document.getElementById('blockedTable');
        const blockedDetails = data.blocked_ip_details || [];
        blockedTbody.innerHTML = blockedDetails.map(function(item) {
            const ip = item.ip || 'N/A';
            const location = item.location || 'Unknown';
            return `<tr>
                <td>${ip}</td>
                <td>${location}</td>
                <td><button class="btn-inline" onclick="unblockDirect('${ip}')">Unblock</button></td>
            </tr>`;
        }).join('') || '<tr><td colspan="3" style="opacity:0.6">No blocked IPs</td></tr>';
    } catch (err) {
        console.error('Stats fetch failed:', err);
    }
}

async function fetchAttacks() {
    try {
        const res = await fetch('/admin/attacks?limit=10', { credentials: 'same-origin' });
        if (res.status === 401) {
            window.location.href = '/admin/login';
            return;
        }
        const attacks = await res.json();
        const tbody = document.getElementById('attacksTable');

        tbody.innerHTML = attacks.reverse().map(function(a) {
            const ts = Number(a.timestamp || (Date.now() / 1000));
            const t = new Date(ts * 1000).toLocaleTimeString();
            const sev = String(a.severity || 'LOW').toUpperCase();
            const sevCls = 'badge-' + sev.toLowerCase();
            const location = a.location || 'Unknown';
            const duration = fmtDuration(a.duration_seconds || 0);
            return `<tr>
                <td>${t}</td>
                <td>${a.attack_type || 'N/A'}</td>
                <td>${a.source_ip || 'N/A'}</td>
                <td>${location}</td>
                <td>${duration}</td>
                <td><span class="badge ${sevCls}">${sev}</span></td>
            </tr>`;
        }).join('') || '<tr><td colspan="6" style="opacity:0.6">No attacks recorded</td></tr>';
    } catch (err) {
        console.error('Attack fetch failed:', err);
    }
}

async function blockIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    const res = await fetch('/admin/block/' + ip, { method: 'POST', credentials: 'same-origin' });
    if (res.status === 401) {
        window.location.href = '/admin/login';
        return;
    }
    document.getElementById('ipInput').value = '';
    fetchStats();
    fetchAttacks();
}

async function unblockIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    const res = await fetch('/admin/unblock/' + ip, { method: 'POST', credentials: 'same-origin' });
    if (res.status === 401) {
        window.location.href = '/admin/login';
        return;
    }
    document.getElementById('ipInput').value = '';
    fetchStats();
    fetchAttacks();
}

async function unblockDirect(ip) {
    const res = await fetch('/admin/unblock/' + ip, { method: 'POST', credentials: 'same-origin' });
    if (res.status === 401) {
        window.location.href = '/admin/login';
        return;
    }
    fetchStats();
    fetchAttacks();
}

function startPolling() {
    const chip = document.getElementById('siteChip');
    if (chip) chip.textContent = 'Protected Site: ' + window.location.origin;
    updateClock();
    setInterval(updateClock, 1000);
    fetchStats();
    fetchAttacks();
    setInterval(fetchStats, 2000);
    setInterval(fetchAttacks, 5000);
}

(function bootstrap() {
    if (typeof Chart !== 'undefined') {
        initCharts();
        startPolling();
        return;
    }
    const fallback = document.createElement('script');
    fallback.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js';
    fallback.onload = function () { initCharts(); startPolling(); };
    fallback.onerror = function () { startPolling(); };
    document.head.appendChild(fallback);
})();
</script>
</body>
</html>"""

start_marker = "DASHBOARD_HTML = '''<!DOCTYPE html>"
end_marker = "</html>'''\\n\\napp.config['start_time'] = time.time()"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx != -1 and end_idx != -1:
    end_idx += len("</html>'''")
    new_content = content[:start_idx] + "DASHBOARD_HTML = '''" + new_html + "'''" + content[end_idx:]
    with open('web-app/app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("Successfully patched DASHBOARD_HTML")
else:
    print("Failed to find DASHBOARD_HTML markers")
    print(start_idx, end_idx)
