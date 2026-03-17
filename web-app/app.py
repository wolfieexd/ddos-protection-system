"""Protected Web Application with DDoS Defense - Production Release"""
from flask import Flask, request, jsonify, render_template_string, g
from functools import wraps
import time
import sys
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detection.ddos_detector import DDoSDetector, TrafficMetrics
from mitigation.rate_limiter import RateLimiter, TrafficAnalyzer
from mitigation.notifier import AttackNotifier
from recovery.health_monitor import HealthMonitor

app = Flask(__name__)

# Admin API key (set via environment variable for security)
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'change-me-in-production')

# Initialize all core components (configurable via environment variables)
detector = DDoSDetector(
    time_window=int(os.environ.get('TIME_WINDOW', 60)),
    requests_threshold=int(os.environ.get('DETECTION_THRESHOLD', 50)),
    unique_ip_threshold=int(os.environ.get('UNIQUE_IP_THRESHOLD', 50))
)
rate_limiter = RateLimiter(
    default_rate=int(os.environ.get('RATE_LIMIT', 100)),
    default_burst=int(os.environ.get('BURST_SIZE', 20))
)
traffic_analyzer = TrafficAnalyzer()
health_monitor = HealthMonitor(
    failure_threshold=int(os.environ.get('FAILURE_THRESHOLD', 3)),
    recovery_time=int(os.environ.get('RECOVERY_TIME', 300))
)
notifier = AttackNotifier(
    webhook_url=os.environ.get('WEBHOOK_URL'),
    cooldown=int(os.environ.get('ALERT_COOLDOWN', 60))
)
health_monitor.register_service('web_app')

# Per-endpoint rate limit profiles: path_prefix -> (rate_per_min, burst)
ENDPOINT_RATE_PROFILES = {
    '/login': (10, 5),
    '/admin': (30, 10),
    '/api': (200, 50),
}


def require_admin(f):
    """Decorator to require API key authentication for admin endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = (request.headers.get('X-API-Key')
                   or request.args.get('api_key'))
        if api_key != ADMIN_API_KEY:
            return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
        return f(*args, **kwargs)
    return decorated


def get_client_ip():
    """Get real client IP, even behind Nginx reverse proxy."""
    return (request.headers.get('X-Real-IP')
            or request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
            or request.remote_addr
            or 'unknown')


def get_rate_profile(path):
    """Get rate limit profile for the given endpoint path."""
    for prefix, profile in ENDPOINT_RATE_PROFILES.items():
        if path.startswith(prefix):
            return profile
    return None


@app.before_request
def ddos_protection():
    g.start_time = time.time()
    client_ip = get_client_ip()

    # Allow health check endpoint to bypass all DDoS checks
    if request.path == '/health':
        return None

    # Allow admin endpoints with valid API key to bypass DDoS checks
    if request.path.startswith('/admin'):
        api_key = (request.headers.get('X-API-Key')
                   or request.args.get('api_key'))
        if api_key == ADMIN_API_KEY:
            return None

    # Check if IP is blocked by detector
    if detector.is_blocked(client_ip):
        logger.info("Blocked request from %s", client_ip)
        return jsonify({'error': 'IP blocked', 'code': 'IP_BLOCKED'}), 403

    # Check rate limit (per-endpoint profiles override global)
    profile = get_rate_profile(request.path)
    if profile:
        allowed, info = rate_limiter.check_rate_limit(
            f"{client_ip}:{request.path}", rate=profile[0], burst=profile[1]
        )
    else:
        allowed, info = rate_limiter.check_rate_limit(client_ip)

    if not allowed:
        logger.info("Rate limited %s (retry_after=%s)", client_ip, info.get('retry_after'))
        response = jsonify({
            'error': 'Rate limit exceeded',
            'code': 'RATE_LIMITED',
            'retry_after': info.get('retry_after', 1)
        })
        response.status_code = 429
        response.headers['Retry-After'] = str(info.get('retry_after', 1))
        return response


@app.after_request
def analyze_traffic(response):
    response_time = time.time() - g.get('start_time', time.time())
    client_ip = get_client_ip()

    # Skip traffic analysis for health checks and authenticated admin requests
    if request.path == '/health':
        return response
    if request.path.startswith('/admin'):
        api_key = (request.headers.get('X-API-Key')
                   or request.args.get('api_key'))
        if api_key == ADMIN_API_KEY:
            return response

    # Feed traffic to detection engine
    metric = TrafficMetrics(
        timestamp=time.time(),
        ip_address=client_ip,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        endpoint=request.path,
        method=request.method,
        status_code=response.status_code,
        response_time=response_time,
        payload_size=response.content_length or 0
    )
    is_attack, signature = detector.analyze_traffic(metric)

    if is_attack and signature:
        logger.warning("Attack detected: %s from %s (confidence=%.2f)",
                       signature.attack_type, client_ip, signature.confidence)
        health_monitor.report_failure('web_app')
        notifier.notify(
            attack_type=signature.attack_type,
            source_ip=client_ip,
            confidence=signature.confidence,
            severity=signature.severity,
            details=f"endpoint={request.path}"
        )
    else:
        health_monitor.report_success('web_app')

    # Feed to traffic analyzer for risk scoring
    risk = traffic_analyzer.analyze_request(
        ip=client_ip, endpoint=request.path, method=request.method,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        status_code=response.status_code, response_time=response_time
    )

    if risk['recommendation'] == 'BLOCK_IMMEDIATELY' and not detector.is_blocked(client_ip):
        detector.blocked_ips.add(client_ip)
        logger.warning("TrafficAnalyzer blocked IP %s (score=%.1f, risk=%s)",
                       client_ip, risk['suspicious_score'], risk['risk_level'])
        notifier.notify(
            attack_type='BEHAVIORAL_BLOCK',
            source_ip=client_ip,
            confidence=risk['suspicious_score'] / 100.0,
            severity='CRITICAL',
            details=f"risk={risk['risk_level']}"
        )

    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


# ==================== Public Routes ====================

@app.route('/')
def home():
    return render_template_string(LANDING_PAGE_HTML)


@app.route('/health')
def health():
    overall = health_monitor.get_overall_health()
    return jsonify({
        'status': overall['status'].lower(),
        'timestamp': time.time(),
        'services': overall.get('services', {})
    })


# ==================== Admin Routes (API Key Protected) ====================

@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    return render_template_string(DASHBOARD_HTML, api_key=request.args.get('api_key', ''))


@app.route('/admin/stats')
@require_admin
def admin_stats():
    # Log requester info and headers for debugging frontend polling issues
    try:
        logger.info("Admin stats requested from %s headers=%s",
                    request.remote_addr, dict(request.headers))
    except Exception:
        logger.exception("Failed to log admin_stats request headers")

    return jsonify({
        'detection': detector.get_statistics(),
        'rate_limiter': rate_limiter.get_stats(),
        'traffic_analyzer': traffic_analyzer.get_stats(),
        'health': health_monitor.get_overall_health(),
        'attacks': notifier.get_attack_summary(),
        'blocked_ips': list(detector.blocked_ips),
        'uptime': time.time() - app.config.get('start_time', time.time())
    })


@app.route('/admin/attacks')
@require_admin
def admin_attacks():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(notifier.get_recent_attacks(limit))


@app.route('/admin/block/<ip>', methods=['POST'])
@require_admin
def admin_block_ip(ip):
    detector.blocked_ips.add(ip)
    logger.info("Admin manually blocked IP: %s", ip)
    return jsonify({'status': 'blocked', 'ip': ip})


@app.route('/admin/unblock/<ip>', methods=['POST'])
@require_admin
def admin_unblock_ip(ip):
    if detector.unblock_ip(ip):
        return jsonify({'status': 'unblocked', 'ip': ip})
    return jsonify({'status': 'not_found', 'ip': ip}), 404


@app.route('/admin/blocked')
@require_admin
def admin_blocked_list():
    return jsonify({'blocked_ips': list(detector.blocked_ips),
                    'count': len(detector.blocked_ips)})


@app.route('/admin/snapshot')
@require_admin
def admin_snapshot():
    """Render a server-side snapshot of current stats suitable for screenshots."""
    stats = {
        'detection': detector.get_statistics(),
        'rate_limiter': rate_limiter.get_stats(),
        'traffic_analyzer': traffic_analyzer.get_stats(),
        'health': health_monitor.get_overall_health(),
        'attacks': notifier.get_attack_summary(),
        'blocked_ips': list(detector.blocked_ips),
        'uptime': time.time() - app.config.get('start_time', time.time())
    }
    recent = notifier.get_recent_attacks(20)
    # Format timestamps for readability
    for a in recent:
        try:
            a_ts = float(a.get('timestamp', time.time()))
            a['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a_ts))
        except Exception:
            a['time_str'] = str(a.get('timestamp'))

    # Pretty uptime
    u = int(stats.get('uptime', 0))
    h = u // 3600
    m = (u % 3600) // 60
    s = u % 60
    if h > 0:
        uptime_str = f"{h}h {m}m {s}s"
    elif m > 0:
        uptime_str = f"{m}m {s}s"
    else:
        uptime_str = f"{s}s"

    return render_template_string(SNAPSHOT_HTML, stats=stats, recent=recent, uptime_str=uptime_str)


@app.route('/admin/snapshot_detailed')
@require_admin
def admin_snapshot_detailed():
    stats = {
        'detection': detector.get_statistics(),
        'rate_limiter': rate_limiter.get_stats(),
        'traffic_analyzer': traffic_analyzer.get_stats(),
        'health': health_monitor.get_overall_health(),
        'attacks': notifier.get_attack_summary(),
        'blocked_ips': list(detector.blocked_ips),
        'uptime': time.time() - app.config.get('start_time', time.time())
    }

    recent_attacks = notifier.get_recent_attacks(50)
    for a in recent_attacks:
        try:
            a_ts = float(a.get('timestamp', time.time()))
            a['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a_ts))
        except Exception:
            a['time_str'] = str(a.get('timestamp'))

    # Build IP metrics from detector.ip_request_count
    ip_metrics = []
    for ip, dq in detector.ip_request_count.items():
        cnt = len(dq)
        last_seen = ''
        if cnt:
            try:
                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(dq[-1]))
            except Exception:
                last_seen = str(dq[-1])
        ip_metrics.append({'ip': ip, 'count': cnt, 'last_seen': last_seen})
    # sort by count desc
    ip_metrics = sorted(ip_metrics, key=lambda x: x['count'], reverse=True)[:50]

    # sample recent requests from the traffic buffer
    recent_requests = []
    for m in list(detector.traffic_buffer)[-100:]:
        try:
            recent_requests.append({
                'time_str': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(m.timestamp)),
                'ip': m.ip_address,
                'method': m.method,
                'endpoint': m.endpoint,
                'status': m.status_code
            })
        except Exception:
            continue

    # pretty uptime
    u = int(stats.get('uptime', 0))
    h = u // 3600
    m = (u % 3600) // 60
    s = u % 60
    if h > 0:
        uptime_str = f"{h}h {m}m {s}s"
    elif m > 0:
        uptime_str = f"{m}m {s}s"
    else:
        uptime_str = f"{s}s"

    return render_template_string(SNAPSHOT_DETAILED_HTML,
                                  stats=stats,
                                  recent_attacks=recent_attacks,
                                  ip_metrics=ip_metrics,
                                  recent_requests=recent_requests,
                                  uptime_str=uptime_str)


# ==================== HTML Templates ====================

LANDING_PAGE_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DDoS Protected App</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea, #764ba2);
               display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
        .container { background: #fff; padding: 40px; border-radius: 20px; text-align: center;
                     box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 500px; }
        h1 { color: #667eea; margin-bottom: 10px; }
        .shield { font-size: 4em; margin-bottom: 20px; }
        p { color: #555; line-height: 1.6; }
        .status { margin-top: 20px; padding: 10px; background: #e8f5e9; border-radius: 8px;
                  color: #2e7d32; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">&#128737;</div>
        <h1>DDoS Protected Application</h1>
        <p>Your connection is protected by our multi-layered DDoS mitigation system.</p>
        <div class="status">Status: Protected</div>
    </div>
</body>
</html>'''


SNAPSHOT_DETAILED_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Detailed Snapshot - DDoS Dashboard</title>
    <style>
        body{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;color:#0b1220;padding:20px}
        .header{display:flex;justify-content:space-between;align-items:center}
        .card{display:inline-block;padding:16px;border-radius:8px;background:#fff;margin:8px;border:1px solid #e1e4e8}
        .grid{display:flex;gap:12px;margin-top:12px;flex-wrap:wrap}
        table{width:100%;border-collapse:collapse;margin-top:12px}
        th,td{padding:8px;border-bottom:1px solid #e9ecef;text-align:left;font-size:13px}
        h2{margin:0}
        .col{width:48%}
    </style>
</head>
<body>
    <div class="header">
        <h2>Detailed DDoS Snapshot</h2>
        <div>Uptime: {{ uptime_str }}</div>
    </div>
    <div class="grid">
        <div class="card"><strong>Total Requests</strong><div style="font-size:24px">{{ stats.detection.total_requests }}</div></div>
        <div class="card"><strong>Attacks Detected</strong><div style="font-size:24px">{{ stats.detection.attacks_detected }}</div></div>
        <div class="card"><strong>IPs Blocked</strong><div style="font-size:24px">{{ stats.detection.blocked_ips_count }}</div></div>
        <div class="card"><strong>Traffic Buffer</strong><div style="font-size:20px">{{ stats.detection.traffic_buffer_size }} samples</div></div>
    </div>

    <h3 style="margin-top:18px">Top Attackers</h3>
    <table>
        <thead><tr><th>IP</th><th>Count</th></tr></thead>
        <tbody>
            {% if stats.attacks.top_attackers %}
                {% for ip, cnt in stats.attacks.top_attackers.items() %}
                    <tr><td>{{ ip }}</td><td>{{ cnt }}</td></tr>
                {% endfor %}
            {% else %}
                <tr><td colspan="2">No attackers recorded</td></tr>
            {% endif %}
        </tbody>
    </table>

    <div style="display:flex;gap:12px;margin-top:18px;align-items:flex-start">
        <div class="col">
            <h3>Recent Attacks</h3>
            <table>
                <thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Severity</th><th>Confidence</th></tr></thead>
                <tbody>
                    {% if recent_attacks %}
                        {% for a in recent_attacks %}
                            <tr>
                                <td>{{ a.time_str }}</td>
                                <td>{{ a.attack_type }}</td>
                                <td>{{ a.source_ip }}</td>
                                <td>{{ a.severity }}</td>
                                <td>{{ '%.2f'|format(a.confidence) }}</td>
                            </tr>
                        {% endfor %}
                    {% else %}
                        <tr><td colspan="5">No recent attacks</td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
        <div class="col">
            <h3>Per-IP Metrics (recent window)</h3>
            <table>
                <thead><tr><th>IP</th><th>Requests</th><th>Last Seen</th></tr></thead>
                <tbody>
                    {% if ip_metrics %}
                        {% for row in ip_metrics %}
                            <tr><td>{{ row.ip }}</td><td>{{ row.count }}</td><td>{{ row.last_seen }}</td></tr>
                        {% endfor %}
                    {% else %}
                        <tr><td colspan="3">No IP metrics</td></tr>
                    {% endif %}
                </tbody>
            </table>
        </div>
    </div>

    <h3 style="margin-top:18px">Recent Requests (sample)</h3>
    <table>
        <thead><tr><th>Time</th><th>IP</th><th>Method</th><th>Endpoint</th><th>Status</th></tr></thead>
        <tbody>
            {% if recent_requests %}
                {% for r in recent_requests %}
                    <tr><td>{{ r.time_str }}</td><td>{{ r.ip }}</td><td>{{ r.method }}</td><td>{{ r.endpoint }}</td><td>{{ r.status }}</td></tr>
                {% endfor %}
            {% else %}
                <tr><td colspan="5">No recent requests</td></tr>
            {% endif %}
        </tbody>
    </table>
</body>
</html>'''

DASHBOARD_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DDoS Protection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script>
    if (typeof Chart === 'undefined') {
const API_KEY = {{ api_key|tojson }};
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js';
        document.head.appendChild(s);
    }
    </script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1923; color: #e0e0e0; }
        .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px 30px;
                  display: flex; justify-content: space-between; align-items: center;
                  border-bottom: 2px solid #0f3460; }
        .header h1 { font-size: 1.4em; color: #00d4ff; }
        .status-badge { padding: 6px 16px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }
        .status-healthy { background: #00c853; color: #000; }
        .status-critical { background: #ff1744; color: #fff; animation: pulse 1s infinite; }
        .status-degraded { background: #ff9100; color: #000; }
        .status-unknown { background: #607d8b; color: #fff; }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 20px 30px; }
        .card { background: #1a2332; border-radius: 12px; padding: 20px; border: 1px solid #2a3a4a; }
        .card h3 { color: #8899aa; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
        .card .value { font-size: 2em; font-weight: 700; }
        .card .value.green { color: #00c853; }
        .card .value.red { color: #ff1744; }
        .card .value.blue { color: #00d4ff; }
        .card .value.orange { color: #ff9100; }
        .charts { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; padding: 0 30px 20px; }
        .chart-card { background: #1a2332; border-radius: 12px; padding: 20px; border: 1px solid #2a3a4a; }
        .chart-card h3 { color: #8899aa; font-size: 0.85em; text-transform: uppercase; margin-bottom: 12px; }
        .tables { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 0 30px 20px; }
        .table-card { background: #1a2332; border-radius: 12px; padding: 20px; border: 1px solid #2a3a4a; }
        .table-card h3 { color: #8899aa; font-size: 0.85em; text-transform: uppercase; margin-bottom: 12px; }
        table { width: 100%; border-collapse: collapse; }
        th { text-align: left; color: #667; font-size: 0.75em; text-transform: uppercase; padding: 8px 4px;
             border-bottom: 1px solid #2a3a4a; }
        td { padding: 8px 4px; font-size: 0.9em; border-bottom: 1px solid #1e2d3d; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; }
        .badge-critical { background: #ff1744; color: #fff; }
        .badge-high { background: #ff5722; color: #fff; }
        .badge-medium { background: #ff9100; color: #000; }
        .badge-low { background: #ffc107; color: #000; }
        .badge-safe { background: #00c853; color: #000; }
        .btn { padding: 4px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8em; }
        .btn-danger { background: #ff1744; color: #fff; }
        .btn-success { background: #00c853; color: #000; }
        .btn:hover { opacity: 0.8; }
        .ip-input { background: #0f1923; border: 1px solid #2a3a4a; color: #e0e0e0; padding: 6px 12px;
                    border-radius: 4px; margin-right: 8px; }
        .controls { padding: 0 30px 20px; display: flex; gap: 12px; align-items: center; }
        .live-dot { width: 8px; height: 8px; background: #00c853; border-radius: 50%; display: inline-block;
                    animation: pulse 2s infinite; margin-right: 6px; }
        .footer { text-align: center; padding: 16px; color: #445; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>&#128737; DDoS Protection Dashboard</h1>
        <div>
            <span class="live-dot"></span>
            <span style="color:#00c853;font-size:0.85em;margin-right:16px;">LIVE</span>
            <span id="systemStatus" class="status-badge status-unknown">Loading...</span>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Total Requests</h3>
            <div id="totalRequests" class="value blue">0</div>
        </div>
        <div class="card">
            <h3>Attacks Detected</h3>
            <div id="attacksDetected" class="value red">0</div>
        </div>
        <div class="card">
            <h3>IPs Blocked</h3>
            <div id="ipsBlocked" class="value orange">0</div>
        </div>
        <div class="card">
            <h3>System Uptime</h3>
            <div id="uptime" class="value green">0s</div>
        </div>
    </div>

    <div class="charts">
        <div class="chart-card">
            <h3>Traffic Over Time</h3>
            <canvas id="trafficChart" height="80"></canvas>
        </div>
        <div class="chart-card">
            <h3>Attack Types</h3>
            <canvas id="attackTypeChart" height="160"></canvas>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="ipInput" class="ip-input" placeholder="Enter IP address...">
        <button class="btn btn-danger" onclick="blockIP()">Block IP</button>
        <button class="btn btn-success" onclick="unblockIP()">Unblock IP</button>
    </div>

    <div class="tables">
        <div class="table-card">
            <h3>Blocked IPs</h3>
            <table>
                <thead><tr><th>IP Address</th><th>Action</th></tr></thead>
                <tbody id="blockedTable"></tbody>
            </table>
        </div>
        <div class="table-card">
            <h3>Recent Attacks</h3>
            <table>
                <thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Severity</th></tr></thead>
                <tbody id="attacksTable"></tbody>
            </table>
        </div>
    </div>

    <div class="footer">DDoS Protection System &mdash; Real-time Monitoring Dashboard</div>

<script>
const API_KEY = '{{ api_key }}';
const headers = {'X-API-Key': API_KEY};

let trafficChart = null, attackTypeChart = null;
const trafficData = { labels: [], requests: [], attacks: [], blocked: [] };

function initCharts() {
    if (typeof Chart === 'undefined') return false;
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');

    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: trafficData.labels,
            datasets: [
                { label: 'Total Requests', data: trafficData.requests, borderColor: '#00d4ff',
                  backgroundColor: 'rgba(0,212,255,0.1)', fill: true, tension: 0.4 },
                { label: 'Attacks', data: trafficData.attacks, borderColor: '#ff1744',
                  backgroundColor: 'rgba(255,23,68,0.1)', fill: true, tension: 0.4 },
                { label: 'Blocked', data: trafficData.blocked, borderColor: '#ff9100',
                  backgroundColor: 'rgba(255,145,0,0.1)', fill: true, tension: 0.4 }
            ]
        },
        options: {
            responsive: true,
            scales: {
                x: { grid: { color: '#1e2d3d' }, ticks: { color: '#667' } },
                y: { grid: { color: '#1e2d3d' }, ticks: { color: '#667' }, beginAtZero: true }
            },
            plugins: { legend: { labels: { color: '#8899aa' } } }
        }
    });

    attackTypeChart = new Chart(attackTypeCtx, {
        type: 'doughnut',
        data: {
            labels: ['IP Flooding', 'Distributed', 'Behavioral'],
            datasets: [{ data: [0, 0, 0], backgroundColor: ['#ff1744', '#ff9100', '#ffc107'], borderWidth: 0 }]
        },
        options: {
            responsive: true,
            plugins: { legend: { position: 'bottom', labels: { color: '#8899aa', padding: 12 } } }
        }
    });
    return true;
}

let prevTotal = 0, prevAttacks = 0, prevBlocked = 0;

async function fetchStats() {
    try {
        const res = await fetch('/admin/stats', { headers });
        if (res.status === 401) {
            document.body.innerHTML = '<div style="color:#ff1744;text-align:center;padding:100px;font-size:1.5em;">Unauthorized: Invalid API Key</div>';
            return;
        }
        const data = await res.json();

        const total = data.detection.total_requests;
        document.getElementById('totalRequests').textContent = total.toLocaleString();
        document.getElementById('attacksDetected').textContent = data.detection.attacks_detected.toLocaleString();
        document.getElementById('ipsBlocked').textContent = data.detection.blocked_ips_count;
        const secs = Math.floor(data.uptime);
        const h = Math.floor(secs/3600), m = Math.floor((secs%3600)/60), s = secs%60;
        document.getElementById('uptime').textContent = h > 0 ? h+'h '+m+'m' : m > 0 ? m+'m '+s+'s' : s+'s';

        const statusEl = document.getElementById('systemStatus');
        const st = data.health.status;
        statusEl.textContent = st.toUpperCase();
        statusEl.className = 'status-badge status-' + st.toLowerCase();

        if (trafficChart) {
            const now = new Date().toLocaleTimeString();
            trafficData.labels.push(now);
            trafficData.requests.push(total - prevTotal);
            trafficData.attacks.push(data.detection.attacks_detected - prevAttacks);
            trafficData.blocked.push(data.detection.blocked_requests - prevBlocked);
            prevTotal = total; prevAttacks = data.detection.attacks_detected; prevBlocked = data.detection.blocked_requests;
            if (trafficData.labels.length > 30) {
                trafficData.labels.shift(); trafficData.requests.shift();
                trafficData.attacks.shift(); trafficData.blocked.shift();
            }
            trafficChart.update();
        }

        if (attackTypeChart) {
            const types = data.attacks.attack_types || {};
            attackTypeChart.data.datasets[0].data = [
                types['IP_FLOODING'] || 0, types['DDOS_DISTRIBUTED'] || 0, types['BEHAVIORAL_BLOCK'] || 0
            ];
            attackTypeChart.update();
        }

        const blockedTbody = document.getElementById('blockedTable');
        blockedTbody.innerHTML = (data.blocked_ips || []).map(function(ip) {
            return '<tr><td>'+ip+'</td><td><button class="btn btn-success" onclick="unblockDirect(\''+ip+'\')">Unblock</button></td></tr>';
        }).join('') || '<tr><td colspan="2" style="color:#445;">No blocked IPs</td></tr>';
    } catch(e) { console.error('Fetch error:', e); }
}

async function fetchAttacks() {
    try {
        const res = await fetch('/admin/attacks?limit=10', { headers });
        if (res.status === 401) return;
        const attacks = await res.json();
        const tbody = document.getElementById('attacksTable');
        tbody.innerHTML = attacks.reverse().map(function(a) {
            var t = new Date(a.timestamp * 1000).toLocaleTimeString();
            var sev = a.severity.toLowerCase();
            return '<tr><td>'+t+'</td><td>'+a.attack_type+'</td><td>'+a.source_ip+'</td>'
                 + '<td><span class="badge badge-'+sev+'">'+a.severity+'</span></td></tr>';
        }).join('') || '<tr><td colspan="4" style="color:#445;">No attacks recorded</td></tr>';
    } catch(e) {}
}

async function blockIP() {
    var ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    await fetch('/admin/block/'+ip, { method: 'POST', headers: headers });
    document.getElementById('ipInput').value = '';
    fetchStats();
}

async function unblockIP() {
    var ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    await fetch('/admin/unblock/'+ip, { method: 'POST', headers: headers });
    document.getElementById('ipInput').value = '';
    fetchStats();
}

async function unblockDirect(ip) {
    await fetch('/admin/unblock/'+ip, { method: 'POST', headers: headers });
    fetchStats();
}

// Initialize charts when ready, then start polling
function startDashboard() {
    initCharts();
    fetchStats(); fetchAttacks();
    setInterval(fetchStats, 2000);
    setInterval(fetchAttacks, 5000);
}

if (typeof Chart !== 'undefined') {
    startDashboard();
} else {
    // Wait for fallback CDN to load
    var checkChart = setInterval(function() {
        if (typeof Chart !== 'undefined') {
            clearInterval(checkChart);
            startDashboard();
        }
    }, 500);
    // Start data polling without charts after 3s if CDN unreachable
    setTimeout(function() {
        if (!trafficChart) {
            clearInterval(checkChart);
            fetchStats(); fetchAttacks();
            setInterval(fetchStats, 2000);
            setInterval(fetchAttacks, 5000);
        }
    }, 3000);
}
</script>
</body>
</html>'''

app.config['start_time'] = time.time()


SNAPSHOT_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Snapshot - DDoS Dashboard</title>
    <style>
        body{font-family:Arial,Helvetica,sans-serif;background:#f6f8fa;color:#0b1220;padding:20px}
        .header{display:flex;justify-content:space-between;align-items:center}
        .card{display:inline-block;padding:16px;border-radius:8px;background:#fff;margin:8px;border:1px solid #e1e4e8}
        .grid{display:flex;gap:12px;margin-top:12px}
        table{width:100%;border-collapse:collapse;margin-top:12px}
        th,td{padding:8px;border-bottom:1px solid #e9ecef;text-align:left;font-size:14px}
        h2{margin:0}
    </style>
</head>
<body>
    <div class="header">
        <h2>DDoS Protection Snapshot</h2>
        <div>Uptime: {{ uptime_str }}</div>
    </div>
    <div class="grid">
        <div class="card"><strong>Total Requests</strong><div style="font-size:24px">{{ stats.detection.total_requests }}</div></div>
        <div class="card"><strong>Attacks Detected</strong><div style="font-size:24px">{{ stats.detection.attacks_detected }}</div></div>
        <div class="card"><strong>IPs Blocked</strong><div style="font-size:24px">{{ stats.detection.blocked_ips_count }}</div></div>
        <div class="card"><strong>Blocked List</strong><div style="font-size:14px">{{ stats.blocked_ips|length }} entries</div></div>
    </div>

    <h3 style="margin-top:18px">Blocked IPs</h3>
    <table>
        <thead><tr><th>IP</th></tr></thead>
        <tbody>
            {% if stats.blocked_ips %}
                {% for ip in stats.blocked_ips %}
                    <tr><td>{{ ip }}</td></tr>
                {% endfor %}
            {% else %}
                <tr><td>No blocked IPs</td></tr>
            {% endif %}
        </tbody>
    </table>

    <h3 style="margin-top:18px">Recent Attacks</h3>
    <table>
        <thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Severity</th></tr></thead>
        <tbody>
            {% if recent %}
                {% for a in recent %}
                    <tr>
                        <td>{{ a.time_str }}</td>
                        <td>{{ a.attack_type }}</td>
                        <td>{{ a.source_ip }}</td>
                        <td>{{ a.severity }}</td>
                    </tr>
                {% endfor %}
            {% else %}
                <tr><td colspan="4">No recent attacks</td></tr>
            {% endif %}
        </tbody>
    </table>
</body>
</html>'''

if __name__ == '__main__':
    logger.info("Starting DDoS Protected Web Application on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
