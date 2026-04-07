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


def classify_ip_location(ip: str) -> str:
    """Resolve location from notifier service (GeoIP-aware with safe fallback)."""
    return notifier.classify_ip_location(ip)


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
    # Restrict detailed health info: allow only local requests or requests with admin API key
    api_key = (request.headers.get('X-API-Key') or request.args.get('api_key'))
    remote = request.remote_addr
    overall = health_monitor.get_overall_health()
    if api_key == ADMIN_API_KEY or remote in ('127.0.0.1', '::1'):
        return jsonify({
            'status': overall['status'].lower(),
            'timestamp': time.time(),
            'services': overall.get('services', {})
        })
    # Non-local callers get minimal information to avoid leaking internal state
    return jsonify({'status': overall['status'].lower(), 'timestamp': time.time()}), 200


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

    blocked_ips = list(detector.blocked_ips)
    blocked_details = [
        {'ip': ip, 'location': classify_ip_location(ip)}
        for ip in blocked_ips
    ]

    return jsonify({
        'detection': detector.get_statistics(),
        'rate_limiter': rate_limiter.get_stats(),
        'traffic_analyzer': traffic_analyzer.get_stats(),
        'health': health_monitor.get_overall_health(),
        'attacks': notifier.get_attack_summary(),
        'blocked_ips': blocked_ips,
        'blocked_ip_details': blocked_details,
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
    blocked_ips = list(detector.blocked_ips)
    return jsonify({
        'blocked_ips': blocked_ips,
        'blocked_ip_details': [
            {'ip': ip, 'location': classify_ip_location(ip)}
            for ip in blocked_ips
        ],
        'count': len(blocked_ips)
    })


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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Protection Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --line: rgba(108, 163, 255, 0.24);
            --text: #d9e8ff;
            --muted: #8ba8d8;
            --ok: #25cc77;
            --card: rgba(12, 27, 50, 0.78);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            color: var(--text);
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background:
                radial-gradient(75% 110% at 16% 0%, rgba(33, 96, 193, 0.38), transparent 57%),
                radial-gradient(52% 80% at 90% 8%, rgba(7, 66, 165, 0.3), transparent 60%),
                linear-gradient(180deg, #060b13 0%, #081426 100%);
            min-height: 100vh;
        }
        .shell { width: min(1460px, 96vw); margin: 14px auto 24px; }
        .topbar {
            display: flex; justify-content: space-between; align-items: center; gap: 14px;
            padding: 12px 16px; border: 1px solid var(--line); border-radius: 16px;
            background: rgba(8, 21, 40, 0.78);
            box-shadow: 0 10px 26px rgba(0,0,0,0.36), inset 0 0 28px rgba(66, 148, 255, 0.08);
            backdrop-filter: blur(10px);
        }
        .brand { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .shield {
            width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
            background: linear-gradient(145deg, rgba(63, 134, 251, 0.36), rgba(63, 134, 251, 0.1));
            border: 1px solid rgba(102, 169, 255, 0.45);
        }
        .brand h1 { margin: 0; font-size: 2.05rem; }
        .site-chip {
            border: 1px solid var(--line); background: rgba(18, 40, 73, 0.82); color: #d5e5ff;
            padding: 8px 12px; border-radius: 10px; font-size: 0.95rem; white-space: nowrap;
        }
        .status-wrap { display: flex; flex-direction: column; gap: 2px; align-items: flex-end; }
        .status-pill {
            display: inline-flex; align-items: center; gap: 8px; border-radius: 999px;
            border: 1px solid rgba(57, 203, 138, 0.42); background: rgba(9, 36, 31, 0.72);
            padding: 8px 14px; font-size: 0.98rem; font-weight: 600;
        }
        .status-critical { color: #ffb8c5; border-color: rgba(255, 79, 111, 0.44); background: rgba(44, 15, 22, 0.76); }
        .status-degraded { color: #ffe2b0; border-color: rgba(255, 176, 32, 0.42); background: rgba(45, 30, 11, 0.76); }
        .status-unknown { color: #bfd0ef; border-color: rgba(118, 145, 189, 0.42); background: rgba(18, 29, 47, 0.76); }
        .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--ok); box-shadow: 0 0 10px var(--ok); }
        .local-time { color: var(--muted); font-size: 0.88rem; padding-right: 6px; }

        .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 14px; }
        .metric {
            border: 1px solid var(--line); border-radius: 12px;
            background: linear-gradient(120deg, rgba(14, 34, 62, 0.8), rgba(11, 25, 45, 0.73));
            box-shadow: inset 0 0 24px rgba(69, 146, 255, 0.08); padding: 14px 16px; min-height: 98px;
        }
        .metric-label { font-size: 0.86rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.65px; }
        .metric-value { margin-top: 8px; font-size: 2.32rem; font-weight: 700; line-height: 1; }

        .layout-grid { display: grid; grid-template-columns: 2.3fr 1fr; gap: 14px; margin-top: 14px; }
        .card {
            border: 1px solid var(--line); border-radius: 14px; background: var(--card);
            box-shadow: 0 10px 24px rgba(1,6,12,0.46), inset 0 0 22px rgba(63,146,255,0.08);
            backdrop-filter: blur(10px);
        }
        .card-head { padding: 14px 16px 8px; font-size: 1.3rem; font-weight: 700; color: #e9f1ff; }
        .sub { color: var(--muted); font-size: 0.95rem; font-weight: 500; }

        .chart-shell, .pie-shell { position: relative; padding: 0 12px 12px; height: 390px; }
        .chart-shell canvas, .pie-shell canvas { width: 100% !important; height: 100% !important; }

        .controls {
            margin-top: 14px; border: 1px solid var(--line); border-radius: 12px; background: rgba(9, 24, 45, 0.72);
            display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 10px 12px;
        }
        .ip-input {
            flex: 1; min-width: 220px; border: 1px solid rgba(98, 141, 199, 0.5); background: rgba(8, 18, 33, 0.96);
            color: #d7e8ff; border-radius: 8px; padding: 10px 12px; outline: none;
        }
        .btn {
            border: 1px solid transparent; border-radius: 8px; padding: 9px 14px; font-weight: 600;
            cursor: pointer; color: #fff; transition: transform 0.15s ease, opacity 0.15s ease;
        }
        .btn:hover { transform: translateY(-1px); opacity: 0.94; }
        .btn-danger { background: linear-gradient(145deg, #ef3158, #cb1e42); }
        .btn-success { background: linear-gradient(145deg, #22b76f, #148a54); }
        .btn-inline {
            border: 1px solid rgba(121, 165, 223, 0.4); background: rgba(28, 52, 83, 0.7); color: #dce9ff;
            padding: 5px 10px; border-radius: 8px; font-size: 0.78rem; cursor: pointer;
        }

        .tables { margin-top: 14px; display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
        .table-wrap { padding: 0 12px 12px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 520px; }
        thead th {
            text-align: left; color: #9bb6e0; font-size: 0.82rem; font-weight: 600; padding: 10px 8px;
            border-bottom: 1px solid rgba(129, 173, 236, 0.28); white-space: nowrap;
        }
        tbody td {
            font-size: 0.93rem; color: #dce8ff; padding: 10px 8px;
            border-bottom: 1px solid rgba(83, 120, 173, 0.22); white-space: nowrap;
        }

        .badge {
            border-radius: 999px; font-size: 0.75rem; padding: 4px 10px; font-weight: 700;
            border: 1px solid transparent;
        }
        .badge-critical { background: rgba(255, 61, 98, 0.18); color: #ff8ea5; border-color: rgba(255, 78, 112, 0.35); }
        .badge-high { background: rgba(255, 180, 50, 0.14); color: #ffd18b; border-color: rgba(255, 183, 72, 0.34); }
        .badge-medium { background: rgba(255, 214, 89, 0.14); color: #ffdf9f; border-color: rgba(255, 219, 108, 0.34); }
        .badge-low { background: rgba(100, 214, 159, 0.14); color: #b7ffdc; border-color: rgba(95, 215, 161, 0.34); }
        .badge-safe { background: rgba(67, 194, 136, 0.14); color: #92f7c8; border-color: rgba(61, 210, 145, 0.3); }

        .footer { margin-top: 14px; text-align: right; color: #89a3cd; font-size: 0.85rem; padding-right: 2px; }

        @media (max-width: 1180px) {
            .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .layout-grid { grid-template-columns: 1fr; }
            .tables { grid-template-columns: 1fr; }
            .topbar { flex-direction: column; align-items: flex-start; }
            .status-wrap { align-items: flex-start; }
        }
        @media (max-width: 680px) {
            .metrics { grid-template-columns: 1fr; }
            .brand h1 { font-size: 1.52rem; }
            .metric-value { font-size: 2rem; }
            .chart-shell, .pie-shell { height: 320px; }
        }
    </style>
</head>
<body>
<div class="shell">
    <div class="topbar">
        <div class="brand">
            <div class="shield">&#128737;</div>
            <h1>Dashboard</h1>
            <div id="siteChip" class="site-chip">Protected Site: --</div>
        </div>
        <div class="status-wrap">
            <div id="systemStatus" class="status-pill status-unknown"><span class="dot"></span>System Status: Loading...</div>
            <div id="localTime" class="local-time">Local time: --:--:--</div>
        </div>
    </div>

    <div class="metrics">
        <div class="metric"><div class="metric-label">Total Requests</div><div id="totalRequests" class="metric-value">0</div></div>
        <div class="metric"><div class="metric-label">Attacks Detected</div><div id="attacksDetected" class="metric-value">0</div></div>
        <div class="metric"><div class="metric-label">IP Blocked</div><div id="ipsBlocked" class="metric-value">0</div></div>
        <div class="metric"><div class="metric-label">System Uptime</div><div id="uptime" class="metric-value">0s</div></div>
    </div>

    <div class="layout-grid">
        <div class="card">
            <div class="card-head">Network Traffic Flow <span class="sub">(today 00:00-23:59)</span></div>
            <div class="chart-shell"><canvas id="trafficChart"></canvas></div>
        </div>
        <div class="card">
            <div class="card-head">Attack Types</div>
            <div class="pie-shell"><canvas id="attackTypeChart"></canvas></div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="ipInput" class="ip-input" placeholder="Enter IP address to block/unblock">
        <button class="btn btn-danger" onclick="blockIP()">Block IP</button>
        <button class="btn btn-success" onclick="unblockIP()">Unblock IP</button>
    </div>

    <div class="tables">
        <div class="card">
            <div class="card-head">Blocked IPs</div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>IP Address</th><th>Location</th><th>Action</th></tr></thead>
                    <tbody id="blockedTable"></tbody>
                </table>
            </div>
        </div>

        <div class="card">
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
const API_KEY = '{{ api_key }}';
const headers = {'X-API-Key': API_KEY};

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
    if (footer) footer.textContent = `Data source: /admin/stats, /admin/attacks ? Updated: ${now.toLocaleDateString()} ${t}`;
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
        ctx.fillStyle = '#8ea8d5';
        ctx.font = '500 13px Segoe UI';
        ctx.fillText('Total Attacks', x, y - 4);
        ctx.fillStyle = '#e4eeff';
        ctx.font = '700 30px Segoe UI';
        ctx.fillText(String(total), x, y + 28);
        ctx.restore();
    }
};
Chart.register(donutCenterText);

function initCharts() {
    if (typeof Chart === 'undefined') return false;

    Chart.defaults.color = '#9cb7e1';
    Chart.defaults.borderColor = 'rgba(93, 136, 194, 0.22)';

    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');

    trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: trafficData.labels,
            datasets: [
                {
                    label: 'Requests (current day cumulative)',
                    data: trafficData.requests,
                    borderColor: '#69a8ff',
                    backgroundColor: 'rgba(105, 168, 255, 0.18)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.32,
                    pointRadius: 0
                },
                {
                    label: 'Attacks (current day cumulative)',
                    data: trafficData.attacks,
                    borderColor: '#ffa62f',
                    backgroundColor: 'rgba(255, 166, 47, 0.2)',
                    borderWidth: 2.4,
                    fill: false,
                    tension: 0.25,
                    pointRadius: 2.6,
                    pointHoverRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: {
                        autoSkip: false,
                        maxRotation: 0,
                        callback: function(value, index) {
                            return index % 2 === 0 ? this.getLabelForValue(value) : '';
                        }
                    }
                },
                y: { beginAtZero: true }
            },
            plugins: { legend: { labels: { boxWidth: 16 } } }
        }
    });

    attackTypeChart = new Chart(attackTypeCtx, {
        type: 'doughnut',
        data: {
            labels: ['IP Flooding', 'Distributed', 'Behavioral'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ff2f56', '#ffa10f', '#21c46e'],
                borderColor: 'rgba(11, 24, 44, 0.95)',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '66%',
            plugins: { legend: { position: 'bottom', labels: { color: '#b9cff0', padding: 14, boxWidth: 12 } } }
        }
    });

    resetDailySeries(new Date());
    return true;
}

async function fetchStats() {
    try {
        const res = await fetch('/admin/stats', { headers });
        if (res.status === 401) {
            document.body.innerHTML = '<div style="color:#ff6b86;padding:48px;text-align:center;font:600 1.2rem Segoe UI,Arial">Unauthorized: Invalid API Key</div>';
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
            // Keep real cumulative counters visible for the current hour,
            // and still absorb positive deltas between polls.
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
        }).join('') || '<tr><td colspan="3" style="color:#86a3cf">No blocked IPs</td></tr>';
    } catch (err) {
        console.error('Stats fetch failed:', err);
    }
}

async function fetchAttacks() {
    try {
        const res = await fetch('/admin/attacks?limit=10', { headers });
        if (res.status === 401) return;
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
        }).join('') || '<tr><td colspan="6" style="color:#86a3cf">No attacks recorded</td></tr>';
    } catch (err) {
        console.error('Attack fetch failed:', err);
    }
}

async function blockIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    await fetch('/admin/block/' + ip, { method: 'POST', headers });
    document.getElementById('ipInput').value = '';
    fetchStats();
    fetchAttacks();
}

async function unblockIP() {
    const ip = document.getElementById('ipInput').value.trim();
    if (!ip) return;
    await fetch('/admin/unblock/' + ip, { method: 'POST', headers });
    document.getElementById('ipInput').value = '';
    fetchStats();
    fetchAttacks();
}

async function unblockDirect(ip) {
    await fetch('/admin/unblock/' + ip, { method: 'POST', headers });
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
