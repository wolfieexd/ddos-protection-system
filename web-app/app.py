"""Protected Web Application with DDoS Defense - Production Release"""
from flask import Flask, request, jsonify, render_template_string, g, redirect, url_for, session
from functools import wraps
import time
import sys
import os
import logging
import secrets
import hmac
import threading
from datetime import timedelta
from urllib.parse import urlparse
from typing import Dict
from werkzeug.security import check_password_hash

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
from recovery.health_monitor import HealthMonitor, ServiceState

app = Flask(__name__)
app.config['start_time'] = time.time()

# App/session security config
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    seconds=int(os.environ.get('SESSION_MAX_AGE_SECONDS', 43200))
)

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')

# Dynamic Password Persistence
DYNAMIC_PASSWORD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.admin_password')

def load_admin_password():
    """Load the current dynamic password from disk if it exists."""
    global ADMIN_PASSWORD
    if os.path.exists(DYNAMIC_PASSWORD_FILE):
        try:
            with open(DYNAMIC_PASSWORD_FILE, 'r') as f:
                saved_pw = f.read().strip()
                if saved_pw:
                    ADMIN_PASSWORD = saved_pw
                    logger.info("Loaded dynamic admin password from storage.")
        except Exception:
            logger.exception("Failed to load dynamic admin password")

def rotate_admin_password():
    """Generate a new random password and save it for the next login."""
    global ADMIN_PASSWORD
    # Generate a fresh 16-character secure token
    new_password = secrets.token_urlsafe(12) 
    try:
        with open(DYNAMIC_PASSWORD_FILE, 'w') as f:
            f.write(new_password)
        ADMIN_PASSWORD = new_password
        return new_password
    except Exception:
        logger.exception("Failed to rotate admin password")
        return None

# Initial load of dynamic password if it exists
load_admin_password()

# Admin API key (optional fallback for programmatic access)
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'change-me-in-production')
LOGIN_MAX_ATTEMPTS = int(os.environ.get('LOGIN_MAX_ATTEMPTS', 5))
LOGIN_LOCK_SECONDS = int(os.environ.get('LOGIN_LOCK_SECONDS', 300))
LOGIN_ATTEMPTS = {}

if not ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH:
    ADMIN_PASSWORD = 'change-me-now'
    logger.warning("No ADMIN_PASSWORD/ADMIN_PASSWORD_HASH configured; using insecure default password.")
    # Initialize the dynamic password file with the default
    try:
        if not os.path.exists(DYNAMIC_PASSWORD_FILE):
            with open(DYNAMIC_PASSWORD_FILE, 'w') as f:
                f.write(ADMIN_PASSWORD)
    except Exception:
        pass

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

# Mitigation staging: detect first, enforce mitigation after a short delay.
MITIGATION_DELAY_SECONDS = int(os.environ.get('ATTACK_MITIGATION_DELAY_SECONDS', 10))
ATTACK_ACTIVITY_WINDOW_SECONDS = int(os.environ.get('ATTACK_ACTIVITY_WINDOW_SECONDS', 30))
_mitigation_state = {'first_detected_at': None, 'last_detected_at': 0.0}
_mitigation_lock = threading.Lock()

# Track blocked-request pressure so ongoing attacks from already-blocked IPs
# still appear as active mitigation in dashboard phase.
_blocked_activity_state = {
    'last_blocked_requests': 0,
    'last_total_requests': 0,
    'last_ts': time.time(),
    'active_until': 0.0,
}
_blocked_activity_lock = threading.Lock()


def register_attack_detection(ts: float | None = None):
    now = ts or time.time()
    with _mitigation_lock:
        first = _mitigation_state['first_detected_at']
        last = _mitigation_state['last_detected_at']
        # Start a new attack window if idle for long enough.
        if first is None or (last and now - last > ATTACK_ACTIVITY_WINDOW_SECONDS):
            _mitigation_state['first_detected_at'] = now
        _mitigation_state['last_detected_at'] = now


def mitigation_delay_remaining(now: float | None = None) -> float:
    now = now or time.time()
    with _mitigation_lock:
        first = _mitigation_state['first_detected_at']
        last = _mitigation_state['last_detected_at']
        if first is None:
            return 0.0
        # Reset window after attack inactivity.
        if last and now - last > ATTACK_ACTIVITY_WINDOW_SECONDS:
            _mitigation_state['first_detected_at'] = None
            _mitigation_state['last_detected_at'] = 0.0
            return 0.0
        remaining = MITIGATION_DELAY_SECONDS - (now - first)
        return remaining if remaining > 0 else 0.0


def is_recovery_priority_active() -> bool:
    """True when service is in RECOVERING and mitigation should not interrupt recovery."""
    return health_monitor.get_service_state('web_app') == ServiceState.RECOVERING


def blocked_traffic_attack_active(stats: Dict, now: float) -> bool:
    """Infer attack activity from blocked-request deltas between polls."""
    blocked = int(stats.get('blocked_requests', 0) or 0)
    total = int(stats.get('total_requests', 0) or 0)

    with _blocked_activity_lock:
        prev_blocked = _blocked_activity_state['last_blocked_requests']
        prev_total = _blocked_activity_state['last_total_requests']
        prev_ts = _blocked_activity_state['last_ts']

        dt = max(0.001, now - prev_ts)
        blocked_delta = max(0, blocked - prev_blocked)
        total_delta = max(0, total - prev_total)
        blocked_rps = blocked_delta / dt

        # Consider attack active if block pressure is high in recent window.
        if blocked_delta >= 10 or blocked_rps >= 3.0 or total_delta >= 20:
            _blocked_activity_state['active_until'] = now + ATTACK_ACTIVITY_WINDOW_SECONDS

        _blocked_activity_state['last_blocked_requests'] = blocked
        _blocked_activity_state['last_total_requests'] = total
        _blocked_activity_state['last_ts'] = now

        return now < float(_blocked_activity_state['active_until'])

# Phase tracking state
_phase_state = {'phase': 'normal', 'since': time.time()}

def compute_system_phase():
    """Derive the current defense lifecycle phase from component states."""
    global _phase_state
    health = health_monitor.get_overall_health()
    stats = detector.get_statistics()
    health_status = health['status']
    now = time.time()

    # Check for recent attacks using configured activity window.
    recent = notifier.get_recent_attacks(20)
    has_recent_attack = any(now - a.get('timestamp', 0) < ATTACK_ACTIVITY_WINDOW_SECONDS for a in recent)
    blocked_pressure_active = blocked_traffic_attack_active(stats, now)
    attack_active = has_recent_attack or blocked_pressure_active
    last_attack_ts = recent[-1].get('timestamp') if recent else None
    blocked_count = stats.get('blocked_ips_count', 0)

    # Auto-trigger recovery: if health is CRITICAL but attacks have stopped,
    # kick the health monitor into RECOVERING so the system doesn't stay
    # stuck in "mitigation" mode forever after an attack ends.
    if health_status == 'CRITICAL' and not attack_active:
        health_monitor.trigger_recovery('web_app')
        health_status = 'RECOVERING'  # use the updated status for phase calc

    # Also advance recovery when health is RECOVERING — call report_success
    # on each phase poll so the recovery timer ticks forward even without
    # external user traffic.
    if health_status == 'RECOVERING':
        health_monitor.report_success('web_app')
        # Re-read in case it just transitioned to HEALTHY
        health = health_monitor.get_overall_health()
        health_status = health['status']

    raw_recovery_prog = health_monitor.recovery_progress('web_app')

    # Cross-worker stable recovery progression derived from last shared attack timestamp.
    # This prevents phase flapping between workers with different in-memory states.
    effective_recovery_prog = raw_recovery_prog
    derived_recovery_active = False
    recovery_time_cfg = max(1, int(getattr(health_monitor, 'recovery_time', 300)))
    if last_attack_ts and not attack_active:
        elapsed = max(0.0, now - float(last_attack_ts))
        effective_recovery_prog = min(1.0, elapsed / recovery_time_cfg)
        derived_recovery_active = effective_recovery_prog < 1.0

    # Recovery gets phase priority while recovery is still in progress.
    if derived_recovery_active or (health_status in ('RECOVERING', 'DEGRADED') and effective_recovery_prog < 1.0):
        new_phase = 'recovery'
    elif attack_active and (health_status == 'CRITICAL' or blocked_count > 0):
        new_phase = 'mitigation'
    elif attack_active:
        new_phase = 'detection'
    elif blocked_count > 0 and effective_recovery_prog < 1.0:
        # Keep post-attack state visible on dashboard while blocks are still active.
        new_phase = 'recovery'
    else:
        new_phase = 'normal'

    if new_phase != _phase_state['phase']:
        _phase_state = {'phase': new_phase, 'since': now}

    # Compute mitigation rate
    total_req = stats.get('total_requests', 0)
    blocked_req = stats.get('blocked_requests', 0)
    mitigation_rate = (blocked_req / total_req * 100) if total_req > 0 else 0.0

    # Compute threat level (0-100) with dynamic decay during recovery
    recent_attacks_count = sum(1 for a in recent if now - a.get('timestamp', 0) < max(60, ATTACK_ACTIVITY_WINDOW_SECONDS))
    threat_level = min(100, recent_attacks_count * 8 + blocked_count * 10)
    if health_status == 'CRITICAL':
        threat_level = max(threat_level, 80)
    elif new_phase == 'recovery':
        # Decay threat level as recovery progresses
        threat_level = max(threat_level, int(60 * (1.0 - effective_recovery_prog)))

    return {
        'phase': _phase_state['phase'],
        'phase_since': _phase_state['since'],
        'phase_duration': now - _phase_state['since'],
        'attack_active': attack_active,
        'blocked_count': blocked_count,
        'mitigation_rate': round(mitigation_rate, 1),
        'health_status': health_status,
        'recovery_progress': round(effective_recovery_prog, 3),
        'threat_level': threat_level,
        'last_attack_timestamp': last_attack_ts
    }


def background_cleanup():
    """Background thread for periodic cleaning of stale rate limiter buckets and old IP blocks."""
    while True:
        try:
            rate_limiter.cleanup_stale_buckets()
            # Automatically unblock IPs older than 1 hour (default)
            pruned_count = detector.prune_blocks(max_age=int(os.environ.get('BLOCK_EXPIRY', 3600)))
            if pruned_count > 0:
                logger.info("Background cleanup: unblocked %d expired IPs", pruned_count)
        except Exception as e:
            logger.error("Error in background cleanup thread: %s", e)
        time.sleep(60)

# Start background cleanup thread
cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

# Per-endpoint rate limit profiles: path_prefix -> (rate_per_min, burst)
ENDPOINT_RATE_PROFILES = {
    '/login': (10, 5),
    '/admin': (30, 10),
    '/api': (200, 50),
}


def require_admin(f):
    """Decorator to require authenticated admin session (or API key fallback)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_admin_authenticated():
            if request.path.startswith('/admin/dashboard'):
                return redirect(url_for('admin_login', next=request.full_path))
            return jsonify({'error': 'Unauthorized', 'code': 'AUTH_REQUIRED'}), 401
        return f(*args, **kwargs)
    return decorated


def _get_admin_api_key():
    return (request.headers.get('X-API-Key')
            or request.args.get('api_key'))


def _is_safe_next_url(target: str) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    return (not parsed.netloc) and target.startswith('/admin')


def verify_admin_password(password: str) -> bool:
    if not password:
        return False
        
    # Keep dynamic password synchronized across Gunicorn workers
    load_admin_password()
    
    if ADMIN_PASSWORD_HASH:
        try:
            return check_password_hash(ADMIN_PASSWORD_HASH, password)
        except Exception:
            logger.exception("Failed to verify ADMIN_PASSWORD_HASH")
            return False
    return bool(ADMIN_PASSWORD) and hmac.compare_digest(password, ADMIN_PASSWORD)


def _login_bucket_key(ip: str) -> str:
    return ip or 'unknown'


def is_login_locked(ip: str) -> bool:
    state = LOGIN_ATTEMPTS.get(_login_bucket_key(ip))
    if not state:
        return False
    locked_until = state.get('locked_until', 0)
    if locked_until > time.time():
        return True
    if locked_until:
        LOGIN_ATTEMPTS.pop(_login_bucket_key(ip), None)
    return False


def register_login_failure(ip: str):
    key = _login_bucket_key(ip)
    state = LOGIN_ATTEMPTS.get(key, {'count': 0, 'locked_until': 0})
    state['count'] = state.get('count', 0) + 1
    if state['count'] >= LOGIN_MAX_ATTEMPTS:
        state['locked_until'] = time.time() + LOGIN_LOCK_SECONDS
        state['count'] = 0
    LOGIN_ATTEMPTS[key] = state


def clear_login_failures(ip: str):
    LOGIN_ATTEMPTS.pop(_login_bucket_key(ip), None)


def is_admin_authenticated() -> bool:
    if session.get('admin_authenticated') and session.get('admin_username') == ADMIN_USERNAME:
        return True

    # API key fallback for scripts/automation clients.
    api_key = _get_admin_api_key()
    if api_key and hmac.compare_digest(api_key, ADMIN_API_KEY):
        return True
    return False


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


# IPs that must never be auto-blocked (loopback, Docker gateway, private ranges)
_NEVER_BLOCK_PREFIXES = (
    '127.', '::1', 'localhost',
    '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
)

def is_private_ip(ip: str) -> bool:
    return ip and any(ip.startswith(p) for p in _NEVER_BLOCK_PREFIXES)


def classify_ip_location(ip: str) -> str:
    """Resolve location from notifier service (GeoIP-aware with safe fallback)."""
    return notifier.classify_ip_location(ip)


@app.before_request
def ddos_protection():
    g.start_time = time.time()
    client_ip = get_client_ip()
    g.mitigation_delay_remaining = mitigation_delay_remaining()

    # Allow health check endpoint to bypass all DDoS checks
    if request.path == '/health':
        return None

    # Admin routes are always allowed through (authentication is enforced separately)
    if request.path.startswith('/admin'):
        return None

    # During recovery, allow full traffic flow so mitigation does not interrupt recovery.
    if is_recovery_priority_active():
        return None

    # During attack warm-up, detect/log traffic but do not enforce mitigation yet.
    if g.mitigation_delay_remaining > 0:
        return None

    # Check if IP is blocked by detector
    if detector.is_blocked(client_ip):
        detector._incr('total_requests')
        detector._incr('blocked_requests')
        g.skip_traffic_analysis = True
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
        detector._incr('total_requests')
        detector._incr('blocked_requests')
        g.skip_traffic_analysis = True
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

    # Prevent stale admin dashboard/login pages on mobile browsers.
    if request.path.startswith('/admin'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    # Skip traffic analysis for health checks and authenticated admin requests
    if request.path == '/health':
        return response
    if request.path in ('/admin/login', '/admin/logout'):
        return response
    if request.path.startswith('/admin') and is_admin_authenticated():
        return response
    if g.get('skip_traffic_analysis'):
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

    recovery_priority = is_recovery_priority_active()

    if is_attack and signature:
        register_attack_detection(metric.timestamp)
        logger.warning("Attack detected: %s from %s (confidence=%.2f)",
                       signature.attack_type, client_ip, signature.confidence)
        if not recovery_priority:
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

    if (not recovery_priority and risk['recommendation'] == 'BLOCK_IMMEDIATELY'
            and not detector.is_blocked(client_ip)):
        register_attack_detection()
        detector._block_ip(client_ip)
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
    # Restrict detailed health info: allow local requests or authenticated admin/API key
    remote = request.remote_addr
    overall = health_monitor.get_overall_health()
    if is_admin_authenticated() or remote in ('127.0.0.1', '::1'):
        return jsonify({
            'status': overall['status'].lower(),
            'timestamp': time.time(),
            'services': overall.get('services', {})
        })
    # Non-local callers get minimal information to avoid leaking internal state
    return jsonify({'status': overall['status'].lower(), 'timestamp': time.time()}), 200


# ==================== Admin Routes (Session Login + API Key Fallback) ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if is_admin_authenticated():
        return redirect(url_for('admin_dashboard'))

    client_ip = get_client_ip()
    error_message = ''
    next_url = request.args.get('next', '/admin/dashboard')
    if not _is_safe_next_url(next_url):
        next_url = '/admin/dashboard'

    if request.method == 'POST':
        next_url = request.form.get('next', '/admin/dashboard')
        if not _is_safe_next_url(next_url):
            next_url = '/admin/dashboard'

        if is_login_locked(client_ip):
            error_message = f"Too many failed attempts. Try again in {LOGIN_LOCK_SECONDS} seconds."
        else:
            password = request.form.get('password', '')
            if verify_admin_password(password):
                session.clear()
                session.permanent = True
                session['admin_authenticated'] = True
                session['admin_username'] = ADMIN_USERNAME
                session['admin_login_at'] = int(time.time())
                clear_login_failures(client_ip)
                
                return redirect(next_url)
            register_login_failure(client_ip)
            error_message = "Invalid password."

    return render_template_string(LOGIN_HTML, error_message=error_message, next_url=next_url)


@app.route('/admin/logout', methods=['GET', 'POST'])
def admin_logout():
    new_password = None
    if is_admin_authenticated():
        new_password = rotate_admin_password()
    session.clear()
    
    if new_password:
        return render_template_string(LOGOUT_HTML, new_password=new_password)
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@require_admin
def admin_dashboard():
    # If access is via API key fallback, upgrade to session auth for dashboard XHR calls.
    if not session.get('admin_authenticated'):
        api_key = _get_admin_api_key()
        if api_key and hmac.compare_digest(api_key, ADMIN_API_KEY):
            session['admin_authenticated'] = True
            session['admin_username'] = ADMIN_USERNAME
            session['admin_login_at'] = int(time.time())
    return render_template_string(DASHBOARD_HTML)


@app.route('/admin/stats')
@require_admin
def admin_stats():
    # Lightweight audit log (avoid dumping sensitive headers/cookies)
    try:
        logger.info("Admin stats requested from %s", request.remote_addr)
    except Exception:
        logger.exception("Failed to log admin_stats request metadata")

    detection_stats = detector.get_statistics()
    attack_summary = notifier.get_attack_summary()
    # Fallback: if historical detector counters exist but notifier summary is empty,
    # keep dashboard widgets consistent instead of showing "0 total attacks" in pie.
    if attack_summary.get('total_attacks', 0) == 0 and detection_stats.get('attacks_detected', 0) > 0:
        attack_summary['total_attacks'] = detection_stats.get('attacks_detected', 0)
        if not attack_summary.get('attack_types'):
            attack_summary['attack_types'] = {
                'IP_FLOODING': detection_stats.get('attacks_detected', 0)
            }

    blocked_ips = list(detector.blocked_ips)
    blocked_details = [
        {'ip': ip, 'location': classify_ip_location(ip)} 
        for ip in blocked_ips
    ]

    return jsonify({
        'detection': detection_stats,
        'rate_limiter': rate_limiter.get_stats(),
        'traffic_analyzer': traffic_analyzer.get_stats(),
        'health': health_monitor.get_overall_health(),
        'attacks': attack_summary,
        'blocked_ips': blocked_ips,
        'blocked_ip_details': blocked_details,
        'uptime': time.time() - app.config.get('start_time', time.time()),
        'system_phase': compute_system_phase()
    })


@app.route('/admin/attacks')
@require_admin
def admin_attacks():
    try:
        limit = int(request.args.get('limit', 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 200))
    recent_attacks = notifier.get_recent_attacks(limit)
    return jsonify(recent_attacks)


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


@app.route('/admin/system_phase')
@require_admin
def admin_system_phase():
    """Return the current defense lifecycle phase."""
    return jsonify(compute_system_phase())


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

LOGOUT_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logged Out - DDoS Protection</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; display: grid; place-items: center;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(180deg, #060b13 0%, #081426 100%);
            color: #d8e7ff;
        }
        .card {
            width: min(430px, 92vw); background: rgba(12, 27, 50, 0.82);
            border: 1px solid rgba(108, 163, 255, 0.24); border-radius: 16px;
            padding: 26px; box-shadow: 0 12px 30px rgba(1, 8, 15, 0.45);
            text-align: center;
        }
        h1 { margin: 0 0 10px 0; font-size: 1.6rem; color: #10b981; }
        p { margin: 0 0 18px 0; color: #9eb9e5; line-height: 1.5; }
        .password-box {
            background: rgba(7, 16, 30, 0.96); border: 1px dashed #2a7cff;
            padding: 16px; margin: 20px 0; border-radius: 8px;
            font-family: monospace; font-size: 1.3rem; font-weight: bold;
            color: #ffc107; user-select: all; letter-spacing: 1px;
        }
        .btn {
            display: inline-block; width: 100%; text-decoration: none;
            border-radius: 10px; padding: 11px 14px;
            background: linear-gradient(145deg, #2a7cff, #1f5fcc);
            color: #fff; font-weight: 700; cursor: pointer; border: 0;
        }
        .btn:hover { opacity: 0.95; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Successfully Logged Out</h1>
        <p>Your session has been securely closed. For security, your admin password has been rotated.</p>
        <p style="color:#d8e7ff">Please save your next password:</p>
        <div class="password-box">{{ new_password }}</div>
        <p style="font-size: 0.85rem; color: #8ca8d6;">This password is required for your next sign in.</p>
        <a class="btn" href="/admin/login">Back to Login</a>
    </div>
</body>
</html>'''

LOGIN_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - DDoS Protection</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background:
                radial-gradient(70% 110% at 10% 0%, rgba(33, 96, 193, 0.35), transparent 60%),
                radial-gradient(60% 90% at 90% 10%, rgba(10, 73, 182, 0.3), transparent 65%),
                linear-gradient(180deg, #060b13 0%, #081426 100%);
            color: #d8e7ff;
        }
        .card {
            width: min(430px, 92vw);
            background: rgba(12, 27, 50, 0.82);
            border: 1px solid rgba(108, 163, 255, 0.24);
            border-radius: 16px;
            padding: 26px;
            box-shadow: 0 12px 30px rgba(1, 8, 15, 0.45);
        }
        h1 { margin: 0 0 4px 0; font-size: 1.8rem; }
        p { margin: 0 0 18px 0; color: #9eb9e5; }
        .field { margin-bottom: 14px; }
        label { display: block; margin-bottom: 7px; color: #b9cff2; font-size: 0.92rem; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 11px 12px;
            border-radius: 10px;
            border: 1px solid rgba(121, 170, 235, 0.36);
            background: rgba(7, 16, 30, 0.96);
            color: #e7f0ff;
            outline: none;
        }
        input[readonly] { opacity: 0.85; }
        .btn {
            width: 100%;
            border: 0;
            border-radius: 10px;
            padding: 11px 14px;
            background: linear-gradient(145deg, #2a7cff, #1f5fcc);
            color: #fff;
            font-weight: 700;
            cursor: pointer;
        }
        .btn:hover { opacity: 0.95; }
        .error {
            margin-bottom: 12px;
            padding: 10px 12px;
            border-radius: 10px;
            border: 1px solid rgba(255, 118, 145, 0.45);
            background: rgba(64, 18, 28, 0.76);
            color: #ffc0cf;
            font-size: 0.9rem;
        }
        .hint {
            margin-top: 12px;
            color: #8ca8d6;
            font-size: 0.82rem;
        }
        @media (max-width: 600px) {
            .card { padding: 24px 20px; width: 90vw; border-radius: 12px; }
            h1 { font-size: 1.6rem; }
            p { font-size: 0.95rem; margin-bottom: 20px; }
            input[type="text"], input[type="password"] { padding: 14px 12px; font-size: 16px; }
            .btn { padding: 14px 12px; font-size: 16px; margin-top: 5px; }
        }
    </style>
</head>
<body>
    <form class="card" method="POST" action="/admin/login">
        <h1>Admin Login</h1>
        <p>Secure access to DDoS control dashboard.</p>
        {% if error_message %}
            <div class="error">{{ error_message }}</div>
        {% endif %}
        <input type="hidden" name="next" value="{{ next_url }}">
        <div class="field">
            <label>Username (locked)</label>
            <input type="text" value="admin" readonly>
        </div>
        <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" placeholder="Enter admin password" required autofocus>
        </div>
        <button class="btn" type="submit">Sign In</button>
        <div class="hint">Username is fixed to <strong>admin</strong>.</div>
    </form>
</body>
</html>'''

LANDING_PAGE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Protected Application</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:'Inter',system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;
            background:#080c18;color:#e2e8f0;overflow:hidden;transition:background 1.5s ease}
        body.phase-normal{background:linear-gradient(145deg,#080c18 0%,#0a1628 50%,#0d1f3c 100%)}
        body.phase-detection{background:linear-gradient(145deg,#1a1000 0%,#1c1508 50%,#261c06 100%)}
        body.phase-mitigation{background:linear-gradient(145deg,#1a0505 0%,#200808 50%,#2a0a0a 100%)}
        body.phase-recovery{background:linear-gradient(145deg,#080c1a 0%,#0a1230 50%,#0c1840 100%)}

        .ambient{position:fixed;inset:0;pointer-events:none;z-index:0;transition:opacity 1s}
        .ambient::before{content:'';position:absolute;width:600px;height:600px;border-radius:50%;
            filter:blur(120px);opacity:0.15;animation:float 8s ease-in-out infinite}
        .phase-normal .ambient::before{background:radial-gradient(circle,#10b981,transparent);top:-200px;left:-100px}
        .phase-detection .ambient::before{background:radial-gradient(circle,#f59e0b,transparent);top:-100px;right:-100px;animation:pulse-warn 2s ease-in-out infinite}
        .phase-mitigation .ambient::before{background:radial-gradient(circle,#ef4444,transparent);top:-100px;left:50%;animation:pulse-danger 1s ease-in-out infinite}
        .phase-recovery .ambient::before{background:radial-gradient(circle,#3b82f6,transparent);bottom:-200px;left:-100px}

        @keyframes float{0%,100%{transform:translateY(0) scale(1)}50%{transform:translateY(-30px) scale(1.05)}}
        @keyframes pulse-warn{0%,100%{opacity:0.15;transform:scale(1)}50%{opacity:0.3;transform:scale(1.1)}}
        @keyframes pulse-danger{0%,100%{opacity:0.2;transform:scale(1)}50%{opacity:0.4;transform:scale(1.15)}}
        @keyframes shield-pulse{0%,100%{transform:scale(1);filter:drop-shadow(0 0 12px var(--glow))}50%{transform:scale(1.08);filter:drop-shadow(0 0 24px var(--glow))}}

        .card{position:relative;z-index:1;width:min(520px,92vw);background:rgba(15,23,42,0.7);
            backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
            border:1px solid rgba(255,255,255,0.08);border-radius:24px;padding:48px 40px;
            text-align:center;box-shadow:0 24px 64px rgba(0,0,0,0.4);transition:border-color 1s}
        .phase-detection .card{border-color:rgba(245,158,11,0.25)}
        .phase-mitigation .card{border-color:rgba(239,68,68,0.3);animation:card-shake .5s ease-in-out infinite alternate}
        .phase-recovery .card{border-color:rgba(59,130,246,0.25)}

        @media(max-width:600px){
            .card{padding:30px 20px;}
            .shield-icon{font-size:3.5rem;margin-bottom:15px}
            h1{font-size:1.4rem}
            .subtitle{font-size:0.85rem;margin-bottom:20px}
            .status-bar{font-size:0.85rem;padding:12px 15px}
        }

        @keyframes card-shake{0%{transform:translateX(0)}100%{transform:translateX(1px)}}

        .shield-icon{--glow:#10b981;font-size:4.5rem;margin-bottom:20px;animation:shield-pulse 3s ease-in-out infinite;transition:all 1s}
        .phase-detection .shield-icon{--glow:#f59e0b}
        .phase-mitigation .shield-icon{--glow:#ef4444;animation-duration:1s}
        .phase-recovery .shield-icon{--glow:#3b82f6;animation-duration:2s}

        h1{font-size:1.8rem;font-weight:800;margin-bottom:8px;letter-spacing:-0.02em}
        .subtitle{color:#94a3b8;font-size:0.95rem;line-height:1.6;margin-bottom:28px}

        .status-bar{padding:14px 20px;border-radius:14px;font-weight:700;font-size:0.95rem;
            display:flex;align-items:center;justify-content:center;gap:10px;transition:all 1s}
        .status-dot{width:10px;height:10px;border-radius:50%;transition:all 1s}

        .status-normal{background:rgba(16,185,129,0.12);color:#10b981;border:1px solid rgba(16,185,129,0.2)}
        .status-normal .status-dot{background:#10b981;box-shadow:0 0 10px #10b981}
        .status-detection{background:rgba(245,158,11,0.12);color:#f59e0b;border:1px solid rgba(245,158,11,0.25)}
        .status-detection .status-dot{background:#f59e0b;box-shadow:0 0 10px #f59e0b;animation:blink 1s infinite}
        .status-mitigation{background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.3)}
        .status-mitigation .status-dot{background:#ef4444;box-shadow:0 0 12px #ef4444;animation:blink .5s infinite}
        .status-recovery{background:rgba(59,130,246,0.12);color:#3b82f6;border:1px solid rgba(59,130,246,0.2)}
        .status-recovery .status-dot{background:#3b82f6;box-shadow:0 0 10px #3b82f6}

        @keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}

        .phase-msg{margin-top:16px;font-size:0.85rem;color:#64748b;min-height:20px;transition:color 0.5s}
    </style>
</head>
<body class="phase-normal">
    <div class="ambient"></div>
    <div class="card">
        <div class="shield-icon">&#128737;</div>
        <h1>DDoS Protected Application</h1>
        <p class="subtitle">Your connection is protected by our multi-layered DDoS mitigation system.</p>
        <div id="statusBar" class="status-bar status-normal">
            <span class="status-dot"></span>
            <span id="statusText">System Protected</span>
        </div>
        <div id="phaseMsg" class="phase-msg"></div>
    </div>
<script>
const phaseConfig={
    normal:{cls:'phase-normal',statusCls:'status-normal',text:'System Protected',msg:'All systems operational. No threats detected.'},
    detection:{cls:'phase-detection',statusCls:'status-detection',text:'Threat Detected \u2014 Analyzing',msg:'Anomalous traffic detected. Our systems are analyzing the threat.'},
    mitigation:{cls:'phase-mitigation',statusCls:'status-mitigation',text:'Under Attack \u2014 Mitigating',msg:'Active threat being mitigated. Service may be temporarily limited.'},
    recovery:{cls:'phase-recovery',statusCls:'status-recovery',text:'Recovering \u2014 Stabilizing',msg:'Attack subsided. Systems are recovering to normal operation.'}
};
function updatePhase(phase){
    const cfg=phaseConfig[phase]||phaseConfig.normal;
    document.body.className=cfg.cls;
    const bar=document.getElementById('statusBar');
    bar.className='status-bar '+cfg.statusCls;
    document.getElementById('statusText').textContent=cfg.text;
    document.getElementById('phaseMsg').textContent=cfg.msg;
}
async function poll(){
    try{
        const r=await fetch('/health');
        const d=await r.json();
        const st=(d.status||'healthy').toUpperCase();
        if(st==='CRITICAL') updatePhase('mitigation');
        else if(st==='RECOVERING'||st==='DEGRADED') updatePhase('recovery');
        else updatePhase('normal');
    }catch(e){updatePhase('normal')}
}
poll();setInterval(poll,5000);
</script>
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
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8/hammer.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.0.1/dist/chartjs-plugin-zoom.min.js"></script>
    <style>
        :root {
            --bg: #060a14; --bg2: #0a1225; --bg3: #0e1a35;
            --card: rgba(12,20,40,0.75); --card-border: rgba(255,255,255,0.06);
            --text: #e8edf5; --text-muted: #6b7fa0; --line: rgba(255,255,255,0.06);
            --shadow: 0 8px 40px rgba(0,0,0,0.35); --blur: blur(20px);
            --ok: #10b981; --warn: #f59e0b; --danger: #ef4444; --info: #3b82f6;
            --phase-color: var(--ok); --phase-glow: rgba(16,185,129,0.15);
        }
        [data-theme="light"] {
            --bg: #f0f3f8; --bg2: #e8edf5; --bg3: #dfe6f0;
            --card: rgba(255,255,255,0.75); --card-border: rgba(0,0,0,0.06);
            --text: #0f172a; --text-muted: #64748b; --line: rgba(0,0,0,0.06);
            --shadow: 0 8px 40px rgba(0,0,0,0.08);
        }
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);
            min-height:100vh;transition:background 1s,color 0.3s}

        /* ===== AMBIENT EFFECTS ===== */
        .ambient{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden;transition:opacity 1.5s}
        .ambient-orb{position:absolute;border-radius:50%;filter:blur(100px);opacity:0.12;transition:all 2s ease}
        .orb-1{width:500px;height:500px;top:-150px;left:-100px;background:var(--phase-color)}
        .orb-2{width:400px;height:400px;bottom:-100px;right:-80px;background:var(--phase-color);opacity:0.08}
        .vignette{position:fixed;inset:0;pointer-events:none;z-index:1;opacity:0;
            box-shadow:inset 0 0 200px rgba(239,68,68,0.3);transition:opacity 1.5s}

        /* Phase body classes */
        body.phase-normal{--phase-color:var(--ok);--phase-glow:rgba(16,185,129,0.12)}
        body.phase-detection{--phase-color:var(--warn);--phase-glow:rgba(245,158,11,0.12)}
        body.phase-mitigation{--phase-color:var(--danger);--phase-glow:rgba(239,68,68,0.15)}
        body.phase-recovery{--phase-color:var(--info);--phase-glow:rgba(59,130,246,0.12)}
        body.phase-mitigation .vignette{opacity:1}

        .shell{position:relative;z-index:2;width:min(1520px,97vw);margin:16px auto;padding-bottom:40px}

        /* ===== PHASE BANNER ===== */
        .phase-banner{padding:14px 24px;border-radius:16px;margin-bottom:20px;display:flex;
            align-items:center;gap:14px;font-weight:700;font-size:0.95rem;
            background:var(--phase-glow);border:1px solid rgba(255,255,255,0.06);
            backdrop-filter:var(--blur);transition:all 1s;overflow:hidden;position:relative}
        .phase-banner .banner-icon{font-size:1.4rem;flex-shrink:0;z-index:1}
        .phase-banner .banner-text{z-index:1}
        .phase-banner .banner-sub{font-weight:400;color:var(--text-muted);font-size:0.85rem;margin-left:auto;z-index:1}

        .phase-banner::after{content:'';position:absolute;top:0;left:-100%;width:60%;height:100%;
            background:linear-gradient(90deg,transparent,rgba(255,255,255,0.04),transparent);
            animation:none;z-index:0}
        body.phase-detection .phase-banner::after{animation:scan 3s linear infinite}
        body.phase-mitigation .phase-banner::after{animation:scan 1.5s linear infinite}
        body.phase-mitigation .phase-banner{border-color:rgba(239,68,68,0.3);
            animation:banner-pulse 2s ease-in-out infinite}
        @keyframes scan{0%{left:-60%}100%{left:100%}}
        @keyframes banner-pulse{0%,100%{box-shadow:0 0 20px rgba(239,68,68,0.1)}50%{box-shadow:0 0 40px rgba(239,68,68,0.2)}}

        /* ===== PHASE TIMELINE ===== */
        .timeline{display:flex;align-items:center;justify-content:center;gap:0;padding:12px 24px;
            border-radius:14px;background:var(--card);border:1px solid var(--card-border);
            backdrop-filter:var(--blur);margin-bottom:20px}
        .t-step{display:flex;align-items:center;gap:8px;padding:8px 16px;border-radius:10px;
            font-size:0.82rem;font-weight:600;color:var(--text-muted);transition:all 0.5s;position:relative}
        .t-step.active{color:var(--phase-color);background:var(--phase-glow)}
        .t-step.done{color:var(--ok)}
        .t-dot{width:10px;height:10px;border-radius:50%;border:2px solid var(--text-muted);
            transition:all 0.5s;flex-shrink:0}
        .t-step.active .t-dot{border-color:var(--phase-color);background:var(--phase-color);
            box-shadow:0 0 10px var(--phase-color);animation:dot-pulse 2s infinite}
        .t-step.done .t-dot{border-color:var(--ok);background:var(--ok)}
        .t-connector{width:40px;height:2px;background:var(--line);transition:background 0.5s;flex-shrink:0}
        .t-connector.done{background:var(--ok)}
        @keyframes dot-pulse{0%,100%{box-shadow:0 0 8px var(--phase-color)}50%{box-shadow:0 0 20px var(--phase-color)}}

        /* ===== TOP BAR ===== */
        .topbar{display:flex;justify-content:space-between;align-items:center;gap:14px;
            padding:16px 24px;margin-bottom:20px;background:var(--card);
            border:1px solid var(--card-border);border-radius:16px;backdrop-filter:var(--blur)}
        .brand{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
        .shield-icon{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;
            background:rgba(59,130,246,0.12);border:1px solid rgba(59,130,246,0.2);font-size:1.2rem}
        .brand h1{font-size:1.5rem;font-weight:800;letter-spacing:-0.03em}
        .site-chip{border:1px solid var(--line);background:rgba(255,255,255,0.03);
            padding:6px 12px;border-radius:8px;font-size:0.85rem;color:var(--text-muted)}
        .actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
        .theme-toggle{background:var(--card);border:1px solid var(--card-border);color:var(--text);
            padding:8px 14px;border-radius:8px;cursor:pointer;font-weight:600;font-size:0.85rem;
            font-family:inherit}
        .theme-toggle:hover{opacity:0.8}
        .logout-link{
            display:inline-flex;
            align-items:center;
            justify-content:center;
            padding:7px 12px;
            border-radius:8px;
            border:1px solid rgba(239,68,68,0.35);
            background:rgba(239,68,68,0.12);
            color:#fca5a5;
            font-size:0.82rem;
            font-weight:700;
            text-decoration:none;
            line-height:1;
        }
        .logout-link:hover{
            background:rgba(239,68,68,0.2);
            border-color:rgba(239,68,68,0.55);
        }
        .status-wrap{display:flex;flex-direction:column;gap:4px;align-items:flex-end}
        .status-pill{display:inline-flex;align-items:center;gap:8px;border-radius:999px;
            border:1px solid var(--card-border);background:var(--card);backdrop-filter:var(--blur);
            padding:6px 14px;font-size:0.82rem;font-weight:600;transition:all 0.5s}
        .status-critical{color:var(--danger);border-color:rgba(239,68,68,0.3);background:rgba(239,68,68,0.08)}
        .status-recovering{color:var(--info);border-color:rgba(59,130,246,0.3);background:rgba(59,130,246,0.08)}
        .status-degraded{color:var(--warn);border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.08)}
        .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);transition:all 0.5s}
        .status-critical .dot{background:var(--danger);box-shadow:0 0 8px var(--danger);animation:blink-dot .6s infinite}
        .status-recovering .dot{background:var(--info);box-shadow:0 0 8px var(--info)}
        @keyframes blink-dot{0%,100%{opacity:1}50%{opacity:0.2}}
        .local-time{color:var(--text-muted);font-size:0.78rem}

        /* ===== METRICS ===== */
        .metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}
        .metric{padding:20px;border-radius:16px;background:var(--card);border:1px solid var(--card-border);
            backdrop-filter:var(--blur);transition:border-color 0.5s,box-shadow 0.5s}
        .metric.glow{border-color:rgba(239,68,68,0.3);box-shadow:0 0 20px rgba(239,68,68,0.08)}
        .metric-label{font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1.2px;font-weight:600}
        .metric-value{margin-top:10px;font-size:2rem;font-weight:800;line-height:1;letter-spacing:-0.03em}
        .metric-trend{font-size:0.75rem;margin-top:6px;font-weight:600}
        .trend-up{color:var(--danger)}
        .trend-down{color:var(--ok)}
        .trend-flat{color:var(--text-muted)}

        /* ===== THREAT GAUGE ===== */
        .gauge-wrap{display:flex;align-items:center;justify-content:center;padding:20px;
            border-radius:16px;background:var(--card);border:1px solid var(--card-border);backdrop-filter:var(--blur)}
        .gauge-svg{width:160px;height:100px}
        .gauge-bg{fill:none;stroke:var(--line);stroke-width:10;stroke-linecap:round}
        .gauge-fill{fill:none;stroke-width:10;stroke-linecap:round;transition:stroke-dashoffset 1s ease,stroke 1s}
        .gauge-text{font-family:'Inter',sans-serif;font-weight:800;fill:var(--text);font-size:24px}
        .gauge-label{font-family:'Inter',sans-serif;font-weight:600;fill:var(--text-muted);font-size:9px;
            text-transform:uppercase;letter-spacing:1px}
        .gauge-info{text-align:center;margin-left:16px}
        .gauge-title{font-size:0.82rem;font-weight:700;margin-bottom:4px}
        .gauge-status{font-size:0.9rem;font-weight:800;transition:color 0.5s}

        /* ===== LAYOUT GRID ===== */
        .grid-2{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:20px}
        .grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}
        .grid-eq{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
        .card{padding:20px;border-radius:16px;background:var(--card);border:1px solid var(--card-border);
            backdrop-filter:var(--blur)}
        .card-head{font-size:1rem;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:8px}
        .card-head .sub{color:var(--text-muted);font-size:0.8rem;font-weight:400}
        .chart-shell{position:relative;height:300px;width:100%}
        .pie-shell{position:relative;height:300px;width:100%}

        /* ===== MITIGATION PANEL ===== */
        .miti-panel{display:none;padding:20px;border-radius:16px;margin-bottom:20px;
            background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.15);
            backdrop-filter:var(--blur);transition:all 0.5s}
        .miti-panel.visible{display:block;animation:slideIn 0.5s ease}
        @keyframes slideIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
        .miti-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-top:14px}
        .miti-stat{text-align:center}
        .miti-stat-value{font-size:1.6rem;font-weight:800;color:var(--danger)}
        .miti-stat-label{font-size:0.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-top:4px}

        /* ===== RECOVERY BAR ===== */
        .recovery-panel{display:none;padding:16px 20px;border-radius:16px;margin-bottom:20px;
            background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);backdrop-filter:var(--blur)}
        .recovery-panel.visible{display:block;animation:slideIn 0.5s ease}
        .recovery-bar-track{height:8px;border-radius:4px;background:var(--line);overflow:hidden;margin-top:10px}
        .recovery-bar-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--info),#60a5fa);
            transition:width 1s ease;position:relative}
        .recovery-bar-fill::after{content:'';position:absolute;top:0;right:0;width:30px;height:100%;
            background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3));animation:shimmer 1.5s infinite}
        @keyframes shimmer{0%{opacity:0}50%{opacity:1}100%{opacity:0}}
        .recovery-info{display:flex;justify-content:space-between;align-items:center;margin-top:8px;
            font-size:0.8rem;color:var(--text-muted)}

        /* ===== EVENT FEED ===== */
        .event-feed{max-height:280px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
        .event-feed::-webkit-scrollbar{width:4px}
        .event-feed::-webkit-scrollbar-thumb{background:var(--line);border-radius:2px}
        .event-item{padding:8px 12px;border-radius:8px;font-size:0.8rem;margin-bottom:4px;
            display:flex;align-items:flex-start;gap:8px;animation:fadeIn 0.3s ease;
            background:rgba(255,255,255,0.02);border:1px solid transparent}
        .event-item.ev-detect{border-color:rgba(245,158,11,0.15);color:#fbbf24}
        .event-item.ev-block{border-color:rgba(239,68,68,0.15);color:#f87171}
        .event-item.ev-recover{border-color:rgba(59,130,246,0.15);color:#60a5fa}
        .event-item.ev-normal{border-color:rgba(16,185,129,0.15);color:#34d399}
        .ev-time{color:var(--text-muted);font-size:0.72rem;flex-shrink:0;min-width:60px;font-weight:500}
        .ev-text{flex:1}
        @keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}

        /* ===== CONTROLS ===== */
        .controls{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:16px 20px;
            background:var(--card);border:1px solid var(--card-border);border-radius:16px;
            backdrop-filter:var(--blur);margin-bottom:20px}
        .ip-input{flex:1;min-width:200px;border:1px solid var(--line);background:rgba(255,255,255,0.04);
            color:var(--text);border-radius:10px;padding:10px 14px;outline:none;font-family:inherit;font-size:0.9rem}
        .ip-input:focus{border-color:rgba(59,130,246,0.4)}
        [data-theme="light"] .ip-input{background:rgba(0,0,0,0.03)}
        .btn{border:none;border-radius:10px;padding:10px 18px;font-weight:700;font-size:0.85rem;
            cursor:pointer;color:#fff;transition:transform 0.15s,opacity 0.15s;font-family:inherit}
        .btn:hover{transform:translateY(-1px);opacity:0.9}
        .btn-danger{background:linear-gradient(145deg,#ef4444,#dc2626)}
        .btn-success{background:linear-gradient(145deg,#10b981,#059669)}
        .btn-inline{border:1px solid var(--line);background:transparent;color:var(--text);
            padding:4px 12px;border-radius:6px;font-size:0.78rem;cursor:pointer;font-weight:600;font-family:inherit}
        .btn-inline:hover{background:rgba(255,255,255,0.04)}

        /* ===== TABLES ===== */
        .tables{display:grid;grid-template-columns:1fr 1.5fr;gap:16px;margin-bottom:20px}
        .table-wrap{overflow-x:auto}
        table{width:100%;border-collapse:collapse;text-align:left}
        th,td{padding:10px 14px;border-bottom:1px solid var(--line)}
        th{font-size:0.7rem;color:var(--text-muted);font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
        td{font-size:0.85rem}
        tr:last-child td{border-bottom:none}

        .badge{border-radius:999px;font-size:0.68rem;padding:3px 10px;font-weight:700;letter-spacing:0.5px}
        .badge-critical{background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.2)}
        .badge-high{background:rgba(245,158,11,0.12);color:#f59e0b;border:1px solid rgba(245,158,11,0.2)}
        .badge-medium{background:rgba(234,179,8,0.12);color:#eab308;border:1px solid rgba(234,179,8,0.2)}
        .badge-low{background:rgba(16,185,129,0.12);color:#10b981;border:1px solid rgba(16,185,129,0.2)}

        .footer{margin-top:20px;text-align:center;color:var(--text-muted);font-size:0.75rem}

        @media(max-width:1024px){
            .shell{width:min(980px,98vw);margin:12px auto;padding-bottom:24px}
            .grid-2,.grid-3,.grid-eq,.tables{grid-template-columns:1fr}
            .topbar{flex-direction:column;align-items:flex-start;gap:14px}
            .brand{width:100%}
            .actions{width:100%;justify-content:space-between}
            .status-wrap{align-items:flex-start}
            .timeline{flex-wrap:wrap;justify-content:center}
            .chart-shell,.pie-shell{height:280px}
        }
        @media(max-width:760px){
            body{overflow-x:hidden}
            .shell{width:100%;margin:0 auto;padding:10px 10px 18px}
            .phase-banner{padding:12px 14px}
            .phase-banner .banner-sub{margin-left:0}
            .timeline{
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:8px;
                padding:10px;
            }
            .t-connector{display:none}
            .t-step{justify-content:flex-start;padding:9px 10px;font-size:0.78rem}
            .topbar,.card,.metric,.gauge-wrap,.controls{border-radius:14px}
            .topbar{padding:14px}
            .brand{gap:10px}
            .brand h1{font-size:1.9rem}
            .site-chip{
                width:100%;
                white-space:nowrap;
                overflow:hidden;
                text-overflow:ellipsis;
            }
            .actions{gap:10px}
            .logout-link{padding:9px 12px;font-size:0.85rem}
            .theme-toggle{padding:9px 12px}
            .metrics{grid-template-columns:1fr 1fr;gap:10px}
            .metric,.gauge-wrap{padding:14px}
            .metric-value{font-size:1.8rem}
            .gauge-wrap{grid-column:1 / -1;flex-direction:column;gap:12px}
            .gauge-info{margin-left:0}
            .chart-shell,.pie-shell{height:230px}
            .card-head{font-size:0.95rem;margin-bottom:12px}
            .event-feed{max-height:220px}
            .controls{padding:0;gap:10px}
            .ip-input{min-width:0;width:100%;font-size:16px;padding:13px 12px}
            .btn{width:100%;font-size:16px;padding:13px 12px}
            .tables .card{padding:12px}
            .table-wrap{overflow-x:visible}
            table,tbody,tr,td{display:block;width:100%}
            thead{display:none}
            tr{
                border:1px solid var(--line);
                border-radius:10px;
                margin-bottom:10px;
                padding:6px 10px;
                background:rgba(255,255,255,0.015);
            }
            td{
                border-bottom:none;
                padding:7px 0;
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:12px;
                font-size:0.82rem;
            }
            td::before{
                content:attr(data-label);
                color:var(--text-muted);
                text-transform:uppercase;
                letter-spacing:0.4px;
                font-size:0.66rem;
                font-weight:700;
                flex-shrink:0;
            }
            td[colspan]{
                display:block;
                opacity:0.65;
                text-align:left;
                padding:8px 0;
            }
            td[colspan]::before{content:''}
            .btn-inline{padding:6px 10px;font-size:0.75rem}
            .footer{font-size:0.7rem;padding-bottom:6px}
        }
        @media(max-width:420px){
            .metrics{grid-template-columns:1fr}
            .brand h1{font-size:1.7rem}
            .metric-value{font-size:1.6rem}
            .chart-shell,.pie-shell{height:210px}
        }
    </style>
</head>
<body class="phase-normal" data-theme="dark">
<div class="ambient"><div class="ambient-orb orb-1"></div><div class="ambient-orb orb-2"></div></div>
<div class="vignette"></div>

<div class="shell">
    <!-- PHASE BANNER -->
    <div id="phaseBanner" class="phase-banner">
        <span class="banner-icon" id="bannerIcon">&#128737;</span>
        <span class="banner-text" id="bannerText">System Protected</span>
        <span class="banner-sub" id="bannerSub">All systems operational</span>
    </div>

    <!-- PHASE TIMELINE -->
    <div class="timeline">
        <div class="t-step active" id="tNormal"><span class="t-dot"></span>Normal</div>
        <div class="t-connector" id="tc1"></div>
        <div class="t-step" id="tDetect"><span class="t-dot"></span>Detection</div>
        <div class="t-connector" id="tc2"></div>
        <div class="t-step" id="tMitigate"><span class="t-dot"></span>Mitigation</div>
        <div class="t-connector" id="tc3"></div>
        <div class="t-step" id="tRecover"><span class="t-dot"></span>Recovery</div>
    </div>

    <!-- TOP BAR -->
    <div class="topbar">
        <div class="brand">
            <div class="shield-icon">&#128737;</div>
            <h1>DDoS Dashboard</h1>
            <div id="siteChip" class="site-chip">Protected Site: --</div>
        </div>
        <div class="actions">
            <button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">&#9728;&#65039; Light</button>
            <div class="status-wrap">
                <div id="systemStatus" class="status-pill"><span class="dot"></span>Loading...</div>
                <div id="localTime" class="local-time">--:--:--</div>
                <a href="/admin/logout" class="logout-link">Logout</a>
            </div>
        </div>
    </div>

    <!-- METRICS ROW -->
    <div class="metrics">
        <div class="metric" id="metricRequests">
            <div class="metric-label">Total Requests</div>
            <div id="totalRequests" class="metric-value">0</div>
            <div id="trendRequests" class="metric-trend trend-flat">&mdash;</div>
        </div>
        <div class="metric" id="metricAttacks">
            <div class="metric-label">Attacks Detected</div>
            <div id="attacksDetected" class="metric-value">0</div>
            <div id="trendAttacks" class="metric-trend trend-flat">&mdash;</div>
        </div>
        <div class="metric">
            <div class="metric-label">IPs Blocked</div>
            <div id="ipsBlocked" class="metric-value">0</div>
            <div id="trendBlocked" class="metric-trend trend-flat">&mdash;</div>
        </div>
        <div class="metric">
            <div class="metric-label">System Uptime</div>
            <div id="uptime" class="metric-value">0s</div>
        </div>
        <div class="gauge-wrap">
            <svg class="gauge-svg" viewBox="0 0 160 100">
                <path class="gauge-bg" d="M 15 85 A 65 65 0 0 1 145 85"/>
                <path class="gauge-fill" id="gaugeFill" d="M 15 85 A 65 65 0 0 1 145 85"
                    stroke-dasharray="204" stroke-dashoffset="204" stroke="var(--ok)"/>
                <text class="gauge-text" x="80" y="72" text-anchor="middle" id="gaugeValue">0</text>
                <text class="gauge-label" x="80" y="92" text-anchor="middle">Threat Level</text>
            </svg>
            <div class="gauge-info">
                <div class="gauge-title">Threat Level</div>
                <div class="gauge-status" id="gaugeStatus" style="color:var(--ok)">SAFE</div>
            </div>
        </div>
    </div>

    <!-- MITIGATION PANEL (shown during attacks) -->
    <div class="miti-panel" id="mitiPanel">
        <div class="card-head" style="color:var(--danger)">&#128308; Active Attack Mitigation</div>
        <div class="miti-grid">
            <div class="miti-stat"><div class="miti-stat-value" id="mitiBlocked">0</div><div class="miti-stat-label">IPs Blocked</div></div>
            <div class="miti-stat"><div class="miti-stat-value" id="mitiRate">0%</div><div class="miti-stat-label">Mitigation Rate</div></div>
            <div class="miti-stat"><div class="miti-stat-value" id="mitiDuration">0s</div><div class="miti-stat-label">Attack Duration</div></div>
            <div class="miti-stat"><div class="miti-stat-value" id="mitiThreat">0</div><div class="miti-stat-label">Threat Level</div></div>
        </div>
    </div>

    <!-- RECOVERY PANEL (shown during recovery) -->
    <div class="recovery-panel" id="recoveryPanel">
        <div class="card-head" style="color:var(--info)">&#128260; System Recovery in Progress</div>
        <div class="recovery-bar-track"><div class="recovery-bar-fill" id="recoveryFill" style="width:0%"></div></div>
        <div class="recovery-info">
            <span id="recoveryPct">0% complete</span>
            <span id="recoveryTime">Elapsed: 0s</span>
        </div>
    </div>

    <!-- CHARTS -->
    <div class="grid-2">
        <div class="card">
            <div class="card-head">Network Traffic <span class="sub">(today)</span></div>
            <div class="chart-shell"><canvas id="trafficChart"></canvas></div>
        </div>
        <div class="card">
            <div class="card-head">Attack Types</div>
            <div class="pie-shell"><canvas id="attackTypeChart"></canvas></div>
        </div>
    </div>

    <!-- EVENT FEED + CONTROLS -->
    <div class="grid-eq">
        <div class="card">
            <div class="card-head">&#9889; Live Event Feed</div>
            <div class="event-feed" id="eventFeed">
                <div class="event-item ev-normal"><span class="ev-time">--:--</span><span class="ev-text">System initialized. Monitoring active.</span></div>
            </div>
        </div>
        <div class="card">
            <div class="card-head">&#128275; IP Management</div>
            <div class="controls" style="border:none;padding:0;background:none;margin-bottom:0">
                <input type="text" id="ipInput" class="ip-input" placeholder="Enter IP address">
                <button class="btn btn-danger" onclick="blockIP()">Block</button>
                <button class="btn btn-success" onclick="unblockIP()">Unblock</button>
            </div>
        </div>
    </div>

    <!-- TABLES -->
    <div class="tables">
        <div class="card">
            <div class="card-head">&#128683; Blocked IPs</div>
            <div class="table-wrap">
                <table><thead><tr><th>IP Address</th><th>Location</th><th>Action</th></tr></thead>
                <tbody id="blockedTable"></tbody></table>
            </div>
        </div>
        <div class="card">
            <div class="card-head">&#128680; Recent Attacks</div>
            <div class="table-wrap">
                <table><thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Location</th><th>Duration</th><th>Severity</th></tr></thead>
                <tbody id="attacksTable"></tbody></table>
            </div>
        </div>
    </div>

    <div id="footerText" class="footer">Updated: --</div>
</div>

<script>
/* ========== THEME ========== */
function toggleTheme(){
    const t=document.body.getAttribute('data-theme')==='dark'?'light':'dark';
    document.body.setAttribute('data-theme',t);
    localStorage.setItem('dashboardTheme',t);
    document.getElementById('themeBtn').innerHTML=t==='dark'?'&#9728;&#65039; Light':'&#127769; Dark';
    if(trafficChart)updateChartColors(t);
}
const savedTheme=localStorage.getItem('dashboardTheme')||'dark';
document.body.setAttribute('data-theme',savedTheme);
document.getElementById('themeBtn').innerHTML=savedTheme==='dark'?'&#9728;&#65039; Light':'&#127769; Dark';

function updateChartColors(theme){
    if(!trafficChart||!attackTypeChart)return;
    const c=theme==='dark'?'#6b7fa0':'#64748b';
    const g=theme==='dark'?'rgba(255,255,255,0.04)':'rgba(0,0,0,0.04)';
    Chart.defaults.color=c;Chart.defaults.borderColor=g;
    trafficChart.options.scales.x.grid.color=g;trafficChart.options.scales.y.grid.color=g;
    trafficChart.options.scales.x.ticks.color=c;trafficChart.options.scales.y.ticks.color=c;
    trafficChart.update();attackTypeChart.update();
}

/* ========== STATE ========== */
let trafficChart=null,attackTypeChart=null;
let trafficRequests=[],trafficAttacks=[];
let currentDayKey='',prevTotal=0,prevAttacks=0,prevBlocked=0,prevUptime=0;
let currentPhase='normal',lastPhase='normal';
let eventLog=[];
const MAX_EVENTS=80;

/* ========== PHASE UI ========== */
const phaseConfig={
    normal:  {icon:'\\u{1F6E1}',text:'System Protected',sub:'All systems operational',cls:'phase-normal'},
    detection:{icon:'\\u26A0\\uFE0F',text:'Threat Detected \\u2014 Analyzing Traffic',sub:'Anomalous patterns under analysis',cls:'phase-detection'},
    mitigation:{icon:'\\uD83D\\uDED1',text:'Active Attack \\u2014 Mitigating Threats',sub:'Blocking malicious traffic',cls:'phase-mitigation'},
    recovery:{icon:'\\uD83D\\uDD04',text:'Recovering \\u2014 Stabilizing Systems',sub:'Returning to normal operations',cls:'phase-recovery'}
};
const timelineOrder=['normal','detection','mitigation','recovery'];
const stepIds=['tNormal','tDetect','tMitigate','tRecover'];
const connIds=['tc1','tc2','tc3'];

function setPhaseUI(phase){
    const cfg=phaseConfig[phase]||phaseConfig.normal;
    // Body class
    document.body.classList.remove('phase-normal','phase-detection','phase-mitigation','phase-recovery');
    document.body.classList.add(cfg.cls);
    // Banner
    document.getElementById('bannerIcon').textContent=cfg.icon;
    document.getElementById('bannerText').textContent=cfg.text;
    document.getElementById('bannerSub').textContent=cfg.sub;
    // Timeline
    const idx=timelineOrder.indexOf(phase);
    stepIds.forEach((id,i)=>{
        const el=document.getElementById(id);
        el.classList.remove('active','done');
        if(i<idx)el.classList.add('done');
        else if(i===idx)el.classList.add('active');
    });
    connIds.forEach((id,i)=>{
        const el=document.getElementById(id);
        el.classList.toggle('done',i<idx);
    });
    // Panels
    document.getElementById('mitiPanel').classList.toggle('visible',phase==='detection'||phase==='mitigation');
    document.getElementById('recoveryPanel').classList.toggle('visible',phase==='recovery');
    // Metric glow
    document.getElementById('metricAttacks').classList.toggle('glow',phase==='detection'||phase==='mitigation');

    // Log phase transition event
    if(phase!==lastPhase){
        const msgs={
            normal:'\\u2705 System returned to normal. All threats cleared.',
            detection:'\\u26A0\\uFE0F Anomalous traffic detected! Analyzing patterns...',
            mitigation:'\\uD83D\\uDED1 Attack confirmed! Mitigation in progress. Blocking malicious IPs.',
            recovery:'\\uD83D\\uDD04 Attack subsided. Entering recovery phase.'
        };
        const evCls={normal:'ev-normal',detection:'ev-detect',mitigation:'ev-block',recovery:'ev-recover'};
        addEvent(msgs[phase]||'Phase changed.',evCls[phase]||'ev-normal');
        lastPhase=phase;
    }
}

/* ========== EVENT FEED ========== */
function addEvent(text,cls){
    const now=new Date();
    const t=now.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    eventLog.push({time:t,text:text,cls:cls||'ev-normal'});
    if(eventLog.length>MAX_EVENTS)eventLog.shift();
    renderEvents();
}
function renderEvents(){
    const feed=document.getElementById('eventFeed');
    feed.innerHTML=eventLog.map(e=>
        `<div class="event-item ${e.cls}"><span class="ev-time">${e.time}</span><span class="ev-text">${e.text}</span></div>`
    ).join('');
    feed.scrollTop=feed.scrollHeight;
}

/* ========== THREAT GAUGE ========== */
function updateGauge(level){
    level=Math.max(0,Math.min(100,level));
    const maxDash=204;
    const offset=maxDash-(level/100)*maxDash;
    const fill=document.getElementById('gaugeFill');
    fill.setAttribute('stroke-dashoffset',offset);
    let color='var(--ok)',label='SAFE';
    if(level>=80){color='var(--danger)';label='CRITICAL';}
    else if(level>=60){color='var(--danger)';label='HIGH';}
    else if(level>=40){color='var(--warn)';label='ELEVATED';}
    else if(level>=20){color='var(--warn)';label='GUARDED';}
    fill.setAttribute('stroke',color);
    document.getElementById('gaugeValue').textContent=level;
    const gs=document.getElementById('gaugeStatus');
    gs.textContent=label;gs.style.color=color;
}

/* ========== CHARTS ========== */
function toDayKey(d){return d.toISOString().slice(0,10)}
function getMinuteIndex(d){return d.getHours()*60+d.getMinutes()}

function initDayBuckets(date){
    const base=new Date(date);base.setHours(0,0,0,0);
    trafficRequests=[];trafficAttacks=[];
    for(let m=0;m<1440;m++){
        const t=new Date(base.getTime()+m*60000);
        trafficRequests.push({x:t,y:0});trafficAttacks.push({x:t,y:0});
    }
    currentDayKey=toDayKey(date);
    if(trafficChart){
        trafficChart.data.datasets[0].data=trafficRequests;
        trafficChart.data.datasets[1].data=trafficAttacks;
        trafficChart.resetZoom();trafficChart.update('none');
    }
}
function resetChartOnRestart(){
    initDayBuckets(new Date());
    if(trafficChart){trafficChart.data.datasets[0].data=trafficRequests;
        trafficChart.data.datasets[1].data=trafficAttacks;trafficChart.resetZoom();trafficChart.update('none');}
}
function fmtUptime(s){
    s=Math.max(0,Math.floor(s||0));
    const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
    if(h>0)return`${h}h ${m}m`;if(m>0)return`${m}m ${sec}s`;return`${sec}s`;
}
function fmtDuration(s){
    s=Math.max(0,Math.floor(s||0));
    const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
    if(h>0)return`${h}h ${m}m ${sec}s`;if(m>0)return`${m}m ${sec}s`;return`${sec}s`;
}
function toStatusClass(st){
    st=(st||'').toLowerCase();
    if(st==='healthy')return'status-pill';
    if(st==='critical')return'status-pill status-critical';
    if(st==='recovering')return'status-pill status-recovering';
    if(st==='degraded')return'status-pill status-degraded';
    if(st==='mitigating')return'status-pill status-critical';
    if(st==='detecting')return'status-pill status-degraded';
    return'status-pill';
}

const donutCenterText={
    id:'donutCenterText',
    afterDraw(chart){
        if(chart.config.type!=='doughnut')return;
        const total=chart.data.datasets[0].data.reduce((a,b)=>a+(Number(b)||0),0);
        const meta=chart.getDatasetMeta(0);
        if(!meta||!meta.data||!meta.data.length)return;
        const x=meta.data[0].x,y=meta.data[0].y,ctx=chart.ctx;
        ctx.save();ctx.textAlign='center';
        ctx.fillStyle=document.body.getAttribute('data-theme')==='dark'?'#6b7fa0':'#64748b';
        ctx.font='600 11px Inter,sans-serif';ctx.fillText('TOTAL',x,y-5);
        ctx.fillStyle=document.body.getAttribute('data-theme')==='dark'?'#e8edf5':'#0f172a';
        ctx.font='800 26px Inter,sans-serif';ctx.fillText(String(total),x,y+22);
        ctx.restore();
    }
};

function initCharts(){
    if(typeof Chart==='undefined')return false;
    Chart.register(donutCenterText);
    const theme=document.body.getAttribute('data-theme');
    const c=theme==='dark'?'#6b7fa0':'#64748b';
    const g=theme==='dark'?'rgba(255,255,255,0.04)':'rgba(0,0,0,0.04)';
    Chart.defaults.color=c;Chart.defaults.borderColor=g;
    Chart.defaults.font.family="'Inter',system-ui,sans-serif";

    trafficChart=new Chart(document.getElementById('trafficChart').getContext('2d'),{
        type:'line',
        data:{datasets:[
            {label:'Requests/min',data:trafficRequests,borderColor:'#3b82f6',
                backgroundColor:'rgba(59,130,246,0.1)',borderWidth:2,fill:true,tension:0.4,pointRadius:0,pointHoverRadius:4},
            {label:'Attacks/min',data:trafficAttacks,borderColor:'#ef4444',
                backgroundColor:'rgba(239,68,68,0.08)',borderWidth:2,fill:false,tension:0.4,pointRadius:0,pointHoverRadius:5}
        ]},
        options:{responsive:true,maintainAspectRatio:false,animation:false,
            interaction:{mode:'index',intersect:false},
            scales:{
                x:{type:'time',
                    min:(()=>{const d=new Date();d.setHours(0,0,0,0);return d})(),
                    max:(()=>{const d=new Date();d.setHours(23,59,0,0);return d})(),
                    time:{unit:'hour',tooltipFormat:'HH:mm',displayFormats:{minute:'HH:mm',hour:'HH:mm'}},
                    grid:{color:g,drawBorder:false},ticks:{color:c,maxRotation:0,autoSkip:true,maxTicksLimit:13}},
                y:{beginAtZero:true,grid:{color:g,drawBorder:false},ticks:{color:c,precision:0}}
            },
            plugins:{
                legend:{labels:{boxWidth:10,usePointStyle:true,pointStyle:'circle',font:{size:11}}},
                tooltip:{backgroundColor:'rgba(10,18,37,0.95)',titleColor:'#fff',bodyColor:'#fff',padding:12,cornerRadius:8,
                    callbacks:{title:function(items){if(!items.length)return'';
                        return new Date(items[0].parsed.x).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}}},
                zoom:{zoom:{wheel:{enabled:true,speed:0.2},pinch:{enabled:true},mode:'x'},
                    pan:{enabled:true,mode:'x'},
                    limits:{x:{min:(()=>{const d=new Date();d.setHours(0,0,0,0);return d.getTime()})(),
                               max:(()=>{const d=new Date();d.setHours(23,59,0,0);return d.getTime()})()}}}
            }
        }
    });
    initDayBuckets(new Date());

    attackTypeChart=new Chart(document.getElementById('attackTypeChart').getContext('2d'),{
        type:'doughnut',
        data:{labels:['IP Flooding','Distributed','Behavioral','Endpoint Surge','Bot Periodic','Subnet Flood'],
            datasets:[{data:[0,0,0,0,0,0],
                backgroundColor:['#ef4444','#f59e0b','#10b981','#8b5cf6','#ec4899','#06b6d4'],
                borderWidth:0,hoverOffset:4}]},
        options:{responsive:true,maintainAspectRatio:false,cutout:'72%',
            plugins:{legend:{position:'bottom',labels:{padding:16,boxWidth:10,usePointStyle:true,pointStyle:'circle',font:{size:11}}},
                tooltip:{backgroundColor:'rgba(10,18,37,0.95)',padding:12,cornerRadius:8}}}
    });
    return true;
}

/* ========== DATA FETCHING ========== */
let prevReqRate=0;

async function fetchStats(){
    try{
        const res=await fetch('/admin/stats',{credentials:'same-origin'});
        if(res.status===401){window.location.href='/admin/login';return}
        const data=await res.json();
        const total=data.detection.total_requests||0;
        const atk=data.detection.attacks_detected||0;
        const blk=data.detection.blocked_ips_count||0;

        document.getElementById('totalRequests').textContent=total.toLocaleString();
        document.getElementById('attacksDetected').textContent=atk.toLocaleString();
        document.getElementById('ipsBlocked').textContent=blk.toLocaleString();

        const uptime=data.uptime||0;
        document.getElementById('uptime').textContent=fmtUptime(uptime);

        // Trends
        const reqDelta=total-prevTotal;
        const atkDelta=atk-prevAttacks;
        const blkDelta=blk-prevBlocked;
        if(prevTotal>0){
            const tr=document.getElementById('trendRequests');
            if(reqDelta>10){tr.className='metric-trend trend-up';tr.textContent='\\u2191 +'+reqDelta+'/poll';}
            else{tr.className='metric-trend trend-flat';tr.textContent='\\u2014 Stable';}
        }
        if(prevAttacks>0||atk>0){
            const ta=document.getElementById('trendAttacks');
            if(atkDelta>0){ta.className='metric-trend trend-up';ta.textContent='\\u26A0 +'+atkDelta+' new';}
            else{ta.className='metric-trend trend-flat';ta.textContent='No new attacks';}
        }
        if(prevBlocked>=0){
            const tb=document.getElementById('trendBlocked');
            if(blkDelta>0){tb.className='metric-trend trend-up';tb.textContent='\\uD83D\\uDD12 +'+blkDelta+' blocked';}
            else if(blkDelta<0){tb.className='metric-trend trend-down';tb.textContent='\\u2935 '+blkDelta+' released';}
            else{tb.className='metric-trend trend-flat';tb.textContent=blk>0?blk+' active':'None';}
        }


        // Restart detection
        if(prevUptime>0&&uptime<prevUptime-10){resetChartOnRestart();prevTotal=0;prevAttacks=0;prevBlocked=0;}
        prevUptime=uptime;

        // Status pill: prefer lifecycle phase over raw health to avoid showing
        // HEALTHY while active mitigation/detection is in progress.
        const statusEl=document.getElementById('systemStatus');
        let status=(data.health.status||'unknown').toUpperCase();
        if(data.system_phase){
            const phase=(data.system_phase.phase||'').toLowerCase();
            if(phase==='mitigation')status='MITIGATING';
            else if(phase==='detection')status='DETECTING';
            else if(phase==='recovery')status='RECOVERING';
        }
        statusEl.className=toStatusClass(status);
        statusEl.innerHTML='<span class="dot"></span>'+status;

        // Phase
        if(data.system_phase){
            const sp=data.system_phase;
            currentPhase=sp.phase||'normal';
            setPhaseUI(currentPhase);
            updateGauge(sp.threat_level||0);

            // Mitigation panel
            document.getElementById('mitiBlocked').textContent=sp.blocked_count||0;
            document.getElementById('mitiRate').textContent=(sp.mitigation_rate||0)+'%';
            document.getElementById('mitiDuration').textContent=fmtDuration(sp.phase_duration||0);
            document.getElementById('mitiThreat').textContent=sp.threat_level||0;

            // Recovery panel
            if(currentPhase==='recovery'){
                const pct=Math.round((sp.recovery_progress||0)*100);
                document.getElementById('recoveryFill').style.width=pct+'%';
                document.getElementById('recoveryPct').textContent=pct+'% complete';
                document.getElementById('recoveryTime').textContent='Elapsed: '+fmtDuration(sp.phase_duration||0);
            }

            // Log attack events from delta
            if(atkDelta>0&&(currentPhase==='detection'||currentPhase==='mitigation')){
                addEvent('\\u{1F6A8} '+atkDelta+' new attack(s) detected. Blocked IPs: '+blk,'ev-detect');
            }
            if(blkDelta>0){
                addEvent('\\u{1F6AB} '+blkDelta+' IP(s) blocked by mitigation engine.','ev-block');
            }
        }

        // Traffic chart
        if(trafficChart){
            const now=new Date();const todayKey=toDayKey(now);
            if(!currentDayKey||currentDayKey!==todayKey){initDayBuckets(now);prevTotal=total;prevAttacks=atk;}
            const rDelta=Math.max(0,total-prevTotal);
            const aDelta=Math.max(0,atk-prevAttacks);
            const idx=getMinuteIndex(now);
            trafficRequests[idx].y+=rDelta;trafficAttacks[idx].y+=aDelta;
            prevTotal=total;prevAttacks=atk;prevBlocked=blk;
            trafficChart.update('none');
        }else{
            prevTotal=total;prevAttacks=atk;prevBlocked=blk;
        }

        // Doughnut
        if(attackTypeChart){
            const types=data.attacks.attack_types||{};
            attackTypeChart.data.datasets[0].data=[
                types['IP_FLOODING']||0,types['DDOS_DISTRIBUTED']||0,
                types['BEHAVIORAL_BLOCK']||0,types['ENDPOINT_SURGE']||0,
                types['BOT_PERIODIC_SPIKE']||0,types['SUBNET_FLOOD']||0
            ];attackTypeChart.update();
        }

        // Blocked IPs table
        const bt=document.getElementById('blockedTable');
        const bd=data.blocked_ip_details||[];
        bt.innerHTML=bd.map(item=>{
            const ip=item.ip||'N/A',loc=item.location||'Unknown';
            return`<tr><td data-label="IP Address">${ip}</td><td data-label="Location">${loc}</td><td data-label="Action"><button class="btn-inline" onclick="unblockDirect('${ip}')">Unblock</button></td></tr>`;
        }).join('')||'<tr><td colspan="3" style="opacity:0.5">No blocked IPs</td></tr>';
    }catch(err){console.error('Stats fetch error:',err);}
}

async function fetchAttacks(){
    try{
        const res=await fetch('/admin/attacks?limit=15',{credentials:'same-origin'});
        if(res.status===401){window.location.href='/admin/login';return}
        const attacks=await res.json();
        const tbody=document.getElementById('attacksTable');
        tbody.innerHTML=attacks.reverse().map(a=>{
            const ts=Number(a.timestamp||(Date.now()/1000));
            const t=new Date(ts*1000).toLocaleTimeString();
            const sev=String(a.severity||'LOW').toUpperCase();
            const sevCls='badge-'+sev.toLowerCase();
            const loc=a.location||'Unknown';
            const dur=fmtDuration(a.duration_seconds||0);
            return`<tr><td data-label="Time">${t}</td><td data-label="Type">${a.attack_type||'N/A'}</td><td data-label="Source IP">${a.source_ip||'N/A'}</td><td data-label="Location">${loc}</td><td data-label="Duration">${dur}</td><td data-label="Severity"><span class="badge ${sevCls}">${sev}</span></td></tr>`;
        }).join('')||'<tr><td colspan="6" style="opacity:0.5">No attacks recorded</td></tr>';
    }catch(err){console.error('Attacks fetch error:',err);}
}

async function blockIP(){
    const ip=document.getElementById('ipInput').value.trim();if(!ip)return;
    const res=await fetch('/admin/block/'+ip,{method:'POST',credentials:'same-origin'});
    if(res.status===401){window.location.href='/admin/login';return}
    document.getElementById('ipInput').value='';
    addEvent('\\u{1F6AB} Manually blocked IP: '+ip,'ev-block');
    fetchStats();fetchAttacks();
}
async function unblockIP(){
    const ip=document.getElementById('ipInput').value.trim();if(!ip)return;
    const res=await fetch('/admin/unblock/'+ip,{method:'POST',credentials:'same-origin'});
    if(res.status===401){window.location.href='/admin/login';return}
    document.getElementById('ipInput').value='';
    addEvent('\\u2705 Manually unblocked IP: '+ip,'ev-normal');
    fetchStats();fetchAttacks();
}
async function unblockDirect(ip){
    const res=await fetch('/admin/unblock/'+ip,{method:'POST',credentials:'same-origin'});
    if(res.status===401){window.location.href='/admin/login';return}
    addEvent('\\u2705 Unblocked IP: '+ip,'ev-normal');
    fetchStats();fetchAttacks();
}

/* ========== CLOCK ========== */
function updateClock(){
    const now=new Date();
    const t=now.toLocaleTimeString();
    const el=document.getElementById('localTime');
    const ft=document.getElementById('footerText');
    if(el)el.textContent=t;
    if(ft)ft.textContent='Updated: '+now.toLocaleDateString()+' '+t;
}

/* ========== BOOTSTRAP ========== */
function startPolling(){
    const chip=document.getElementById('siteChip');
    if(chip)chip.textContent='Protected: '+window.location.origin;
    updateClock();setInterval(updateClock,1000);
    fetchStats();fetchAttacks();
    setInterval(fetchStats,500);
    setInterval(fetchAttacks,2000);
}

(function bootstrap(){
    startPolling();
    if(typeof Chart!=='undefined'){try{initCharts();}catch(e){console.error('Chart init:',e);}return;}
    const fb=document.createElement('script');
    fb.src='https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js';
    fb.onload=function(){try{initCharts();}catch(e){console.error('Chart init(fb):',e);}};
    document.head.appendChild(fb);
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

@app.route('/metrics')
def metrics():
    """Prometheus metrics export endpoint."""
    stats = detector.get_statistics()
    health_status = health_monitor.get_overall_health()['status']
    is_healthy = 1 if health_status == 'HEALTHY' else 0
    
    lines = [
        "# HELP ddos_total_requests Total number of HTTP requests processed by the DDoS engine.",
        "# TYPE ddos_total_requests counter",
        f"ddos_total_requests {stats.get('total_requests', 0)}",
        "# HELP ddos_attacks_detected Total number of DDoS attacks detected.",
        "# TYPE ddos_attacks_detected counter",
        f"ddos_attacks_detected {stats.get('attacks_detected', 0)}",
        "# HELP ddos_blocked_ips_count Current number of IPs blocked.",
        "# TYPE ddos_blocked_ips_count gauge",
        f"ddos_blocked_ips_count {stats.get('blocked_ips_count', 0)}",
        "# HELP ddos_blocked_requests Total number of requests blocked.",
        "# TYPE ddos_blocked_requests counter",
        f"ddos_blocked_requests {stats.get('blocked_requests', 0)}",
        "# HELP ddos_system_health Current health status (1 for healthy, 0 for otherwise).",
        "# TYPE ddos_system_health gauge",
        f"ddos_system_health {is_healthy}",
    ]
    
    return app.response_class(
        response='\\n'.join(lines) + '\\n',
        status=200,
        mimetype='text/plain; version=0.0.4'
    )

if __name__ == '__main__':
    logger.info("Starting DDoS Protected Web Application on port 8000")
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
