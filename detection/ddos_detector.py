"""DDoS Detection Engine - Multi-algorithm threat detection system"""
import time
import logging
import os
import sqlite3
import statistics
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import redis as redis_lib
    _redis_available = True
except ImportError:
    _redis_available = False

try:
    from mitigation.edge_firewall import edge_firewall
except (ImportError, ModuleNotFoundError):
    edge_firewall = None

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis key constants
# ---------------------------------------------------------------------------
_KEY_TOTAL     = 'ddos:stats:total_requests'
_KEY_ATTACKS   = 'ddos:stats:attacks_detected'
_KEY_BLOCKED_R = 'ddos:stats:blocked_requests'
_KEY_BLOCKED_SET = 'ddos:blocked_ips'


# IPs in these ranges are never auto-blocked (loopback, Docker internals, RFC-1918)
_NEVER_BLOCK_PREFIXES = (
    '127.', '::1',
    '10.', '192.168.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
)

def _is_private(ip: str) -> bool:
    return bool(ip and any(ip.startswith(p) for p in _NEVER_BLOCK_PREFIXES))


@dataclass
class TrafficMetrics:
    timestamp: float
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    status_code: int
    response_time: float
    payload_size: int

@dataclass
class AttackSignature:
    attack_type: str
    severity: str
    confidence: float
    source_ips: List[str]
    target_endpoint: str
    timestamp: float


class DDoSDetector:
    def __init__(self, time_window=60, requests_threshold=50, unique_ip_threshold=50):
        self.time_window = time_window
        self.requests_threshold = requests_threshold
        self.unique_ip_threshold = unique_ip_threshold
        self.block_private_ips = os.environ.get('BLOCK_PRIVATE_IPS', 'true').lower() == 'true'
        self.traffic_buffer = deque(maxlen=10000)
        self.ip_request_count = defaultdict(lambda: deque(maxlen=1000))
        self.endpoint_request_count = defaultdict(lambda: deque(maxlen=1000))
        self.subnet_request_count = defaultdict(lambda: deque(maxlen=1000))

        # In-memory blocked set is kept as a fast local cache; Redis is source of truth.
        self.blocked_ips: set = set()

        # ------------------------------------------------------------------
        # Redis connection (primary shared store)
        # ------------------------------------------------------------------
        self._redis: Optional['redis_lib.Redis'] = None
        if _redis_available:
            redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
            try:
                self._redis = redis_lib.from_url(redis_url, decode_responses=True,
                                                 socket_connect_timeout=2,
                                                 socket_timeout=2)
                self._redis.ping()
                logger.info("Connected to Redis at %s", redis_url)
            except Exception:
                logger.warning("Redis unavailable — falling back to SQLite for shared state.")
                self._redis = None

        # ------------------------------------------------------------------
        # SQLite fallback (used only when Redis is unavailable)
        # ------------------------------------------------------------------
        db_dir = os.environ.get('DDOS_STATE_DIR', os.path.dirname(os.path.dirname(__file__)))
        self.db_path = os.environ.get('DDOS_STATE_DB', os.path.join(db_dir, 'ddos_state.db'))
        self._init_db()

        # Load initial blocked-IP set into the local cache
        self._load_blocked_ips()

    # ==========================================================================
    # Core traffic analysis
    # ==========================================================================

    def analyze_traffic(self, metric: TrafficMetrics) -> Tuple[bool, Optional[AttackSignature]]:
        now = time.time()
        self.traffic_buffer.append(metric)
        self._incr('total_requests')
        self.ip_request_count[metric.ip_address].append(metric.timestamp)
        self.endpoint_request_count[metric.endpoint].append(metric.timestamp)

        # /24 subnet tracking
        try:
            subnet = str(ipaddress.ip_network(f"{metric.ip_address}/24", strict=False))
            self.subnet_request_count[subnet].append(metric.timestamp)
        except Exception:
            subnet = "unknown"

        if self.is_blocked(metric.ip_address):
            self._incr('blocked_requests')

        if self._detect_ip_flooding(metric):
            self._incr('attacks_detected')
            logger.warning("IP Flooding detected from %s", metric.ip_address)
            return True, AttackSignature("IP_FLOODING", "HIGH", 0.95, [metric.ip_address], metric.endpoint, now)

        if self._detect_periodic_spikes(metric.ip_address):
            self._incr('attacks_detected')
            logger.warning("Periodic spike pattern (Bot) detected from %s", metric.ip_address)
            return True, AttackSignature("BOT_PERIODIC_SPIKE", "HIGH", 0.85, [metric.ip_address], "multiple", now)

        if self._detect_endpoint_surge(metric.endpoint):
            self._incr('attacks_detected')
            logger.warning("Unexplained surge in requests to endpoint: %s", metric.endpoint)
            return True, AttackSignature("ENDPOINT_SURGE", "MEDIUM", 0.80, [], metric.endpoint, now)

        if self._detect_distributed_attack():
            self._incr('attacks_detected')
            logger.warning("Distributed DDoS attack detected")
            return True, AttackSignature("DDOS_DISTRIBUTED", "CRITICAL", 0.92, [], "multiple", now)

        if subnet != "unknown" and self._detect_subnet_flooding(subnet):
            self._incr('attacks_detected')
            logger.warning("Suspicious traffic from subnet: %s", subnet)
            return True, AttackSignature("SUBNET_FLOOD", "HIGH", 0.88, [subnet], "multiple", now)

        return False, None

    # ==========================================================================
    # Detection algorithms (unchanged)
    # ==========================================================================

    def _detect_ip_flooding(self, metric: TrafficMetrics) -> bool:
        if _is_private(metric.ip_address) and not self.block_private_ips:
            return False
        current_time = time.time()
        recent = [ts for ts in self.ip_request_count[metric.ip_address]
                  if current_time - ts <= self.time_window]
        threshold = self._adaptive_threshold(subject_ip=metric.ip_address)
        if len(recent) > threshold:
            self._block_ip(metric.ip_address)
            return True
        return False

    def _detect_periodic_spikes(self, ip: str) -> bool:
        timestamps = list(self.ip_request_count[ip])
        if len(timestamps) < 10:
            return False
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        if not intervals:
            return False
        avg_interval = statistics.mean(intervals)
        if avg_interval < 0.1:
            return False
        std_dev = statistics.pstdev(intervals)
        if std_dev < 0.05 * avg_interval:
            self._block_ip(ip)
            return True
        return False

    def _detect_endpoint_surge(self, endpoint: str) -> bool:
        current_time = time.time()
        recent = [ts for ts in self.endpoint_request_count[endpoint]
                  if current_time - ts <= self.time_window]
        return len(recent) > self.requests_threshold * 5

    def _detect_subnet_flooding(self, subnet: str) -> bool:
        current_time = time.time()
        recent = [ts for ts in self.subnet_request_count[subnet]
                  if current_time - ts <= self.time_window]
        return len(recent) > self.requests_threshold * 3

    def _adaptive_threshold(self, subject_ip: Optional[str] = None) -> int:
        now = time.time()
        try:
            per_ip: Dict[str, int] = {}
            for m in list(self.traffic_buffer):
                if now - m.timestamp <= self.time_window:
                    per_ip[m.ip_address] = per_ip.get(m.ip_address, 0) + 1
            if subject_ip and subject_ip in per_ip:
                per_ip.pop(subject_ip, None)
            counts = list(per_ip.values())
            if not counts:
                return int(self.requests_threshold)
            mean = statistics.mean(counts)
            std = statistics.pstdev(counts) if len(counts) > 1 else 0
            return max(int(self.requests_threshold), int(mean + 3 * std))
        except Exception:
            return int(self.requests_threshold)

    def _detect_distributed_attack(self) -> bool:
        current_time = time.time()
        recent = [m for m in self.traffic_buffer if current_time - m.timestamp <= self.time_window]
        if not recent:
            return False
        unique_ips = set(m.ip_address for m in recent)
        return len(unique_ips) > self.unique_ip_threshold and len(recent) / self.time_window > 50

    # ==========================================================================
    # Redis-first shared state helpers (SQLite fallback)
    # ==========================================================================

    def _incr(self, key: str, amount: int = 1):
        """Atomically increment a counter in Redis (or SQLite)."""
        if self._redis:
            try:
                redis_key = {'total_requests': _KEY_TOTAL,
                             'attacks_detected': _KEY_ATTACKS,
                             'blocked_requests': _KEY_BLOCKED_R}[key]
                self._redis.incr(redis_key, amount)
                return
            except Exception:
                pass  # fall through to SQLite
        self._sqlite_incr(key, amount)

    def _get_stats_from_store(self) -> Dict:
        if self._redis:
            try:
                pipe = self._redis.pipeline()
                pipe.get(_KEY_TOTAL)
                pipe.get(_KEY_ATTACKS)
                pipe.get(_KEY_BLOCKED_R)
                total, attacks, blocked = pipe.execute()
                return {
                    'total_requests':   int(total   or 0),
                    'attacks_detected': int(attacks  or 0),
                    'blocked_requests': int(blocked  or 0),
                }
            except Exception:
                pass
        return self._sqlite_get_stats()

    # --- Blocked-IP helpers ---------------------------------------------------

    def _block_ip(self, ip: str):
        """Block an IP. Private/loopback handling is configurable."""
        if _is_private(ip) and not self.block_private_ips:
            return
        self.blocked_ips.add(ip)
        if edge_firewall:
            try:
                edge_firewall.block_ip(ip)
            except Exception:
                logger.exception("Edge firewall block failed for %s", ip)
        if self._redis:
            try:
                self._redis.sadd(_KEY_BLOCKED_SET, ip)
                return
            except Exception:
                pass
        self._sqlite_block(ip)

    def _load_blocked_ips(self):
        if self._redis:
            try:
                ips = self._redis.smembers(_KEY_BLOCKED_SET)
                self.blocked_ips = set(ips)
                return
            except Exception:
                pass
        self._sqlite_load_blocked()

    def is_blocked(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            return True
        # Check authoritative store for cross-worker blocks
        if self._redis:
            try:
                if self._redis.sismember(_KEY_BLOCKED_SET, ip):
                    self.blocked_ips.add(ip)
                    return True
                return False
            except Exception:
                pass
        # SQLite fallback
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT 1 FROM blocked_ips WHERE ip = ?', (ip,))
            if cur.fetchone():
                self.blocked_ips.add(ip)
                return True
        except Exception:
            pass
        finally:
            try: conn.close()
            except Exception: pass
        return False

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips and not self.is_blocked(ip):
            return False
        self.blocked_ips.discard(ip)
        if edge_firewall:
            try:
                edge_firewall.unblock_ip(ip)
            except Exception:
                logger.exception("Edge firewall unblock failed for %s", ip)
        if self._redis:
            try:
                self._redis.srem(_KEY_BLOCKED_SET, ip)
            except Exception:
                pass
        # Always clean SQLite too (used as persistent backup)
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
            conn.commit()
        except Exception:
            pass
        finally:
            try: conn.close()
            except Exception: pass
        logger.info("IP %s has been unblocked", ip)
        return True

    def prune_blocks(self, max_age=3600):
        """Unblock IPs older than max_age seconds (SQLite-tracked only, Redis TTL handles the rest)."""
        now = time.time()
        expired = []
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT ip FROM blocked_ips WHERE ? - blocked_at > ?', (now, max_age))
            expired = [row[0] for row in cur.fetchall()]
        except Exception:
            logger.exception("Failed to query expired blocks")
        finally:
            try: conn.close()
            except Exception: pass
        for ip in expired:
            self.unblock_ip(ip)
        return len(expired)

    def get_statistics(self) -> Dict:
        self._load_blocked_ips()
        stats = self._get_stats_from_store()
        stats['blocked_ips_count'] = len(self.blocked_ips)
        stats['traffic_buffer_size'] = len(self.traffic_buffer)
        return stats

    # ==========================================================================
    # SQLite fallback implementations
    # ==========================================================================

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at REAL
            )''')
            cur.execute('''CREATE TABLE IF NOT EXISTS global_stats (
                key TEXT PRIMARY KEY,
                val INTEGER DEFAULT 0
            )''')
            for key in ('total_requests', 'attacks_detected', 'blocked_requests'):
                cur.execute('INSERT OR IGNORE INTO global_stats(key, val) VALUES (?, 0)', (key,))
            conn.commit()
        except Exception:
            logger.exception("Failed to initialize ddos state DB")
        finally:
            try: conn.close()
            except Exception: pass

    def _sqlite_incr(self, key: str, amount: int = 1):
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            cur = conn.cursor()
            cur.execute('UPDATE global_stats SET val = val + ? WHERE key = ?', (amount, key))
            conn.commit()
        except Exception:
            pass
        finally:
            try: conn.close()
            except Exception: pass

    def _sqlite_get_stats(self) -> dict:
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            cur = conn.cursor()
            cur.execute('SELECT key, val FROM global_stats')
            return {row[0]: row[1] for row in cur.fetchall()}
        except Exception:
            return {}
        finally:
            try: conn.close()
            except Exception: pass

    def _sqlite_block(self, ip: str):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('INSERT OR REPLACE INTO blocked_ips(ip, blocked_at) VALUES (?, ?)',
                        (ip, time.time()))
            conn.commit()
        except Exception:
            logger.exception("Failed to persist blocked IP %s to SQLite", ip)
        finally:
            try: conn.close()
            except Exception: pass

    def _sqlite_load_blocked(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT ip FROM blocked_ips')
            for (ip,) in cur.fetchall():
                self.blocked_ips.add(ip)
        except Exception:
            logger.exception("Failed to load blocked IPs from SQLite")
        finally:
            try: conn.close()
            except Exception: pass
