"""DDoS Detection Engine - Multi-algorithm threat detection system"""
import time
import logging
import os
import sqlite3
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

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
        self.traffic_buffer = deque(maxlen=10000)
        self.ip_request_count = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips = set()
        self.stats = {'total_requests': 0, 'blocked_requests': 0, 'attacks_detected': 0}

        # Persistent state DB (shared on disk across worker processes)
        db_dir = os.environ.get('DDOS_STATE_DIR', os.path.dirname(os.path.dirname(__file__)))
        self.db_path = os.environ.get('DDOS_STATE_DB', os.path.join(db_dir, 'ddos_state.db'))
        self._init_db()
        self._load_blocked_ips()

    def analyze_traffic(self, metric: TrafficMetrics) -> Tuple[bool, Optional[AttackSignature]]:
        self.traffic_buffer.append(metric)
        self.stats['total_requests'] += 1
        self.ip_request_count[metric.ip_address].append(metric.timestamp)

        if metric.ip_address in self.blocked_ips:
            self.stats['blocked_requests'] += 1

        if self._detect_ip_flooding(metric):
            self.stats['attacks_detected'] += 1
            logger.warning("IP Flooding detected from %s", metric.ip_address)
            return True, AttackSignature("IP_FLOODING", "HIGH", 0.95, [metric.ip_address], metric.endpoint, time.time())
        if self._detect_distributed_attack():
            self.stats['attacks_detected'] += 1
            logger.warning("Distributed DDoS attack detected")
            return True, AttackSignature("DDOS_DISTRIBUTED", "CRITICAL", 0.92, [], "multiple", time.time())
        return False, None

    def _detect_ip_flooding(self, metric: TrafficMetrics) -> bool:
        current_time = time.time()
        recent = [ts for ts in self.ip_request_count[metric.ip_address]
                  if current_time - ts <= self.time_window]
        threshold = self._adaptive_threshold(subject_ip=metric.ip_address)
        if len(recent) > threshold:
            self._persist_block(metric.ip_address)
            return True
        return False

    def _adaptive_threshold(self, subject_ip: Optional[str] = None) -> int:
        """Compute an adaptive threshold based on recent traffic distribution.

        Uses mean + 3*std of per-IP request counts in the recent time window,
        but never drops below configured `requests_threshold`.
        """
        now = time.time()
        # build counts per IP over the time window
        counts = []
        try:
            per_ip = {}
            for m in list(self.traffic_buffer):
                if now - m.timestamp <= self.time_window:
                    per_ip[m.ip_address] = per_ip.get(m.ip_address, 0) + 1
            # Exclude the subject IP from baseline calculation so spikes from the
            # candidate attacker do not inflate the adaptive threshold.
            if subject_ip and subject_ip in per_ip:
                per_ip.pop(subject_ip, None)
            counts = list(per_ip.values())
            if not counts:
                return int(self.requests_threshold)
            mean = statistics.mean(counts)
            std = statistics.pstdev(counts) if len(counts) > 1 else 0
            dyn = int(mean + 3 * std)
            return max(int(self.requests_threshold), dyn)
        except Exception:
            return int(self.requests_threshold)

    # --- Persistence helpers for blocked IPs ---
    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at REAL
            )''')
            conn.commit()
        except Exception:
            logger.exception("Failed to initialize ddos state DB")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _load_blocked_ips(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT ip FROM blocked_ips')
            rows = cur.fetchall()
            for (ip,) in rows:
                self.blocked_ips.add(ip)
        except Exception:
            logger.exception("Failed to load blocked IPs from DB")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _persist_block(self, ip: str):
        # Always update in-memory state first so detection reacts immediately
        self.blocked_ips.add(ip)
        try:
            now = time.time()
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('INSERT OR REPLACE INTO blocked_ips(ip, blocked_at) VALUES (?,?)', (ip, now))
            conn.commit()
        except Exception:
            logger.exception("Failed to persist blocked IP %s", ip)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _detect_distributed_attack(self) -> bool:
        current_time = time.time()
        recent = [m for m in self.traffic_buffer if current_time - m.timestamp <= self.time_window]
        if not recent:
            return False
        unique_ips = set(m.ip_address for m in recent)
        return len(unique_ips) > self.unique_ip_threshold and len(recent) / self.time_window > 50

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def unblock_ip(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            # remove from memory and DB
            try:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('DELETE FROM blocked_ips WHERE ip = ?', (ip,))
                conn.commit()
            except Exception:
                logger.exception("Failed to remove blocked IP %s from DB", ip)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            self.blocked_ips.discard(ip)
            logger.info("IP %s has been unblocked", ip)
            return True
        return False

    def get_statistics(self) -> Dict:
        return {
            **self.stats,
            'blocked_ips_count': len(self.blocked_ips),
            'traffic_buffer_size': len(self.traffic_buffer),
        }
