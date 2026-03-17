"""DDoS Detection Engine - Multi-algorithm threat detection system"""
import time
import logging
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
        if len(recent) > self.requests_threshold:
            self.blocked_ips.add(metric.ip_address)
            return True
        return False

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
