"""Attack Notification System - Webhook and logging alerts"""
import time
import logging
import threading
from typing import Dict, List, Optional
from collections import deque

logger = logging.getLogger(__name__)


class AttackNotifier:
    def __init__(self, webhook_url: Optional[str] = None, cooldown: int = 60):
        self.webhook_url = webhook_url
        self.cooldown = cooldown
        self.attack_log = deque(maxlen=500)
        self._last_notified = {}
        self._lock = threading.Lock()

    def notify(self, attack_type: str, source_ip: str, confidence: float,
               severity: str, details: str = ''):
        now = time.time()
        event = {
            'timestamp': now,
            'attack_type': attack_type,
            'source_ip': source_ip,
            'confidence': confidence,
            'severity': severity,
            'details': details
        }

        with self._lock:
            self.attack_log.append(event)

        # Cooldown per IP to avoid notification flood
        key = f"{attack_type}:{source_ip}"
        if key in self._last_notified and now - self._last_notified[key] < self.cooldown:
            return

        self._last_notified[key] = now
        logger.warning("ATTACK ALERT: %s from %s (severity=%s, confidence=%.2f) %s",
                       attack_type, source_ip, severity, confidence, details)

        if self.webhook_url:
            threading.Thread(target=self._send_webhook, args=(event,), daemon=True).start()

    def _send_webhook(self, event: Dict):
        if not self.webhook_url:
            return
        try:
            import urllib.request
            import json
            payload = json.dumps(event).encode('utf-8')
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=10)
            logger.info("Webhook notification sent to %s", self.webhook_url)
        except Exception as e:
            logger.error("Webhook notification failed: %s", e)

    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        with self._lock:
            attacks = list(self.attack_log)
        return attacks[-limit:]

    def get_attack_summary(self) -> Dict:
        with self._lock:
            attacks = list(self.attack_log)
        if not attacks:
            return {'total_attacks': 0, 'attack_types': {}, 'top_attackers': {}}

        type_counts = {}
        ip_counts = {}
        for a in attacks:
            type_counts[a['attack_type']] = type_counts.get(a['attack_type'], 0) + 1
            ip_counts[a['source_ip']] = ip_counts.get(a['source_ip'], 0) + 1

        top_attackers = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        return {
            'total_attacks': len(attacks),
            'attack_types': type_counts,
            'top_attackers': top_attackers,
            'latest': attacks[-1] if attacks else None
        }
