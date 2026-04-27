"""Attack Notification System - Webhook and logging alerts"""
import time
import logging
import threading
import ipaddress
import os
import json
import urllib.request
import urllib.parse
from typing import Dict, List, Optional
from collections import deque

try:
    import redis as redis_lib
    _redis_available = True
except ImportError:
    _redis_available = False

logger = logging.getLogger(__name__)

_KEY_ATTACK_EVENTS = 'ddos:attacks:events'
_KEY_ATTACK_TOTAL = 'ddos:attacks:total'
_KEY_ATTACK_TYPES = 'ddos:attacks:types'
_KEY_ATTACKERS = 'ddos:attacks:attackers'


class AttackNotifier:
    def __init__(self, webhook_url: Optional[str] = None, cooldown: int = 60):
        self.webhook_url = webhook_url
        self.cooldown = cooldown
        attack_log_maxlen = int(os.environ.get('ATTACK_LOG_MAXLEN', '5000'))
        if attack_log_maxlen < 100:
            attack_log_maxlen = 100
        self.attack_log = deque(maxlen=attack_log_maxlen)
        self.attack_log_maxlen = attack_log_maxlen
        self._last_notified = {}
        self._attack_windows = {}
        self._lock = threading.Lock()
        self._geoip_source = os.environ.get('GEOIP_SOURCE', 'auto').strip().lower()
        self._geoip_api_url = os.environ.get('GEOIP_API_URL', '').strip()
        self._geoip_api_timeout = float(os.environ.get('GEOIP_API_TIMEOUT', '2.0'))
        self._geoip_cache = {}
        self._geoip_reader = self._init_geoip_reader()
        self._redis = None
        if _redis_available:
            redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
            try:
                self._redis = redis_lib.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                self._redis.ping()
            except Exception:
                logger.warning("Notifier Redis unavailable; using in-memory attack log only.")
                self._redis = None

    def _init_geoip_reader(self):
        """Initialize optional MaxMind GeoIP reader if configured."""
        db_path = os.environ.get('GEOIP_DB_PATH')
        if not db_path:
            return None
        if not os.path.exists(db_path):
            logger.warning("GEOIP_DB_PATH set but file not found: %s", db_path)
            return None

        try:
            import geoip2.database  # type: ignore
            return geoip2.database.Reader(db_path)
        except Exception:
            logger.exception("Failed to initialize GeoIP reader")
            return None

    @staticmethod
    def _network_scope_fallback(ip: str) -> str:
        """Return a deterministic network-scope label from the IP itself."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "Invalid IP"

        if addr.is_loopback:
            return "Loopback"
        if addr.is_private:
            return "Private Network"
        if addr.is_link_local:
            return "Link Local"
        if addr.is_multicast:
            return "Multicast"
        if addr.is_reserved:
            return "Reserved"
        if addr.is_unspecified:
            return "Unspecified"
        return "Public (GeoIP not configured)"

    def classify_ip_location(self, ip: str) -> str:
        """Resolve IP to location using GeoIP DB, fallback to network scope labels."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "Invalid IP"

        # Keep local/private/special addresses explicit
        if (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return self._network_scope_fallback(ip)

        if ip in self._geoip_cache:
            return self._geoip_cache[ip]

        if self._geoip_source in ('auto', 'db') and self._geoip_reader is not None:
            try:
                city = self._geoip_reader.city(ip)
                city_name = (city.city.name or '').strip()
                country_name = (city.country.name or '').strip()
                if city_name and country_name:
                    location = f"{city_name}, {country_name}"
                    self._geoip_cache[ip] = location
                    return location
                if country_name:
                    self._geoip_cache[ip] = country_name
                    return country_name
            except Exception:
                logger.debug("GeoIP city lookup failed for %s", ip, exc_info=True)

        if self._geoip_source in ('auto', 'api'):
            api_location = self._lookup_location_via_api(ip)
            if api_location:
                self._geoip_cache[ip] = api_location
                return api_location

        fallback = self._network_scope_fallback(ip)
        self._geoip_cache[ip] = fallback
        return fallback

    def _lookup_location_via_api(self, ip: str) -> Optional[str]:
        """Lookup location using configured GeoIP API URL template."""
        if not self._geoip_api_url:
            return None

        try:
            url = self._geoip_api_url.format(ip=ip, ip_url=urllib.parse.quote(ip))
        except Exception:
            logger.warning("Invalid GEOIP_API_URL template; expected placeholders like {ip}")
            return None

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ddos-protection-system/1.0'})
            with urllib.request.urlopen(req, timeout=self._geoip_api_timeout) as resp:
                payload = json.loads(resp.read().decode('utf-8', errors='replace'))
        except Exception:
            logger.debug("GeoIP API lookup failed for %s via %s", ip, url, exc_info=True)
            return None

        # Supports common formats:
        # ipwho.is: {success, city, country}
        # ip-api: {status, city, country}
        # ipapi.co: {city, country_name}
        try:
            if isinstance(payload, dict):
                if 'success' in payload and payload.get('success') is False:
                    return None
                if payload.get('status') == 'fail':
                    return None

                city = (payload.get('city') or '').strip()
                country = (payload.get('country') or payload.get('country_name') or '').strip()
                if city and country:
                    return f"{city}, {country}"
                if country:
                    return country
        except Exception:
            logger.debug("GeoIP API response parse failed for %s", ip, exc_info=True)
        return None

    def notify(self, attack_type: str, source_ip: str, confidence: float,
               severity: str, details: str = ''):
        now = time.time()
        with self._lock:
            key = f"{attack_type}:{source_ip}"
            window = self._attack_windows.get(key)
            if window is None:
                window = {'first_seen': now, 'last_seen': now, 'count': 1}
            else:
                window['last_seen'] = now
                window['count'] += 1
            self._attack_windows[key] = window

            duration_seconds = max(0, int(window['last_seen'] - window['first_seen']))
            event = {
                'timestamp': now,
                'attack_type': attack_type,
                'source_ip': source_ip,
                'confidence': confidence,
                'severity': severity,
                'details': details,
                'first_seen': window['first_seen'],
                'last_seen': window['last_seen'],
                'duration_seconds': duration_seconds,
                'occurrences': window['count'],
                'location': self.classify_ip_location(source_ip),
            }
            self.attack_log.append(event)
            if self._redis:
                try:
                    payload = json.dumps(event, separators=(',', ':'))
                    pipe = self._redis.pipeline()
                    pipe.incr(_KEY_ATTACK_TOTAL, 1)
                    pipe.hincrby(_KEY_ATTACK_TYPES, attack_type, 1)
                    pipe.hincrby(_KEY_ATTACKERS, source_ip, 1)
                    pipe.lpush(_KEY_ATTACK_EVENTS, payload)
                    pipe.ltrim(_KEY_ATTACK_EVENTS, 0, self.attack_log_maxlen - 1)
                    pipe.execute()
                except Exception:
                    logger.debug("Failed to persist attack event to Redis", exc_info=True)

        # Cooldown per IP to avoid notification flood
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
        if self._redis:
            try:
                rows = self._redis.lrange(_KEY_ATTACK_EVENTS, 0, max(0, limit - 1))
                attacks = []
                for row in rows:
                    try:
                        attacks.append(json.loads(row))
                    except Exception:
                        continue
                return list(reversed(attacks))
            except Exception:
                logger.debug("Failed to read recent attacks from Redis", exc_info=True)
        with self._lock:
            attacks = list(self.attack_log)
        return attacks[-limit:]

    def get_attack_summary(self) -> Dict:
        if self._redis:
            try:
                pipe = self._redis.pipeline()
                pipe.get(_KEY_ATTACK_TOTAL)
                pipe.hgetall(_KEY_ATTACK_TYPES)
                pipe.hgetall(_KEY_ATTACKERS)
                pipe.lindex(_KEY_ATTACK_EVENTS, 0)
                total_raw, types_raw, attackers_raw, latest_raw = pipe.execute()
                total = int(total_raw or 0)
                type_counts = {k: int(v) for k, v in (types_raw or {}).items()}
                ip_counts = {k: int(v) for k, v in (attackers_raw or {}).items()}
                top_attackers = dict(
                    sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                )
                latest = None
                if latest_raw:
                    try:
                        latest = json.loads(latest_raw)
                    except Exception:
                        latest = None
                if total == 0 and not type_counts and not top_attackers and not latest:
                    return {'total_attacks': 0, 'attack_types': {}, 'top_attackers': {}}
                return {
                    'total_attacks': total,
                    'attack_types': type_counts,
                    'top_attackers': top_attackers,
                    'latest': latest
                }
            except Exception:
                logger.debug("Failed to read attack summary from Redis", exc_info=True)
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
