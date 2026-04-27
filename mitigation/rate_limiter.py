"""Traffic Analyzer and Rate Limiter with Token Bucket Algorithm"""
import time
import logging
from collections import defaultdict
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, default_rate=100, default_burst=20):
        self.default_rate = default_rate
        self.default_burst = default_burst
        self.local_buckets = {}

    def check_rate_limit(self, identifier: str, rate=None, burst=None) -> Tuple[bool, Dict]:
        rate = rate or self.default_rate
        burst = burst or self.default_burst
        current_time = time.time()

        if identifier not in self.local_buckets:
            self.local_buckets[identifier] = {'tokens': burst, 'last_update': current_time}

        bucket = self.local_buckets[identifier]
        time_passed = current_time - bucket['last_update']
        tokens_to_add = time_passed * (rate / 60.0)
        bucket['tokens'] = min(burst, bucket['tokens'] + tokens_to_add)
        bucket['last_update'] = current_time

        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            return True, {'allowed': True, 'remaining': int(bucket['tokens'])}

        retry_after = max(1, int((1.0 - bucket['tokens']) / (rate / 60.0)))
        return False, {'allowed': False, 'remaining': 0, 'retry_after': retry_after}

    def cleanup_stale_buckets(self, max_age=300):
        """Remove buckets that haven't been updated in max_age seconds."""
        current_time = time.time()
        stale = [k for k, v in self.local_buckets.items()
                 if current_time - v['last_update'] > max_age]
        for key in stale:
            del self.local_buckets[key]

    def get_stats(self) -> Dict:
        return {'active_buckets': len(self.local_buckets)}


class TrafficAnalyzer:
    def __init__(self):
        self.ip_profiles = defaultdict(lambda: {
            'first_seen': time.time(), 
            'request_count': 0, 
            'suspicious_score': 0,
            'user_agents': set(),
            'endpoints': set(),
            'status_codes': defaultdict(int)
        })
        self.ua_distribution = defaultdict(int)

    def analyze_request(self, ip: str, endpoint: str, method: str, user_agent: str,
                        status_code: int, response_time: float) -> Dict:
        profile = self.ip_profiles[ip]
        profile['request_count'] += 1
        profile['user_agents'].add(user_agent)
        profile['endpoints'].add(endpoint)
        profile['status_codes'][status_code] += 1
        
        self.ua_distribution[user_agent] += 1
        
        suspicious_score = self._calculate_suspicious_score(ip, profile, user_agent)
        profile['suspicious_score'] = suspicious_score

        return {
            'ip': ip, 'suspicious_score': suspicious_score,
            'risk_level': self._get_risk_level(suspicious_score),
            'recommendation': self._get_recommendation(suspicious_score)
        }

    def _calculate_suspicious_score(self, ip: str, profile: Dict, current_ua: str) -> float:
        score = 0.0
        now = time.time()
        age = now - profile['first_seen']
        
        # 1. Rate-based scoring
        if age > 0:
            req_per_second = profile['request_count'] / age
            if req_per_second > 50: score += 50
            elif req_per_second > 20: score += 30
            elif req_per_second > 10: score += 15
            elif req_per_second > 5: score += 5
            
        # 2. User-Agent diversity (An IP using many UAs is suspicious)
        ua_count = len(profile['user_agents'])
        if ua_count > 5: score += 40
        elif ua_count > 2: score += 15
        
        # 3. Endpoint diversity (Scraping/Scanning behavior)
        endpoint_count = len(profile['endpoints'])
        if endpoint_count > 20: score += 30
        
        # 4. Error rate (High 4xx/5xx responses)
        total_reqs = sum(profile['status_codes'].values())
        if total_reqs > 10:
            error_reqs = sum(v for k, v in profile['status_codes'].items() if k >= 400)
            error_rate = error_reqs / total_reqs
            if error_rate > 0.8: score += 40
            elif error_rate > 0.5: score += 20
            
        # 5. Global UA popularity (Using a very rare UA might be a custom bot)
        # (This is a bit simplistic as it depends on local traffic history)
        if self.ua_distribution[current_ua] < 2 and total_reqs > 50:
             score += 10

        return min(100.0, score)

    def _get_risk_level(self, score: float) -> str:
        if score >= 80: return "CRITICAL"
        elif score >= 60: return "HIGH"
        elif score >= 40: return "MEDIUM"
        elif score >= 20: return "LOW"
        return "SAFE"

    def _get_recommendation(self, score: float) -> str:
        if score >= 80: return "BLOCK_IMMEDIATELY"
        elif score >= 60: return "RATE_LIMIT_AGGRESSIVE"
        elif score >= 40: return "RATE_LIMIT_MODERATE"
        return "ALLOW"

    def get_stats(self) -> Dict:
        return {'tracked_ips': len(self.ip_profiles)}
