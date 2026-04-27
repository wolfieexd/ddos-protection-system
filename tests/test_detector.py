"""Unit Tests for DDoS Detection System"""
import unittest
import time
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.ddos_detector import DDoSDetector, TrafficMetrics, AttackSignature
from mitigation.rate_limiter import RateLimiter, TrafficAnalyzer
from mitigation.notifier import AttackNotifier
from recovery.health_monitor import HealthMonitor, ServiceState


def make_metric(ip="192.168.1.1", endpoint="/", method="GET", status=200):
    return TrafficMetrics(
        timestamp=time.time(), ip_address=ip, user_agent="Mozilla/5.0",
        endpoint=endpoint, method=method, status_code=status,
        response_time=0.1, payload_size=1024
    )


class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DDoSDetector(time_window=10, requests_threshold=5)

    def test_normal_traffic(self):
        """Normal traffic from different IPs should not be flagged"""
        for i in range(3):
            is_attack, signature = self.detector.analyze_traffic(make_metric(ip=f"192.168.1.{i}"))
            self.assertFalse(is_attack)
            self.assertIsNone(signature)

    def test_ip_flooding(self):
        """Single IP exceeding threshold should be blocked"""
        attacker_ip = "10.0.0.1"
        for _ in range(10):
            self.detector.analyze_traffic(make_metric(ip=attacker_ip))

        self.assertTrue(self.detector.is_blocked(attacker_ip),
                        f"IP {attacker_ip} should be blocked after flooding")

    def test_ip_flooding_increments_stats(self):
        """Attack detection should increment attacks_detected counter"""
        for _ in range(10):
            self.detector.analyze_traffic(make_metric(ip="10.0.0.1"))

        stats = self.detector.get_statistics()
        self.assertGreater(stats['attacks_detected'], 0, "attacks_detected should be incremented")

    def test_blocked_ip_increments_blocked_count(self):
        """Requests from blocked IPs should increment blocked_requests counter"""
        ip = "10.0.0.2"
        # First flood to get blocked
        for _ in range(10):
            self.detector.analyze_traffic(make_metric(ip=ip))
        self.assertTrue(self.detector.is_blocked(ip))

        # Send more requests from blocked IP
        self.detector.analyze_traffic(make_metric(ip=ip))
        stats = self.detector.get_statistics()
        self.assertGreater(stats['blocked_requests'], 0, "blocked_requests should be incremented")

    def test_unblock_ip(self):
        """Unblocking an IP should allow traffic again"""
        ip = "10.0.0.3"
        for _ in range(10):
            self.detector.analyze_traffic(make_metric(ip=ip))
        self.assertTrue(self.detector.is_blocked(ip))

        result = self.detector.unblock_ip(ip)
        self.assertTrue(result)
        self.assertFalse(self.detector.is_blocked(ip))

    def test_unblock_nonexistent_ip(self):
        """Unblocking an IP that was never blocked should return False"""
        result = self.detector.unblock_ip("1.2.3.4")
        self.assertFalse(result)

    def test_statistics_include_extra_fields(self):
        """get_statistics should return blocked_ips_count and traffic_buffer_size"""
        self.detector.analyze_traffic(make_metric())
        stats = self.detector.get_statistics()
        self.assertIn('blocked_ips_count', stats)
        self.assertIn('traffic_buffer_size', stats)
        self.assertEqual(stats['traffic_buffer_size'], 1)

    def test_traffic_spike_triggers_ip_flood(self):
        """A sudden spike from one IP should trigger IP_FLOODING detection"""
        detected = False
        for _ in range(20):
            is_attack, signature = self.detector.analyze_traffic(make_metric(ip="192.168.1.100"))
            if is_attack and signature and signature.attack_type == "IP_FLOODING":
                detected = True
                self.assertEqual(signature.severity, "HIGH")
                self.assertAlmostEqual(signature.confidence, 0.95, places=2)
                break
        self.assertTrue(detected, "Should detect IP flooding from traffic spike")


class TestRateLimiter(unittest.TestCase):
    def setUp(self):
        self.limiter = RateLimiter(default_rate=60, default_burst=5)

    def test_allows_within_burst(self):
        """Requests within burst capacity should be allowed"""
        for i in range(5):
            allowed, info = self.limiter.check_rate_limit("test-ip")
            self.assertTrue(allowed, f"Request {i+1} within burst should be allowed")
            self.assertTrue(info['allowed'])

    def test_blocks_after_burst_exceeded(self):
        """Requests exceeding burst capacity should be rejected"""
        for _ in range(5):
            self.limiter.check_rate_limit("test-ip")

        allowed, info = self.limiter.check_rate_limit("test-ip")
        self.assertFalse(allowed, "Request after burst exhausted should be blocked")
        self.assertIn('retry_after', info)
        self.assertGreater(info['retry_after'], 0)

    def test_tokens_refill_over_time(self):
        """Tokens should refill after waiting"""
        for _ in range(5):
            self.limiter.check_rate_limit("test-ip")

        # Wait for tokens to refill
        time.sleep(1.1)
        allowed, info = self.limiter.check_rate_limit("test-ip")
        self.assertTrue(allowed, "Token should refill after waiting")

    def test_separate_buckets_per_ip(self):
        """Different IPs should have independent buckets"""
        for _ in range(5):
            self.limiter.check_rate_limit("ip-a")

        allowed, _ = self.limiter.check_rate_limit("ip-b")
        self.assertTrue(allowed, "Different IP should have its own bucket")

    def test_cleanup_stale_buckets(self):
        """Stale buckets should be cleaned up"""
        self.limiter.check_rate_limit("old-ip")
        self.limiter.local_buckets["old-ip"]['last_update'] = time.time() - 600
        self.limiter.cleanup_stale_buckets(max_age=300)
        self.assertNotIn("old-ip", self.limiter.local_buckets)

    def test_get_stats(self):
        """get_stats should return active bucket count"""
        self.limiter.check_rate_limit("ip-1")
        self.limiter.check_rate_limit("ip-2")
        stats = self.limiter.get_stats()
        self.assertEqual(stats['active_buckets'], 2)

    def test_per_endpoint_rate_limit(self):
        """Custom rate/burst per endpoint should work"""
        # Use tight rate: 10/min, burst=2
        for i in range(2):
            allowed, _ = self.limiter.check_rate_limit("user1:/login", rate=10, burst=2)
            self.assertTrue(allowed, f"Request {i+1} within burst should be allowed")

        allowed, _ = self.limiter.check_rate_limit("user1:/login", rate=10, burst=2)
        self.assertFalse(allowed, "Should be rate limited on /login after burst")

        # Same IP on different endpoint should still work
        allowed, _ = self.limiter.check_rate_limit("user1:/api", rate=200, burst=50)
        self.assertTrue(allowed, "Different endpoint should have separate bucket")


class TestTrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TrafficAnalyzer()

    def test_safe_traffic(self):
        """Low-rate traffic should be classified as SAFE"""
        result = self.analyzer.analyze_request("192.168.1.1", "/", "GET", "Mozilla", 200, 0.1)
        self.assertIn(result['risk_level'], ["SAFE", "LOW"])
        self.assertEqual(result['recommendation'], "ALLOW")

    def test_risk_levels(self):
        """Risk levels should map correctly to scores"""
        self.assertEqual(self.analyzer._get_risk_level(0), "SAFE")
        self.assertEqual(self.analyzer._get_risk_level(25), "LOW")
        self.assertEqual(self.analyzer._get_risk_level(45), "MEDIUM")
        self.assertEqual(self.analyzer._get_risk_level(65), "HIGH")
        self.assertEqual(self.analyzer._get_risk_level(85), "CRITICAL")

    def test_recommendations(self):
        """Recommendations should map correctly to scores"""
        self.assertEqual(self.analyzer._get_recommendation(10), "ALLOW")
        self.assertEqual(self.analyzer._get_recommendation(45), "RATE_LIMIT_MODERATE")
        self.assertEqual(self.analyzer._get_recommendation(65), "RATE_LIMIT_AGGRESSIVE")
        self.assertEqual(self.analyzer._get_recommendation(85), "BLOCK_IMMEDIATELY")

    def test_get_stats(self):
        """get_stats should return tracked IP count"""
        self.analyzer.analyze_request("1.1.1.1", "/", "GET", "Mozilla", 200, 0.1)
        self.analyzer.analyze_request("2.2.2.2", "/", "GET", "Mozilla", 200, 0.1)
        stats = self.analyzer.get_stats()
        self.assertEqual(stats['tracked_ips'], 2)

    def test_scoring_thresholds(self):
        """Scoring should reach all risk levels based on request rate"""
        profile = {'first_seen': time.time() - 1, 'request_count': 3, 'user_agents': set(), 'endpoints': set(), 'status_codes': {}}
        self.assertEqual(self.analyzer._calculate_suspicious_score("1.1.1.1", profile, "UA"), 0)   # 3 rps -> SAFE
        
        profile['request_count'] = 8
        self.assertEqual(self.analyzer._calculate_suspicious_score("1.1.1.1", profile, "UA"), 5)  # 8 rps -> LOW
        
        profile['request_count'] = 15
        self.assertEqual(self.analyzer._calculate_suspicious_score("1.1.1.1", profile, "UA"), 15) # 15 rps -> MEDIUM
        
        profile['request_count'] = 30
        self.assertEqual(self.analyzer._calculate_suspicious_score("1.1.1.1", profile, "UA"), 30) # 30 rps -> HIGH
        
        profile['request_count'] = 100
        self.assertEqual(self.analyzer._calculate_suspicious_score("1.1.1.1", profile, "UA"), 50) # 100 rps -> CRITICAL


class TestAttackNotifier(unittest.TestCase):
    def setUp(self):
        self.notifier = AttackNotifier(cooldown=1)

    def test_notify_stores_event(self):
        """Notifications should be stored in attack log"""
        self.notifier.notify("IP_FLOODING", "10.0.0.1", 0.95, "HIGH")
        attacks = self.notifier.get_recent_attacks()
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]['attack_type'], "IP_FLOODING")
        self.assertEqual(attacks[0]['source_ip'], "10.0.0.1")

    def test_multiple_notifications(self):
        """Multiple notifications should all be recorded"""
        self.notifier.notify("IP_FLOODING", "10.0.0.1", 0.95, "HIGH")
        self.notifier.notify("DDOS_DISTRIBUTED", "10.0.0.2", 0.92, "CRITICAL")
        self.notifier.notify("BEHAVIORAL_BLOCK", "10.0.0.3", 0.80, "CRITICAL")
        attacks = self.notifier.get_recent_attacks()
        self.assertEqual(len(attacks), 3)

    def test_attack_summary(self):
        """Summary should aggregate attack types and top attackers"""
        for _ in range(5):
            self.notifier.notify("IP_FLOODING", "10.0.0.1", 0.95, "HIGH")
        self.notifier.notify("DDOS_DISTRIBUTED", "10.0.0.2", 0.92, "CRITICAL")

        summary = self.notifier.get_attack_summary()
        self.assertEqual(summary['total_attacks'], 6)
        self.assertEqual(summary['attack_types']['IP_FLOODING'], 5)
        self.assertEqual(summary['attack_types']['DDOS_DISTRIBUTED'], 1)
        self.assertIn('10.0.0.1', summary['top_attackers'])

    def test_recent_attacks_limit(self):
        """get_recent_attacks should respect limit parameter"""
        for i in range(10):
            self.notifier.notify("IP_FLOODING", f"10.0.0.{i}", 0.95, "HIGH")
        attacks = self.notifier.get_recent_attacks(limit=3)
        self.assertEqual(len(attacks), 3)

    def test_empty_summary(self):
        """Empty notifier should return zero counts"""
        summary = self.notifier.get_attack_summary()
        self.assertEqual(summary['total_attacks'], 0)

    def test_cooldown_prevents_duplicate_logs(self):
        """Cooldown should not prevent logging, only external notifications"""
        # Both calls should store events regardless of cooldown
        self.notifier.notify("IP_FLOODING", "10.0.0.1", 0.95, "HIGH")
        self.notifier.notify("IP_FLOODING", "10.0.0.1", 0.95, "HIGH")
        attacks = self.notifier.get_recent_attacks()
        self.assertEqual(len(attacks), 2)


class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.monitor = HealthMonitor(failure_threshold=3, recovery_time=1)

    def test_register_service(self):
        """Registered service should start as HEALTHY"""
        self.monitor.register_service("test")
        health = self.monitor.get_overall_health()
        self.assertEqual(health['status'], 'HEALTHY')
        self.assertEqual(health['services']['test'], 'healthy')

    def test_failure_threshold(self):
        """Service should become CRITICAL after threshold failures"""
        self.monitor.register_service("test")
        self.monitor.report_failure("test")
        self.monitor.report_failure("test")
        self.assertEqual(self.monitor.service_health["test"], ServiceState.HEALTHY)

        self.monitor.report_failure("test")
        self.assertEqual(self.monitor.service_health["test"], ServiceState.CRITICAL)

    def test_success_resets_failures(self):
        """Success should reset failure count"""
        self.monitor.register_service("test")
        self.monitor.report_failure("test")
        self.monitor.report_failure("test")
        self.monitor.report_success("test")
        self.assertEqual(self.monitor.failure_counts["test"], 0)

    def test_overall_health_critical(self):
        """Overall health should be CRITICAL if any service is critical"""
        self.monitor.register_service("svc1")
        self.monitor.register_service("svc2")
        for _ in range(3):
            self.monitor.report_failure("svc1")
        health = self.monitor.get_overall_health()
        self.assertEqual(health['status'], 'CRITICAL')

    def test_trigger_recovery(self):
        """trigger_recovery should set service to RECOVERING"""
        self.monitor.register_service("test")
        result = self.monitor.trigger_recovery("test")
        self.assertTrue(result)
        self.assertEqual(self.monitor.service_health["test"], ServiceState.RECOVERING)

    def test_recovery_to_healthy(self):
        """Service should recover to HEALTHY after recovery_time"""
        self.monitor.register_service("test")
        self.monitor.trigger_recovery("test")
        time.sleep(1.1)  # recovery_time=1 in setUp
        self.monitor.report_success("test")
        self.assertEqual(self.monitor.service_health["test"], ServiceState.HEALTHY)

    def test_trigger_recovery_unknown_service(self):
        """Triggering recovery on unknown service should return False"""
        result = self.monitor.trigger_recovery("nonexistent")
        self.assertFalse(result)

    def test_no_services_returns_unknown(self):
        """Empty monitor should return UNKNOWN status"""
        health = self.monitor.get_overall_health()
        self.assertEqual(health['status'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
