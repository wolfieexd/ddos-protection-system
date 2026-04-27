"""Health Monitor with Auto-Recovery and Circuit Breaker"""
import time
import logging
from typing import Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class ServiceState(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    RECOVERING = "recovering"

class HealthMonitor:
    def __init__(self, check_interval=60, failure_threshold=3, recovery_time=60):
        self.check_interval = check_interval
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.service_health = {}
        self.failure_counts = {}
        self.last_check = {}
        self.recovery_start = {}
        # Track when each service entered its current state
        self.state_since = {}
        # Track the last time we saw an attack (for phase derivation)
        self.last_attack_time = {}

    def register_service(self, service_name: str):
        self.service_health[service_name] = ServiceState.HEALTHY
        self.failure_counts[service_name] = 0
        self.last_check[service_name] = time.time()
        self.state_since[service_name] = time.time()
        logger.info("Service '%s' registered with HEALTHY state", service_name)

    def report_failure(self, service_name: str):
        if service_name not in self.service_health:
            self.register_service(service_name)
        self.failure_counts[service_name] = self.failure_counts.get(service_name, 0) + 1
        count = self.failure_counts[service_name]
        self.last_attack_time[service_name] = time.time()
        logger.warning("Service '%s' failure #%d", service_name, count)
        if count >= self.failure_threshold:
            prev = self.service_health.get(service_name)
            self.service_health[service_name] = ServiceState.CRITICAL
            if prev != ServiceState.CRITICAL:
                self.state_since[service_name] = time.time()
            self.recovery_start[service_name] = time.time()
            logger.critical("Service '%s' entered CRITICAL state", service_name)

    def report_success(self, service_name: str):
        if service_name not in self.service_health:
            self.register_service(service_name)
            return
        self.failure_counts[service_name] = 0
        current_state = self.service_health.get(service_name, ServiceState.HEALTHY)

        if current_state == ServiceState.CRITICAL:
            # Transition CRITICAL → RECOVERING on first success
            self.service_health[service_name] = ServiceState.RECOVERING
            self.state_since[service_name] = time.time()
            if service_name not in self.recovery_start:
                self.recovery_start[service_name] = time.time()
            logger.info("Service '%s' transitioned from CRITICAL to RECOVERING", service_name)
        elif current_state == ServiceState.RECOVERING:
            recovery_elapsed = time.time() - self.recovery_start.get(service_name, time.time())
            if recovery_elapsed >= self.recovery_time:
                self.service_health[service_name] = ServiceState.HEALTHY
                self.state_since[service_name] = time.time()
                logger.info("Service '%s' recovered to HEALTHY", service_name)
        elif current_state == ServiceState.DEGRADED:
            self.service_health[service_name] = ServiceState.HEALTHY
            self.state_since[service_name] = time.time()
            logger.info("Service '%s' back to HEALTHY", service_name)

    def get_service_state(self, service_name: str) -> Optional[ServiceState]:
        """Return the raw ServiceState enum for a specific service."""
        return self.service_health.get(service_name)

    def recovery_progress(self, service_name: str) -> float:
        """Return recovery progress as 0.0–1.0 for a service in RECOVERING state."""
        state = self.service_health.get(service_name)
        if state != ServiceState.RECOVERING:
            if state == ServiceState.HEALTHY:
                return 1.0
            return 0.0
        start = self.recovery_start.get(service_name, time.time())
        elapsed = time.time() - start
        return min(1.0, max(0.0, elapsed / self.recovery_time))

    def get_overall_health(self) -> Dict:
        if not self.service_health:
            return {'status': 'UNKNOWN', 'services': {}, 'message': 'No services registered'}

        recovering_count = sum(1 for state in self.service_health.values() if state == ServiceState.RECOVERING)
        critical_count = sum(1 for state in self.service_health.values() if state == ServiceState.CRITICAL)
        degraded_count = sum(1 for state in self.service_health.values() if state == ServiceState.DEGRADED)

        if critical_count > 0:
            overall = 'CRITICAL'
        elif recovering_count > 0:
            overall = 'RECOVERING'
        elif degraded_count > 0:
            overall = 'DEGRADED'
        else:
            overall = 'HEALTHY'

        return {
            'status': overall,
            'services': {name: state.value for name, state in self.service_health.items()},
            'timestamp': time.time()
        }

    def trigger_recovery(self, service_name: str) -> bool:
        if service_name in self.service_health:
            self.service_health[service_name] = ServiceState.RECOVERING
            self.recovery_start[service_name] = time.time()
            self.state_since[service_name] = time.time()
            logger.info("Recovery triggered for service '%s'", service_name)
            return True
        return False
