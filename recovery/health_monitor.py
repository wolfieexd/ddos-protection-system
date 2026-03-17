"""Health Monitor with Auto-Recovery and Circuit Breaker"""
import time
import logging
from typing import Dict
from enum import Enum

logger = logging.getLogger(__name__)

class ServiceState(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    RECOVERING = "recovering"

class HealthMonitor:
    def __init__(self, check_interval=60, failure_threshold=3, recovery_time=300):
        self.check_interval = check_interval
        self.failure_threshold = failure_threshold
        self.recovery_time = recovery_time
        self.service_health = {}
        self.failure_counts = {}
        self.last_check = {}
        self.recovery_start = {}

    def register_service(self, service_name: str):
        self.service_health[service_name] = ServiceState.HEALTHY
        self.failure_counts[service_name] = 0
        self.last_check[service_name] = time.time()
        logger.info("Service '%s' registered with HEALTHY state", service_name)

    def report_failure(self, service_name: str):
        if service_name not in self.service_health:
            self.register_service(service_name)
        self.failure_counts[service_name] = self.failure_counts.get(service_name, 0) + 1
        count = self.failure_counts[service_name]
        logger.warning("Service '%s' failure #%d", service_name, count)
        if count >= self.failure_threshold:
            self.service_health[service_name] = ServiceState.CRITICAL
            self.recovery_start[service_name] = time.time()
            logger.critical("Service '%s' entered CRITICAL state", service_name)

    def report_success(self, service_name: str):
        if service_name not in self.service_health:
            self.register_service(service_name)
            return
        self.failure_counts[service_name] = 0
        current_state = self.service_health.get(service_name, ServiceState.HEALTHY)

        if current_state == ServiceState.RECOVERING:
            recovery_duration = time.time() - self.recovery_start.get(service_name, 0)
            if recovery_duration >= self.recovery_time:
                self.service_health[service_name] = ServiceState.HEALTHY
                logger.info("Service '%s' recovered to HEALTHY", service_name)
        elif current_state != ServiceState.HEALTHY:
            self.service_health[service_name] = ServiceState.HEALTHY
            logger.info("Service '%s' back to HEALTHY", service_name)

    def get_overall_health(self) -> Dict:
        if not self.service_health:
            return {'status': 'UNKNOWN', 'services': {}, 'message': 'No services registered'}

        critical_count = sum(1 for state in self.service_health.values() if state == ServiceState.CRITICAL)
        degraded_count = sum(1 for state in self.service_health.values() if state == ServiceState.DEGRADED)

        if critical_count > 0:
            overall = 'CRITICAL'
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
            logger.info("Recovery triggered for service '%s'", service_name)
            return True
        return False
