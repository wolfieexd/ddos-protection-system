# Methods Implemented in DDoS Protection System

This document provides a comprehensive list of all protection methods implemented in this project.

---

## DETECTION Methods

**File:** `detection/ddos_detector.py`

### 1. IP Flooding Detection
- **How It Works:** Counts requests per IP within a sliding time window. If requests exceed threshold → IP is blocked
- **Parameters:** `time_window=60s`, `requests_threshold=50`
- **Status:** ✅ Implemented

### 2. Distributed Attack Detection
- **How It Works:** Detects when many unique IPs send high volume of requests simultaneously
- **Parameters:** `unique_ip_threshold=50`, `rate > 50 req/s`
- **Status:** ✅ Implemented

---

## MITIGATION Methods

**File:** `mitigation/rate_limiter.py`

### 3. Token Bucket Rate Limiting
- **How It Works:** Each IP gets a bucket of tokens. Each request consumes 1 token. Tokens refill over time. No tokens = request rejected
- **Parameters:** `default_rate=100 req/min`, `default_burst=20`
- **Status:** ✅ Implemented

### 4. Dynamic IP Blocking
- **How It Works:** Malicious IPs are added to a blocked set. All future requests from blocked IPs are immediately rejected (HTTP 403)
- **Status:** ✅ Implemented

### 5. Traffic Risk Scoring
- **How It Works:** Calculates a suspiciousness score (0-100) for each IP based on:
  - Request rate (>10 req/s = +30 points, >5 req/s = +20 points)
  - Time since first seen
  - Total request count
- **Status:** ✅ Implemented

### 6. Risk Level Classification
- **How It Works:** Categorizes IPs based on suspicious score:
  - 0-20: SAFE
  - 20-40: LOW
  - 40-60: MEDIUM
  - 60-80: HIGH
  - 80-100: CRITICAL
- **Status:** ✅ Implemented

### 7. Action Recommendation
- **How It Works:** Suggests appropriate response based on risk level:
  - SAFE/LOW → ALLOW
  - MEDIUM → RATE_LIMIT_MODERATE
  - HIGH → RATE_LIMIT_AGGRESSIVE
  - CRITICAL → BLOCK_IMMEDIATELY
- **Status:** ✅ Implemented

---

## RECOVERY Methods

**File:** `recovery/health_monitor.py`

### 8. Service Health Monitoring
- **How It Works:** Continuously tracks service state using enum values:
  - HEALTHY → Normal operation
  - DEGRADED → Some issues, still running
  - CRITICAL → Under attack or failing
  - RECOVERING → Attack ended, restoring normal
- **Status:** ✅ Implemented

### 9. Failure Tracking
- **How It Works:** Counts consecutive failures per service. When failures exceed threshold (default: 3), service state changes to CRITICAL
- **Parameters:** `failure_threshold=3`
- **Status:** ✅ Implemented

### 10. Auto-Recovery
- **How It Works:** Automatically restores service to HEALTHY state after cooldown period (default: 300 seconds) once failures stop
- **Parameters:** `recovery_time=300s`
- **Status:** ✅ Implemented

### 11. Recovery Triggering
- **How It Works:** Allows manual or automatic triggering of recovery process. Sets service to RECOVERING state and starts recovery timer
- **Status:** ✅ Implemented

---

## NETWORK LAYER Protection

**File:** `deployment/nginx.conf`

### 12. Nginx Rate Limiting
- **How It Works:** First line of defense at the load balancer level
  - General endpoints: 10 requests/second
  - API endpoints: 20 requests/second
- **Status:** ✅ Implemented

### 13. Connection Limiting
- **How It Works:** Limits maximum concurrent connections per IP address to prevent connection exhaustion
- **Parameters:** `limit_conn addr 10`
- **Status:** ✅ Implemented

### 14. Load Balancing
- **How It Works:** Uses least-connection algorithm to distribute traffic across backend servers
- **Algorithm:** `least_conn`
- **Status:** ✅ Implemented

### 15. Security Headers
- **How It Works:** Adds security headers to all responses:
  - X-Frame-Options: SAMEORIGIN
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Referrer-Policy: strict-origin-when-cross-origin
- **Status:** ✅ Implemented

### 16. Burst Handling
- **How It Works:** Allows short bursts of traffic before rate limiting kicks in
  - General: burst=20
  - API: burst=50
- **Status:** ✅ Implemented

---

## Summary Table

| Category | Method | How It Works | Status |
|----------|--------|--------------|--------|
| Detection | IP Flooding Detection | Counts requests per IP in time window; blocks if exceeds threshold | ✅ |
| Detection | Distributed Attack Detection | Detects many unique IPs + high volume simultaneously | ✅ |
| Mitigation | Token Bucket Rate Limiting | Each IP gets tokens; requests consume tokens; no tokens = rejected | ✅ |
| Mitigation | Dynamic IP Blocking | Malicious IPs added to blocked set; future requests rejected (403) | ✅ |
| Mitigation | Traffic Risk Scoring | Calculates suspiciousness score (0-100) based on behavior | ✅ |
| Mitigation | Risk Level Classification | Categorizes IPs: SAFE, LOW, MEDIUM, HIGH, CRITICAL | ✅ |
| Mitigation | Action Recommendation | Suggests: ALLOW, RATE_LIMIT, or BLOCK based on risk | ✅ |
| Recovery | Service Health Monitoring | Tracks state: HEALTHY, DEGRADED, CRITICAL, RECOVERING | ✅ |
| Recovery | Failure Tracking | Counts consecutive failures; triggers CRITICAL after threshold | ✅ |
| Recovery | Auto-Recovery | Restores HEALTHY state after cooldown period (300s) | ✅ |
| Recovery | Recovery Triggering | Manual/automatic trigger to start recovery process | ✅ |
| Network | Nginx Rate Limiting | First layer defense: 10 req/s general, 20 req/s API | ✅ |
| Network | Connection Limiting | Max 10 concurrent connections per IP | ✅ |
| Network | Load Balancing | Least-connection algorithm distributes traffic | ✅ |
| Network | Security Headers | Adds X-Frame-Options, X-XSS-Protection, etc. | ✅ |
| Network | Burst Handling | Allows short bursts (20-50 requests) before limiting | ✅ |

---

## Future Scope (Not Implemented)

| Method | Description | Priority |
|--------|-------------|----------|
| CAPTCHA Challenge-Response | Verify humans vs bots during attacks | High |
| Global Rate Limiting | Server-wide request limiting (not per-IP) | High |
| Machine Learning Detection | Adaptive detection using ML models | Medium |
| User-Agent Blacklisting | Block known malicious user agents | Medium |
| Geo-blocking | Block traffic from specific countries | Low |
| Repeat Offender Tracking | Track and escalate punishment for repeat attackers | Medium |
| IP Reputation Database | Check IPs against known malicious IP lists | Medium |
| Honeypot Endpoints | Trap and identify attackers | Low |

---

## Architecture Flow

```
Incoming Request
       │
       ▼
┌─────────────────────┐
│ Nginx Load Balancer │ ← Rate Limiting, Connection Limits
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Flask Application   │
│ @before_request     │ ← Check if IP is blocked
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ DDoS Detector       │ ← IP Flooding + Distributed Attack Detection
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Rate Limiter        │ ← Token Bucket Algorithm
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Traffic Analyzer    │ ← Risk Scoring + Recommendations
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Health Monitor      │ ← Service State + Auto-Recovery
└──────────┬──────────┘
           │
           ▼
      Response
```

---

## Configuration Parameters

### Detection Engine
```python
DDoSDetector(
    time_window=60,           # Analysis window in seconds
    requests_threshold=50,    # Max requests per IP before blocking
    unique_ip_threshold=50    # Max unique IPs for distributed detection
)
```

### Rate Limiter
```python
RateLimiter(
    default_rate=100,         # Requests per minute
    default_burst=20          # Burst capacity
)
```

### Health Monitor
```python
HealthMonitor(
    check_interval=60,        # Health check interval in seconds
    failure_threshold=3,      # Failures before CRITICAL state
    recovery_time=300         # Recovery period in seconds
)
```

### Nginx
```nginx
limit_req_zone rate=10r/s     # General rate limit
limit_req_zone rate=20r/s     # API rate limit
limit_conn addr 10            # Max connections per IP
```

---

*Document created for project reference and presentation purposes.*
