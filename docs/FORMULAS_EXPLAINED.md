# Mathematical Formulas Used in the DDoS Protection System

This document explains every formula used in the system, what each symbol means, and how it maps to the actual code.

---

## Equation 1 - IP Flooding Detection

```
Block(ip) = True,   if R_ip(W) > T_req
             False,  otherwise
```

### Symbols

| Symbol | Meaning | Default Value |
|--------|---------|---------------|
| `ip` | The client's IP address | `request.remote_addr` |
| `R_ip(W)` | Number of requests from that IP within the time window | Count of timestamps in the deque |
| `W` | Time window (seconds) | 60 |
| `T_req` | Request threshold | 50 |

### Plain English

Count how many requests a single IP sent in the last 60 seconds. If it exceeds 50, block that IP.

### Code Mapping (`detection/ddos_detector.py`)

```python
# R_ip(W) - filter timestamps within window
recent = [t for t in self.ip_request_count[ip] if t > current_time - self.time_window]

# Block(ip) - if count exceeds threshold
if len(recent) > self.requests_threshold:
    self.blocked_ips.add(ip)  # Block = True
```

### Walkthrough

- IP `192.168.1.5` sends 60 requests in the last 60 seconds
- `R_ip(W)` = 60, `T_req` = 50
- 60 > 50 = **True** -> IP is blocked

---

## Equation 2 - Distributed Attack Detection

```
DDoS = (U > T_ip) AND (N / W > 50)
```

### Symbols

| Symbol | Meaning | Default Value |
|--------|---------|---------------|
| `U` | Number of unique IP addresses in the traffic buffer | `len(set(unique_ips))` |
| `T_ip` | Unique IP threshold | 50 |
| `N` | Total number of requests in the window | `len(recent_traffic)` |
| `W` | Time window (seconds) | 60 |
| `N/W` | Request rate (requests per second) | Calculated |
| `AND` | Both conditions must be true simultaneously | - |

### Plain English

If more than 50 different IPs are sending requests **AND** the combined rate exceeds 50 requests/second, it is a coordinated DDoS attack.

### Why Two Conditions?

Either condition alone could be innocent:

- Many unique IPs = could just be a popular page
- High request rate = could be one heavy user

But **both together** = many sources flooding simultaneously = DDoS.

### Code Mapping (`detection/ddos_detector.py`)

```python
recent_traffic = [t for t in self.traffic_buffer if t.timestamp > current_time - self.time_window]
unique_ips = set(t.ip_address for t in recent_traffic)

# U > T_ip                         AND         N / W > 50
if len(unique_ips) > self.unique_ip_threshold and len(recent_traffic) / self.time_window > 50:
    # DDoS = True
```

### Walkthrough

- 70 unique IPs are sending traffic, total 4,000 requests in 60 seconds
- `U` = 70, `T_ip` = 50 -> 70 > 50 = True
- `N/W` = 4000/60 = 66.7 req/s -> 66.7 > 50 = True
- Both True -> **DDoS detected** (severity: CRITICAL, confidence: 0.92)

---

## Equation 3 - Token Bucket Refill

```
T_new = min(B, T_current + delta_t * (r / 60))
```

### Symbols

| Symbol | Meaning | Default Value |
|--------|---------|---------------|
| `T_new` | Updated token count after refill | `bucket['tokens']` after update |
| `T_current` | Tokens currently in the bucket | `bucket['tokens']` before update |
| `B` | Burst capacity (max tokens the bucket can hold) | 20 |
| `delta_t` | Seconds elapsed since last request from this IP | `current_time - bucket['last_update']` |
| `r` | Rate limit in requests per minute | 100 |
| `r/60` | Converted to requests per second (token refill speed) | 1.667 tokens/sec |

### Plain English

Add tokens based on how much time has passed (the longer since the last request, the more tokens are restored), but never exceed the bucket's maximum capacity of 20.

### How It Works Step by Step

1. Every IP address gets a "bucket" that starts with 20 tokens
2. Each request costs 1 token
3. Tokens refill over time at `r/60` tokens per second
4. The bucket can never hold more than `B` tokens
5. If tokens >= 1 -> request allowed, consume a token
6. If tokens < 1 -> request rejected

### Code Mapping (`mitigation/rate_limiter.py`)

```python
time_passed = current_time - bucket['last_update']                    # delta_t
tokens_to_add = time_passed * (rate / 60.0)                           # delta_t * (r/60)
bucket['tokens'] = min(burst, bucket['tokens'] + tokens_to_add)       # min(B, T_current + ...)
```

### Walkthrough

- Bucket has 5 tokens, 3 seconds have passed, rate = 100/min
- Tokens to add = 3 * (100/60) = 5.0
- T_new = min(20, 5 + 5) = **10 tokens**
- Request arrives -> 10 >= 1 -> **Allowed**, bucket now has **9 tokens**

Another example (bucket nearly empty):

- Bucket has 0.2 tokens, 0.3 seconds have passed, rate = 100/min
- Tokens to add = 0.3 * 1.667 = 0.5
- T_new = min(20, 0.2 + 0.5) = **0.7 tokens**
- Request arrives -> 0.7 < 1 -> **Rejected**

---

## Equation 4 - Retry Delay Calculation

```
t_retry = (1 - T_new) / (r / 60)
```

### Symbols

| Symbol | Meaning |
|--------|---------|
| `t_retry` | Seconds the client must wait before retrying |
| `1 - T_new` | How many more tokens are needed to reach 1.0 (cost of one request) |
| `r / 60` | Token refill rate per second |

### Plain English

When a request is rejected (not enough tokens), calculate exactly how many seconds until the bucket has enough tokens to serve one request.

### Code Mapping (`mitigation/rate_limiter.py`)

```python
'retry_after': int((1.0 - bucket['tokens']) / (rate / 60.0))
```

### Walkthrough

- Bucket has 0.3 tokens (T_new = 0.3), rate = 100/min
- Tokens needed = 1 - 0.3 = 0.7
- Refill speed = 100/60 = 1.667 tokens/sec
- Wait time = 0.7 / 1.667 = **0.42 seconds**

Another example:

- Bucket has 0 tokens, rate = 100/min
- Tokens needed = 1 - 0 = 1.0
- Wait time = 1.0 / 1.667 = **0.6 seconds**

---

## Equation 5 - Suspicious Score Calculation

```
S = min(100, SUM(w_i * f_i(rate)))
```

### Symbols

| Symbol | Meaning |
|--------|---------|
| `S` | Final suspicious score (0 to 100) |
| `w_i` | Weight for each scoring factor (all weights = 1 in current implementation) |
| `f_i(rate)` | Scoring function applied to the request rate |
| `min(100, ...)` | Cap the score at 100 maximum |
| `SUM` | Sum of all contributing scoring factors |

### Scoring Functions in the Current Implementation

| Condition | Points Added |
|-----------|-------------|
| rate > 10 req/s | +30 |
| rate > 5 req/s (but <= 10) | +20 |
| rate <= 5 req/s | +0 |

**Note:** The code uses `elif`, so only one condition fires - they do not stack.

### Risk Level Mapping

| Score Range | Risk Level | Action Recommendation |
|-------------|------------|----------------------|
| 0 - 19 | SAFE | ALLOW |
| 20 - 39 | LOW | ALLOW |
| 40 - 59 | MEDIUM | RATE_LIMIT_MODERATE |
| 60 - 79 | HIGH | RATE_LIMIT_AGGRESSIVE |
| 80 - 100 | CRITICAL | BLOCK_IMMEDIATELY |

### Code Mapping (`mitigation/rate_limiter.py`)

```python
def _calculate_suspicious_score(self, profile):
    score = 0.0
    age = time.time() - profile['first_seen']
    if age > 0:
        req_per_second = profile['request_count'] / age
        if req_per_second > 10: score += 30      # f_1: high rate
        elif req_per_second > 5: score += 20     # f_2: moderate rate
    return min(100.0, score)                      # min(100, S)
```

### Walkthrough Examples

| Scenario | Requests | Time Active | Rate | Score | Risk Level | Action |
|----------|----------|-------------|------|-------|------------|--------|
| Normal browsing | 10 | 5 sec | 2 req/s | 0 | SAFE | ALLOW |
| Moderate activity | 40 | 5 sec | 8 req/s | 20 | LOW | ALLOW |
| Suspicious user | 60 | 5 sec | 12 req/s | 30 | LOW | ALLOW |
| Attacker | 100 | 2 sec | 50 req/s | 30 | LOW | ALLOW |

---

## Summary

| Eq. | Purpose | File | Core Idea |
|-----|---------|------|-----------|
| 1 | IP Flood Detection | `detection/ddos_detector.py` | Block IP if requests > threshold in time window |
| 2 | Distributed Attack Detection | `detection/ddos_detector.py` | Flag if many unique IPs + high rate simultaneously |
| 3 | Token Bucket Refill | `mitigation/rate_limiter.py` | Refill tokens over time, cap at burst capacity |
| 4 | Retry Delay | `mitigation/rate_limiter.py` | Tell rejected clients how long to wait |
| 5 | Risk Scoring | `mitigation/rate_limiter.py` | Score IPs by behavior, classify risk, recommend action |

---

## How They Work Together

```
Request arrives
    |
    v
[Eq. 1] Is this IP flooding? (> 50 req in 60s?)
    |--- Yes --> BLOCKED (HTTP 403)
    |--- No
    v
[Eq. 2] Is this a distributed attack? (> 50 unique IPs AND > 50 req/s?)
    |--- Yes --> All source IPs flagged, severity CRITICAL
    |--- No
    v
[Eq. 3] Does this IP have tokens? (Token bucket check)
    |--- Yes --> Allow, consume 1 token
    |--- No --> [Eq. 4] Calculate retry delay, reject with retry_after
    v
[Eq. 5] Calculate suspicious score for this IP
    |--- Score maps to risk level and action recommendation
    v
Response sent
```
