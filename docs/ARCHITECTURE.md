# System Architecture

## Overview
Multi-layer DDoS protection system with real-time detection, automated mitigation, and self-healing capabilities.

## Architecture Diagram
```
+-----------------------------------------------+
|                Incoming Traffic                 |
+-----------------------------------------------+
                        |
              +--------------------+
              | Nginx Load Balancer|
              | (Layer 1: Rate     |
              |  Limit + Conn Limit|
              +--------------------+
                        |
              +--------------------+
              |  Flask Application |
              |  @before_request   |
              |  - IP Block Check  |
              |  - Rate Limiter    |
              +--------------------+
                        |
              +--------------------+
              |   DDoS Detector    |
              |  (2 Algorithms)    |
              |  - IP Flooding     |
              |  - Distributed     |
              |    Attack          |
              +--------------------+
                    |         |
         +----------------+  +------------------+
         | Rate Limiter   |  | Traffic Analyzer |
         | (Token Bucket) |  | (Risk Scoring)   |
         +----------------+  +------------------+
                    |         |
         +----------------+  +------------------+
         |                |  | Health Monitor   |
         |                |  | (Circuit Breaker)|
         +----------------+  +------------------+
                    |         |
              +--------------------+
              | Protected Response |
              | (Security Headers) |
              +--------------------+
```

## Component Details

### 1. Detection Engine (`detection/ddos_detector.py`)
- **IP Flooding Detection**: Tracks request rates per IP within a sliding time window
- **Distributed Attack Detection**: Monitors unique IP count and aggregate request rates

### 2. Mitigation Layer (`mitigation/rate_limiter.py`)
- **Token Bucket Algorithm**: Per-IP rate limiting with burst capacity
- **Traffic Analyzer**: Behavioral risk scoring (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
- **Stale Bucket Cleanup**: Automatic removal of inactive rate limit buckets

### 3. Recovery System (`recovery/health_monitor.py`)
- **Health Monitoring**: Service state tracking (HEALTHY/DEGRADED/CRITICAL/RECOVERING)
- **Circuit Breaker**: Automatic failover after threshold failures
- **Auto-Recovery**: Gradual service restoration with recovery time gate

### 4. Web Application (`web-app/app.py`)
- **Flask Framework**: Lightweight WSGI application
- **Middleware Integration**: `@before_request` for blocking/rate limiting, `@after_request` for detection and analysis
- **Monitoring Endpoints**: `/health` and `/admin/stats` for real-time statistics

## Data Flow
1. Request arrives at Nginx (Layer 1 rate limiting + connection limiting)
2. Traffic forwarded to Flask app via reverse proxy
3. `@before_request` checks IP block list and rate limiter
4. `@after_request` feeds traffic metrics to DDoS Detector (2 algorithms)
5. Traffic Analyzer computes behavioral risk score
6. High-risk IPs auto-blocked via feedback loop
7. Health Monitor tracks service state
8. Response returned with security headers

## Deployment
- **Containerized**: Docker Compose with Nginx + Flask
- **WSGI Server**: Gunicorn with 4 workers (production)
- **Load Balancing**: Nginx with least-connections strategy
- **Health Checks**: Docker health check on `/health` endpoint
