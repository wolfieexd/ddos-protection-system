# Implementation Guide

## Quick Start

### Prerequisites
- Python 3.9+
- Docker & Docker Compose
- Git

### Installation
```bash
# Clone repository
git clone https://github.com/wolfieexd/ddos-protection-system.git
cd ddos-protection-system

# Install dependencies
pip install -r requirements.txt

# Run with Docker
docker-compose up -d

# Access application (via Nginx)
curl http://localhost:80
```

## Configuration

### Detection Rules
Edit `detection/ddos_detector.py`:
```python
detector = DDoSDetector(
    time_window=60,        # Analysis window (seconds)
    requests_threshold=50  # Requests before blocking
)
```

### Rate Limiting
Edit `mitigation/rate_limiter.py`:
```python
limiter = RateLimiter(
    default_rate=100,  # Requests per minute
    default_burst=20   # Burst capacity
)
```

## Testing

### Unit Tests
```bash
python -m pytest tests/ -v
```

### Attack Simulation
```bash
# HTTP Flood
python simulation/attack_simulator.py \
    --target http://localhost:80 \
    --duration 30 \
    --rps 100

# Watch detection
curl http://localhost:80/admin/stats
```

## Deployment

### Docker (Production)
```bash
docker-compose up -d
```

This starts:
- **Nginx** on port 80 (rate limiting, connection limiting, security headers)
- **Flask + Gunicorn** on internal port 8000 (not exposed to host)

### Manual (Development)
```bash
pip install -r requirements.txt
python web-app/app.py
```

## Troubleshooting

### High False Positives
- Increase `requests_threshold`
- Adjust `time_window`

### Performance Issues
- Scale web app workers in Dockerfile (`-w 4`)
- Tune Nginx rate limits in `deployment/nginx.conf`

### Memory Usage
```bash
# Check container stats
docker stats
```

## Best Practices
1. Start with conservative thresholds
2. Monitor false positive rate via `/admin/stats`
3. Test recovery mechanisms before production
4. Keep dependencies updated
5. Always route traffic through Nginx, not directly to Flask
