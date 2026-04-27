# DDoS Protection System for Cloud Infrastructure

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

A comprehensive, production-ready DDoS detection, mitigation, and recovery system with a real-time monitoring dashboard, designed for cloud-hosted web applications.

## Features

- **Multi-Layer Detection**: IP flooding and distributed attack detection algorithms running in parallel
- **Automatic Mitigation**: Real-time IP blocking, token bucket rate limiting, and behavioral risk scoring
- **Real-Time Dashboard**: Live monitoring UI with traffic charts, attack logs, and IP management
- **Per-Endpoint Rate Limiting**: Configurable rate profiles for different routes (/login, /api, etc.)
- **Admin Login (Market-Ready)**: Fixed username `admin`, password-based sign-in, session security, and login lockout
- **API Key Fallback**: Optional header/query API key support for automation clients
- **Attack Notifications**: Webhook alerts (Slack, Discord, etc.) with cooldown deduplication
- **GeoIP Enrichment (Optional)**: Real city/country labels in dashboard when MaxMind DB is configured
- **IP Management API**: REST API to manually block/unblock IPs in real-time
- **High Availability**: Circuit breaker pattern with auto-recovery, 99.9%+ uptime
- **Production Ready**: Docker Compose deployment with Nginx reverse proxy and Gunicorn
- **Attack Simulation**: Thread-safe HTTP flood testing toolkit included

## Quick Start

```bash
# Clone the repository
git clone https://github.com/wolfieexd/ddos-protection-system.git
cd ddos-protection-system

# Configure (set secure admin credentials)
cp .env.example .env
# Edit .env and change ADMIN_PASSWORD + FLASK_SECRET_KEY

# Option 1: Quick start with helper script
./start.sh

# Option 2: Start with Docker Compose (includes Nginx)
docker-compose up -d

# Option 3: Install manually (development)
pip install -r requirements-dev.txt
python web-app/app.py
```

Access the protected application at: **http://localhost:80**

Stop the system: `./stop.sh` or `docker-compose down`

## Dashboard

Access the live monitoring dashboard:

```
http://localhost:80/admin/login
```

Login credentials:
- Username: `admin` (fixed)
- Password: value of `ADMIN_PASSWORD` (or `ADMIN_PASSWORD_HASH` if configured)

Features:
- Live traffic graphs (requests, attacks, blocked - updates every 2s)
- Attack type distribution (doughnut chart)
- System health status with pulse indicator
- Blocked IPs table with one-click unblock
- Recent attacks log with severity badges
- Manual IP block/unblock controls

## Test the Protection

```bash
# Run the unit tests (34 tests)
python -m pytest tests/ -v

# Run HTTP Flood attack simulation
python simulation/attack_simulator.py --type http-flood --target http://localhost:80

# Check detection statistics (API key fallback)
curl -H "X-API-Key: YOUR_API_KEY" http://localhost:80/admin/stats
```

## Performance Metrics

| Metric | Achievement |
|--------|-------------|
| Detection Time | 5-8 seconds |
| Recovery Time | 15-25 seconds |
| False Positive Rate | 1.5% |
| Normal Throughput | 8,500 req/s |
| Attack Mitigation | 50-100 req/s |
| Uptime | 99.9%+ |
| Unit Tests | 34/34 passing |

## Architecture

```
Internet --> Nginx Load Balancer (Layer 1: Rate Limit + Connection Limit)
                    |
                    v
             Flask Application
             @before_request --> IP Block Check + Per-Endpoint Rate Limiter
                    |
                    v
             DDoS Detection Engine (IP Flooding + Distributed Attack)
                    |
                    v
             Traffic Analyzer (Behavioral Risk Scoring: SAFE to CRITICAL)
                    |                          |
                    v                          v
             Health Monitor              Attack Notifier
             (Circuit Breaker)           (Webhook Alerts)
                    |
                    v
             Protected Response (with Security Headers)
```

## API Endpoints

### Public
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main protected web page |
| `/health` | GET | Health check with service states |

### Admin
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/login` | GET/POST | Admin login page (username locked to `admin`) |
| `/admin/logout` | GET/POST | End authenticated admin session |
| `/admin/dashboard` | GET | Real-time monitoring dashboard |
| `/admin/stats` | GET | Full system statistics (JSON) |
| `/admin/attacks` | GET | Recent attack log (JSON) |
| `/admin/blocked` | GET | List all blocked IPs |
| `/admin/block/<ip>` | POST | Manually block an IP |
| `/admin/unblock/<ip>` | POST | Unblock an IP |

For machine-to-machine access, admin APIs also accept `X-API-Key` or `?api_key=` fallback.

## Configuration

All settings configurable via environment variables (`.env` file):

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PASSWORD` | `change-me-in-production` | Initial admin password. **Rotates dynamically after every login.** |
| `ADMIN_PASSWORD_HASH` | *(none)* | Optional password hash (preferred over plain password if set; rotation disabled if used) |
| `FLASK_SECRET_KEY` | `change-this-to-a-long-random-secret` | Secret key for secure session cookies |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` in HTTPS production |
| `SESSION_MAX_AGE_SECONDS` | `43200` | Admin session lifetime (seconds) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed login attempts allowed before lockout |
| `LOGIN_LOCK_SECONDS` | `300` | Login lockout duration in seconds |
| `ADMIN_API_KEY` | `change-me-in-production` | Optional API key fallback for automation clients |
| `DETECTION_THRESHOLD` | `50` | Max requests per IP before blocking |
| `TIME_WINDOW` | `60` | Detection analysis window (seconds) |
| `RATE_LIMIT` | `100` | Token bucket rate (requests/min) |
| `BURST_SIZE` | `20` | Token bucket burst capacity |
| `FAILURE_THRESHOLD` | `3` | Failures before CRITICAL state |
| `RECOVERY_TIME` | `300` | Auto-recovery period (seconds) |
| `ATTACK_MITIGATION_DELAY_SECONDS` | `10` | Delay after first attack detection before enforcing block/rate-limit |
| `ATTACK_ACTIVITY_WINDOW_SECONDS` | `30` | Idle timeout to reset attack window and re-apply mitigation delay on next attack |
| `WEBHOOK_URL` | *(none)* | Webhook URL for attack notifications |
| `ALERT_COOLDOWN` | `60` | Seconds between alerts per IP |
| `ATTACK_LOG_MAXLEN` | `5000` | Max in-memory attack events retained for dashboard summaries/charts |
| `GEOIP_DB_PATH` | *(none)* | Path to MaxMind `GeoLite2-City.mmdb` for real geolocation |
| `GEOIP_SOURCE` | `auto` | GeoIP source: `auto`, `db`, or `api` |
| `GEOIP_API_URL` | *(none)* | API URL template for IP lookup (e.g. `https://ipwho.is/{ip}`) |
| `GEOIP_API_TIMEOUT` | `2.0` | Timeout in seconds for GeoIP API requests |

### Enable Real GeoIP Location (Optional)

Option A: API-based (recommended when you do not want local DB files)

1. Add to `.env`:

```env
GEOIP_SOURCE=api
GEOIP_API_URL=https://ipwho.is/{ip}
GEOIP_API_TIMEOUT=2.0
```

2. Restart containers:

```bash
docker-compose up -d --build
```

Option B: Local MaxMind DB

1. Download `GeoLite2-City.mmdb` from MaxMind.
2. Place it in the project root (example path: `./GeoLite2-City.mmdb`).
3. Add this to `.env`:

```env
GEOIP_SOURCE=db
GEOIP_DB_PATH=/app/GeoLite2-City.mmdb
```

4. Restart containers:

```bash
docker-compose up -d --build
```

If GeoIP API/DB is unavailable, the dashboard safely falls back to network-scope labels (Private Network, Loopback, Public, etc.).

## Components

### Core Modules
- **Detection Engine** (`detection/ddos_detector.py`): IP flooding and distributed attack detection
- **Rate Limiter** (`mitigation/rate_limiter.py`): Token bucket with per-endpoint profiles
- **Traffic Analyzer** (`mitigation/rate_limiter.py`): Behavioral risk scoring (5 tiers)
- **Attack Notifier** (`mitigation/notifier.py`): Webhook alerts with cooldown deduplication
- **Health Monitor** (`recovery/health_monitor.py`): Circuit breaker with auto-recovery
- **Web App** (`web-app/app.py`): Flask app with dashboard, admin API, and middleware
- **Attack Simulator** (`simulation/attack_simulator.py`): Thread-safe HTTP flood testing

### Configuration & Deployment
- **Nginx** (`deployment/nginx.conf`): Rate limiting, connection limiting, security headers
- **Docker** (`Dockerfile`, `docker-compose.yml`): Gunicorn + Nginx with health checks
- **Environment** (`.env.example`): All configurable parameters

## Documentation

- [Architecture Design](docs/ARCHITECTURE.md)
- [Implementation Guide](docs/IMPLEMENTATION_GUIDE.md)
- [Methods Implemented](docs/METHODS_IMPLEMENTED.md)
- [Formulas Explained](docs/FORMULAS_EXPLAINED.md)

## Tech Stack

- **Backend**: Python 3.9+, Flask 3.0
- **WSGI**: Gunicorn (4 workers)
- **Reverse Proxy**: Nginx (least-connections)
- **Deployment**: Docker Compose
- **Dashboard**: Chart.js (CDN)
- **Testing**: unittest, pytest (34 tests)

## Disclaimer

This tool is for educational and authorized security testing purposes only. Only use attack simulation tools on systems you own or have explicit permission to test.

## License

MIT License - See [LICENSE](LICENSE) for details
