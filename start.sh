#!/bin/bash
# Start DDoS Protection System

set -e

echo "Starting DDoS Protection System..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Build decision state
STATE_DIR=".state"
BUILD_STATE_FILE="$STATE_DIR/build-input.hash"
mkdir -p "$STATE_DIR"

file_hash() {
    local f="$1"
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$f" | awk '{print $1}'
    elif command -v shasum > /dev/null 2>&1; then
        shasum -a 256 "$f" | awk '{print $1}'
    elif command -v md5sum > /dev/null 2>&1; then
        md5sum "$f" | awk '{print $1}'
    elif command -v powershell.exe > /dev/null 2>&1; then
        powershell.exe -NoProfile -Command "(Get-FileHash -Algorithm SHA256 '$f').Hash" 2>/dev/null | tr -d '\r' | tr '[:upper:]' '[:lower:]'
    else
        # No hash tool available; force rebuild as safe fallback.
        echo "no-hash-tool"
    fi
}

DOCKERFILE_HASH="$(file_hash Dockerfile)"
REQ_HASH="$(file_hash requirements.txt)"
CURRENT_BUILD_INPUTS="dockerfile=$DOCKERFILE_HASH;requirements=$REQ_HASH"
PREV_BUILD_INPUTS=""
if [ -f "$BUILD_STATE_FILE" ]; then
    PREV_BUILD_INPUTS="$(cat "$BUILD_STATE_FILE")"
fi

NEED_BUILD="false"
if [ "${1:-}" = "--build" ]; then
    NEED_BUILD="true"
elif [ "$CURRENT_BUILD_INPUTS" != "$PREV_BUILD_INPUTS" ]; then
    NEED_BUILD="true"
fi

if [ "$NEED_BUILD" = "true" ]; then
    echo "Building and starting containers..."
    docker compose up -d --build
    echo "$CURRENT_BUILD_INPUTS" > "$BUILD_STATE_FILE"
else
    echo "Starting containers (no rebuild; Dockerfile/requirements unchanged)..."
    docker compose up -d
fi

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 6

# Check service health
echo "Checking service health..."
if command -v curl > /dev/null 2>&1; then
    curl -s http://localhost:80/health
    echo ""
else
    echo "curl not found, skipping health check"
fi

# Resolve current admin login password (dynamic file first, .env fallback)
ADMIN_USER="admin"
ADMIN_PASS=""

if docker compose exec -T web_app sh -lc 'test -s /app/web-app/.admin_password' > /dev/null 2>&1; then
    ADMIN_PASS=$(docker compose exec -T web_app sh -lc 'cat /app/web-app/.admin_password' 2>/dev/null | tr -d '\r')
fi

if [ -z "$ADMIN_PASS" ] && [ -f .env ]; then
    ADMIN_PASS=$(grep -E '^ADMIN_PASSWORD=' .env | tail -n1 | cut -d= -f2- | tr -d '\r')
fi

if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS="(not found - set ADMIN_PASSWORD in .env)"
fi

# Resolve LAN IP for phone access URL
LAN_IP=""

# Windows preferred: parse ipconfig "Wireless LAN adapter Wi-Fi" -> "IPv4 Address"
if [ -z "$LAN_IP" ] && command -v powershell.exe > /dev/null 2>&1; then
    LAN_IP=$(powershell.exe -NoProfile -Command "$txt = ipconfig | Out-String; $m = [regex]::Match($txt, 'Wireless LAN adapter Wi-?Fi:[\\s\\S]*?IPv4[^:]*:\\s*([0-9\\.]+)'); if($m.Success){$m.Groups[1].Value}" 2>/dev/null | tr -d '\r')
fi

# Windows fallback: adapter alias lookup for Wi-Fi
if [ -z "$LAN_IP" ] && command -v powershell.exe > /dev/null 2>&1; then
    LAN_IP=$(powershell.exe -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { ($_.InterfaceAlias -eq 'Wi-Fi' -or $_.InterfaceAlias -eq 'WiFi' -or $_.InterfaceAlias -like '*Wireless*') -and $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 -ExpandProperty IPAddress)" 2>/dev/null | tr -d '\r')
fi

# Linux/macOS preferred methods
if [ -z "$LAN_IP" ] && command -v hostname > /dev/null 2>&1; then
    LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [ -z "$LAN_IP" ] && command -v ip > /dev/null 2>&1; then
    LAN_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
fi
if [ -z "$LAN_IP" ] && command -v ifconfig > /dev/null 2>&1; then
    LAN_IP=$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}')
fi

# Windows generic fallback
if [ -z "$LAN_IP" ] && command -v powershell.exe > /dev/null 2>&1; then
    LAN_IP=$(powershell.exe -NoProfile -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1 -ExpandProperty IPAddress)" 2>/dev/null | tr -d '\r')
fi

if [ -z "$LAN_IP" ]; then
    LAN_IP="<YOUR_PC_LAN_IP>"
fi

echo ""
echo "DDoS Protection System is running!"
echo ""
echo "Endpoints:"
echo "  - Website:      http://localhost"
echo "  - Admin Login:  http://localhost/admin/login"
echo "  - Dashboard:    http://localhost/admin/dashboard"
echo "  - Health Check: http://localhost/health"
echo "  - Admin Stats:  http://localhost/admin/stats (session login or API key)"
echo ""
echo "Login Credentials:"
echo "  - Username:     $ADMIN_USER"
echo "  - Password:     $ADMIN_PASS"
echo ""
echo "LAN Access:"
echo "  - Detected LAN IP: $LAN_IP"
echo "  - Phone URL:       http://$LAN_IP/admin/login"
echo "To stop: ./stop.sh or docker compose down"
