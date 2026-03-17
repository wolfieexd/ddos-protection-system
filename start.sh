#!/bin/bash
# Start DDoS Protection System

echo "Starting DDoS Protection System..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker first."
    exit 1
fi

# Build and start containers
echo "Building containers..."
docker-compose build

echo "Starting services..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 5

# Check service health
echo "Checking service health..."
if command -v curl > /dev/null 2>&1; then
    curl -s http://localhost:80/health
    echo ""
else
    echo "curl not found, skipping health check"
fi

echo ""
echo "DDoS Protection System is running!"
echo ""
echo "Endpoints:"
echo "  - Web App:      http://localhost:80"
echo "  - Dashboard:    http://localhost:80/admin/dashboard?api_key=YOUR_KEY"
echo "  - Health Check: http://localhost:80/health"
echo "  - Admin Stats:  http://localhost:80/admin/stats (requires API key)"
echo ""
echo "Set ADMIN_API_KEY in .env to secure admin endpoints."
echo "To stop: ./stop.sh or docker-compose down"
