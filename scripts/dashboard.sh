#!/bin/bash
# =============================================================================
# Networco Kubernetes Dashboard Access Script
# =============================================================================
#
# This script sets up a secure tunnel to the Kubernetes Dashboard and
# generates a login token.
#
# Usage:
#   ./dashboard.sh [server-ip]
#
# =============================================================================

set -e

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_IP="${1:-217.170.206.215}"
SSH_USER="root"
DASHBOARD_URL="http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

# 1. Generate Token
log_info "Generating admin token..."
TOKEN=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$SERVER_IP" "k3s kubectl create token admin-user -n kubernetes-dashboard --duration=24h")

if [ -z "$TOKEN" ]; then
	log_error "Failed to generate token. Is the dashboard installed?"
	exit 1
fi

# 2. Start Tunnel and Proxy
log_info "Starting SSH tunnel and kubectl proxy..."

# Kill existing local tunnel and remote proxy if any
pkill -f "ssh -L 8001" || true
ssh -o StrictHostKeyChecking=no "$SSH_USER@$SERVER_IP" "fuser -k 8001/tcp || pkill -f 'kubectl proxy' || pkill -f 'k3s kubectl proxy' || killall kubectl" 2>/dev/null || true

# Start tunnel and proxy
ssh -L 8001:localhost:8001 "$SSH_USER@$SERVER_IP" "k3s kubectl proxy" &
TUNNEL_PID=$!

# Wait a moment for the tunnel to establish
sleep 2

# Cleanup function
cleanup() {
	echo -e "\n"
	log_info "Cleaning up..."
	# Kill local tunnel process
	kill $TUNNEL_PID 2>/dev/null || true
	pkill -f "ssh -L 8001" || true
	# Kill remote proxy process specifically by port
	ssh -o StrictHostKeyChecking=no "$SSH_USER@$SERVER_IP" "fuser -k 8001/tcp || pkill -f 'kubectl proxy' || pkill -f 'k3s kubectl proxy' || killall kubectl" 2>/dev/null || true
	log_success "Dashboard access stopped and remote proxy cleaned up."
	exit 0
}

# Set trap for Ctrl+C and exit
trap cleanup SIGINT SIGTERM EXIT

# 3. Output Token
echo -e "\n${GREEN}=====================================================================${NC}"
echo -e "${GREEN}KUBERNETES DASHBOARD TOKEN (Valid for 24h):${NC}"
echo -e "---------------------------------------------------------------------"
echo -e "$TOKEN"
echo -e "---------------------------------------------------------------------"
echo -e "${GREEN}=====================================================================${NC}\n"

# 4. Open Browser
log_info "Opening dashboard in browser..."
if [ -n "$BROWSER" ]; then
	# Run in background so we don't block
	"$BROWSER" "$DASHBOARD_URL" &
else
	echo -e "Please open this URL in your browser:\n$DASHBOARD_URL"
fi

log_info "Dashboard is running. Press Ctrl+C to stop serving and exit."

# Keep script running
while true; do
	sleep 1
done
