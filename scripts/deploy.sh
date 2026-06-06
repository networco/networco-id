#!/bin/bash
# =============================================================================
# NetworcoID - Deployment Script
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEPLOY_DIR="$REPO_ROOT/deploy/k3s"
NAMESPACE="networco-id"
KUBECONFIG_PATH="$REPO_ROOT/.kubeconfig"

# Handle SSH Tunnel / Kubeconfig
if [ -f "$KUBECONFIG_PATH" ]; then
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo -e "${BLUE}ℹ Using local kubeconfig: $KUBECONFIG_PATH${NC}"
fi

# Pre-flight check: Is the cluster reachable?
echo -e "${YELLOW}🔍 Checking cluster connectivity...${NC}"
TUNNEL_PID=""

check_connectivity() {
    kubectl cluster-info > /dev/null 2>&1
}

if ! check_connectivity; then
    echo -e "${YELLOW}🌐 Cluster not reachable. Attempting to start SSH tunnel...${NC}"
    
    # Start the tunnel in the background
    # We redirect output to avoid cluttering the deployment log
    "$SCRIPT_DIR/k3s.sh" tunnel > /dev/null 2>&1 &
    TUNNEL_PID=$!
    
    # Give it a few seconds to establish
    echo -e "${YELLOW}⏳ Waiting for tunnel to establish...${NC}"
    MAX_RETRIES=5
    COUNT=0
    while ! check_connectivity && [ $COUNT -lt $MAX_RETRIES ]; do
        sleep 2
        ((COUNT++))
        echo "  Attempt $COUNT/$MAX_RETRIES..."
    done

    if ! check_connectivity; then
        echo -e "${RED}❌ Error: Failed to establish SSH tunnel.${NC}"
        [ -n "$TUNNEL_PID" ] && kill $TUNNEL_PID
        exit 1
    fi
    echo -e "${GREEN}✓ Tunnel established (PID: $TUNNEL_PID).${NC}"
    
    # Ensure the tunnel is closed when the script exits
    trap 'echo -e "\n${YELLOW}🔌 Closing SSH tunnel...${NC}"; kill $TUNNEL_PID' EXIT
else
    echo -e "${GREEN}✓ Cluster is already reachable.${NC}"
fi

# Parse arguments
SKIP_BUILD=false
BUILD_ARGS=()

for arg in "$@"; do
    case $arg in
        --skip-build)
            SKIP_BUILD=true
            ;;
        *)
            # Collect other arguments to pass to build.sh (e.g., --no-push, version)
            BUILD_ARGS+=("$arg")
            ;;
    esac
done

echo -e "${BLUE}=== NetworcoID Deployment ===${NC}"

# 1. Sync Secrets from .env.prod
echo -e "${YELLOW}Step 1: Synchronizing secrets...${NC}"
if ! "$SCRIPT_DIR/sync-secrets.sh"; then
    echo -e "${RED}❌ Warning: Secret synchronization failed. Deployment may fail if secrets are missing.${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 2. Build and push images using existing script
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}Step 2: Building and pushing images...${NC}"
    "$SCRIPT_DIR/build.sh" "${BUILD_ARGS[@]}"
else
    echo -e "${YELLOW}Step 2: Skipping build as requested.${NC}"
fi

# 3. Apply Kubernetes manifests
echo -e "${YELLOW}Step 3: Applying Kubernetes manifests...${NC}"
kubectl apply -f "$DEPLOY_DIR/00-namespace.yaml"
kubectl apply -f "$DEPLOY_DIR/01-nats.yaml"
# Postgres now runs on the shared CloudNativePG HA cluster (networco-db/pg);
# the old in-namespace StatefulSet was decommissioned 2026-06-06. db-host points
# at pg-rw.networco-db.svc.cluster.local via networcoid-secrets (POSTGRES_HOST).
# Skip 03-secrets.yaml as it's handled by sync-secrets.sh in Step 1
kubectl apply -f "$DEPLOY_DIR/04-api.yaml"
kubectl apply -f "$DEPLOY_DIR/05-worker.yaml"
kubectl apply -f "$DEPLOY_DIR/06-ingress.yaml"

# 3. Force rollout to ensure new images are pulled
echo -e "${YELLOW}Step 3: Restarting deployments to pull latest images...${NC}"
kubectl rollout restart deployment networcoid -n "$NAMESPACE"
kubectl rollout restart deployment networcoid-worker -n "$NAMESPACE"

# 4. Wait for rollout to complete
echo -e "${YELLOW}Step 4: Waiting for rollout status...${NC}"
kubectl rollout status deployment networcoid -n "$NAMESPACE"
kubectl rollout status deployment networcoid-worker -n "$NAMESPACE"

echo -e "${GREEN}✓ Deployment successful!${NC}"
echo -e "🌐 URL: ${BLUE}https://id.networco.countdown.no${NC}"
