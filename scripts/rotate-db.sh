#!/bin/bash
# =============================================================================
# NetworcoID - Database Password Rotation
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
ENV_FILE="$REPO_ROOT/.env.prod"
NAMESPACE="networco-id"
KUBECONFIG_PATH="$REPO_ROOT/.kubeconfig"

# Handle Kubeconfig
if [ -f "$KUBECONFIG_PATH" ]; then
    export KUBECONFIG="$KUBECONFIG_PATH"
fi

# Pre-flight check: Is the cluster reachable?
check_connectivity() {
    kubectl cluster-info > /dev/null 2>&1
}

TUNNEL_PID=""
if ! check_connectivity; then
    echo -e "${YELLOW}🌐 Cluster not reachable. Attempting to start SSH tunnel...${NC}"
    "$SCRIPT_DIR/k3s.sh" tunnel > /dev/null 2>&1 &
    TUNNEL_PID=$!
    
    MAX_RETRIES=5
    COUNT=0
    while ! check_connectivity && [ $COUNT -lt $MAX_RETRIES ]; do
        sleep 2
        ((COUNT++))
    done

    if ! check_connectivity; then
        echo -e "${RED}❌ Error: Failed to establish SSH tunnel.${NC}"
        [ -n "$TUNNEL_PID" ] && kill $TUNNEL_PID
        exit 1
    fi
    trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT
fi

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ Error: $ENV_FILE not found.${NC}"
    exit 1
fi

# Load current config
set -a
source "$ENV_FILE"
set +a

# Generate new password if not provided
if [ -z "$NEW_DATABASE_PASSWORD" ]; then
    echo -e "${YELLOW}Generating new secure password...${NC}"
    NEW_DATABASE_PASSWORD=$(openssl rand -hex 24)
fi

echo -e "${BLUE}=== Rotating Database Password for $POSTGRES_USER ===${NC}"

# 1. Update password in Kubernetes Postgres pod
echo -e "${YELLOW}Updating password in Kubernetes Postgres pod...${NC}"
# We use the pod's own environment variables to authenticate the psql command
kubectl exec statefulset/postgres -n "$NAMESPACE" -- sh -c "export PGPASSWORD=\$POSTGRES_PASSWORD; psql -U \$POSTGRES_USER -d \$POSTGRES_DB -c \"ALTER ROLE \$POSTGRES_USER WITH PASSWORD '$NEW_DATABASE_PASSWORD';\""

# 2. Update .env.prod
echo -e "${YELLOW}Updating local .env.prod...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$NEW_DATABASE_PASSWORD/" "$ENV_FILE"
else
    sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$NEW_DATABASE_PASSWORD/" "$ENV_FILE"
fi

# 3. Synchronize secrets to Kubernetes
"$SCRIPT_DIR/sync-secrets.sh"

# 4. Rollout restart deployments
echo -e "${YELLOW}Restarting deployments in $NAMESPACE...${NC}"
kubectl rollout restart deployment networcoid -n "$NAMESPACE"
kubectl rollout restart deployment networcoid-worker -n "$NAMESPACE"

# 5. Wait for rollout
kubectl rollout status deployment networcoid -n "$NAMESPACE"
kubectl rollout status deployment networcoid-worker -n "$NAMESPACE"

echo -e "${GREEN}✓ Database password rotated and services updated successfully!${NC}"
