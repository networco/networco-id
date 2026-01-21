#!/bin/bash
# =============================================================================
# NetworcoID - Secret Synchronization
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
    
    # Start the tunnel in the background
    "$SCRIPT_DIR/k3s.sh" tunnel > /dev/null 2>&1 &
    TUNNEL_PID=$!
    
    # Give it a few seconds to establish
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
    
    # Ensure the tunnel is closed when the script exits
    trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT
fi

# --- Pull Mode ---
if [ "$1" == "--pull" ]; then
    echo -e "${BLUE}=== Pulling Secrets from Kubernetes to $ENV_FILE ===${NC}"
    
    # Map K8s keys back to ENV keys
    MAPPING=(
        "db-host:POSTGRES_HOST"
        "db-name:POSTGRES_DB"
        "db-user:POSTGRES_USER"
        "db-password:POSTGRES_PASSWORD"
        "jwt-secret:JWT_SECRET"
        "admin-access-key:ADMIN_ACCESS_KEY"
        "brevo-api-key:BREVO_API_KEY"
        "issuer:ISSUER"
        "base-url:BASE_URL"
        "NATS_URL:NATS_URL"
    )

    # Check if secret exists
    if ! kubectl get secret networcoid-secrets -n "$NAMESPACE" &> /dev/null; then
        echo -e "${RED}❌ Error: Secret 'networcoid-secrets' not found in namespace '$NAMESPACE'.${NC}"
        exit 1
    fi

    # Get secret as JSON
    SECRET_JSON=$(kubectl get secret networcoid-secrets -n "$NAMESPACE" -o json)

    # Reconstruct .env.prod
    echo "# NetworcoID Production Secrets (Pulled on $(date))" > "$ENV_FILE"
    
    for item in "${MAPPING[@]}"; do
        K8S_KEY=${item%%:*}
        ENV_KEY=${item#*:}
        
        # Extract and decode value
        VALUE=$(echo "$SECRET_JSON" | jq -r ".data[\"$K8S_KEY\"]" | base64 -d)
        
        if [ "$VALUE" != "null" ]; then
            echo "$ENV_KEY=$VALUE" >> "$ENV_FILE"
        fi
    done

    echo -e "${GREEN}✓ Secrets pulled and saved to $ENV_FILE${NC}"
    exit 0
fi

# --- Push Mode (Default) ---

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${YELLOW}⚠️  $ENV_FILE not found. Attempting to pull secrets from cluster...${NC}"
    if kubectl get secret networcoid-secrets -n "$NAMESPACE" &> /dev/null; then
        "$0" --pull
    else
        echo -e "${RED}❌ Error: $ENV_FILE not found and secret 'networcoid-secrets' does not exist in cluster.${NC}"
        echo -e "${YELLOW}Please create $ENV_FILE manually or ensure cluster access is correct.${NC}"
        exit 1
    fi
fi

echo -e "${BLUE}=== Synchronizing Secrets to Kubernetes ($NAMESPACE) ===${NC}"

# Load environment variables
set -a
source "$ENV_FILE"
set +a

# Update networcoid-secrets in networco-id namespace
echo -e "${YELLOW}Updating networcoid-secrets...${NC}"

# Internal defaults if not set in .env.prod
POSTGRES_HOST=${POSTGRES_HOST:-"postgres"}
NATS_URL=${NATS_URL:-"nats://nats.networco-id.svc.cluster.local:4222"}

kubectl create secret generic networcoid-secrets \
    --namespace "$NAMESPACE" \
    --from-literal=db-host="$POSTGRES_HOST" \
    --from-literal=db-name="$POSTGRES_DB" \
    --from-literal=db-user="$POSTGRES_USER" \
    --from-literal=db-password="$POSTGRES_PASSWORD" \
    --from-literal=jwt-secret="$JWT_SECRET" \
    --from-literal=admin-access-key="$ADMIN_ACCESS_KEY" \
    --from-literal=brevo-api-key="$BREVO_API_KEY" \
    --from-literal=issuer="$ISSUER" \
    --from-literal=base-url="$BASE_URL" \
    --from-literal=NATS_URL="$NATS_URL" \
    --dry-run=client -o yaml | kubectl apply -f -

echo -e "${GREEN}✓ Secrets synchronized successfully.${NC}"
