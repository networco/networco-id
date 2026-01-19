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

# 1. Update password on host via SSH
echo -e "${YELLOW}Updating password on database host ($POSTGRES_HOST)...${NC}"
ssh root@$POSTGRES_HOST "sudo -u postgres psql -c \"DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '$POSTGRES_USER') THEN CREATE ROLE $POSTGRES_USER WITH LOGIN PASSWORD '$NEW_DATABASE_PASSWORD'; ELSE ALTER ROLE $POSTGRES_USER WITH PASSWORD '$NEW_DATABASE_PASSWORD'; END IF; END \$\$;\""

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
