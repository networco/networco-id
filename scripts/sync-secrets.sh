#!/usr/bin/env bash
# =============================================================================
# NetworcoID — secret synchronisation between an env file and a cluster
# =============================================================================
#
# The environment is now an ARGUMENT and has no default. It used to be
# hardcoded to prod: the file was .env.prod and the cluster was whatever
# .kubeconfig happened to point at, so running the script while thinking
# about test would have rewritten production's secrets without a prompt.
#
#   sync-secrets.sh --env test --diff     # what differs, by KEY NAME only
#   sync-secrets.sh --env test --pull     # cluster -> .env.test (PARTIAL, see below)
#   sync-secrets.sh --env prod --push     # .env.prod -> cluster (default action)
#
# IMPORTANT — a pull is NOT a backup of the env file. Only the keys in
# MAPPING below live in the cluster; CI-only credentials (GHCR_*, TS_*)
# and values applied straight to the deployment (EMAIL_SENDER_*) never
# reach it and cannot come back. Pushing a pulled file into the
# ENV_ID_TEST / ENV_ID_PROD GitHub secret would drop them, and the next
# deploy would fail to pull images or reach the tailnet. --pull says so
# on the way out; --diff exists so the usual question ("is my local file
# still current?") can be answered without a round trip that loses keys.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Both clusters use this namespace -- they are separate clusters, not
# separate namespaces, so the environment selects the KUBECONFIG.
NAMESPACE="networco-id"
SECRET_NAME="networcoid-secrets"

# The single source of truth for what lives in the cluster secret, used by
# all three modes so pull and push cannot drift apart (they had: pull knew
# 14 keys, the deploy workflow wrote 23).
MAPPING=(
    "db-host:POSTGRES_HOST"
    "db-name:POSTGRES_DB"
    "db-user:POSTGRES_USER"
    "db-password:POSTGRES_PASSWORD"
    "jwt-secret:JWT_SECRET"
    "admin-access-key:ADMIN_ACCESS_KEY"
    "admin-password:INITIAL_ADMIN_PASSWORD"
    "admin-email:INITIAL_ADMIN_EMAIL"
    "client-id:INITIAL_CLIENT_ID"
    "client-secret:INITIAL_CLIENT_SECRET"
    "brevo-api-key:BREVO_API_KEY"
    "resend-api-key:RESEND_API_KEY"
    "postbud-api-key:POSTBUD_APIKEY"
    "issuer:ISSUER"
    "base-url:BASE_URL"
    "frontend-url:FRONTEND_URL"
    "NATS_URL:NATS_URL"
    "nats-stream-replicas:NATS_STREAM_REPLICAS"
    "idura-enabled:IDURA_ENABLED"
    "idura-domain:IDURA_DOMAIN"
    "idura-client-id:IDURA_CLIENT_ID"
    "idura-client-secret:IDURA_CLIENT_SECRET"
    "idura-acr-values:IDURA_ACR_VALUES"
)

ENV_NAME=""
ACTION="push"

while [ $# -gt 0 ]; do
    case "$1" in
        --env)    ENV_NAME="${2:-}"; shift 2 ;;
        --env=*)  ENV_NAME="${1#*=}"; shift ;;
        --pull)   ACTION="pull"; shift ;;
        --push)   ACTION="push"; shift ;;
        --diff)   ACTION="diff"; shift ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}" >&2
            exit 2 ;;
    esac
done

case "$ENV_NAME" in
    test|prod) ;;
    "")
        echo -e "${RED}--env is required (test or prod).${NC}" >&2
        echo -e "${YELLOW}No default on purpose: this script writes to a cluster,${NC}" >&2
        echo -e "${YELLOW}and the old default was prod.${NC}" >&2
        exit 2 ;;
    *)
        echo -e "${RED}--env must be test or prod (got '$ENV_NAME').${NC}" >&2
        exit 2 ;;
esac

ENV_FILE="$REPO_ROOT/.env.$ENV_NAME"

# --- Cluster access -----------------------------------------------------
# An explicit KUBECONFIG wins. Otherwise a per-environment file, so the two
# clusters cannot be confused; the legacy unsuffixed .kubeconfig is accepted
# for prod only, which is the cluster it was always fetched from.
if [ -z "${KUBECONFIG:-}" ]; then
    if [ -f "$REPO_ROOT/.kubeconfig.$ENV_NAME" ]; then
        export KUBECONFIG="$REPO_ROOT/.kubeconfig.$ENV_NAME"
    elif [ "$ENV_NAME" = "prod" ] && [ -f "$REPO_ROOT/.kubeconfig" ]; then
        export KUBECONFIG="$REPO_ROOT/.kubeconfig"
    fi
fi

check_connectivity() { kubectl cluster-info > /dev/null 2>&1; }

TUNNEL_PID=""
if ! check_connectivity; then
    if [ "$ENV_NAME" = "prod" ]; then
        # k3s.sh tunnels to the prod control plane. Test is reached over the
        # tailnet with its own kubeconfig, so there is nothing to tunnel.
        echo -e "${YELLOW}🌐 Cluster not reachable. Starting the prod SSH tunnel…${NC}"
        "$SCRIPT_DIR/k3s.sh" tunnel > /dev/null 2>&1 &
        TUNNEL_PID=$!
        trap 'kill $TUNNEL_PID 2>/dev/null || true' EXIT
        for _ in 1 2 3 4 5; do
            check_connectivity && break
            sleep 2
        done
    fi

    if ! check_connectivity; then
        echo -e "${RED}❌ Cannot reach the $ENV_NAME cluster.${NC}" >&2
        echo -e "${YELLOW}Set KUBECONFIG, or place one at .kubeconfig.$ENV_NAME.${NC}" >&2
        [ "$ENV_NAME" = "test" ] && echo -e "${YELLOW}The test cluster is reached over the tailnet; CI uses KUBECONFIG_TEST.${NC}" >&2
        exit 1
    fi
fi

secret_json() {
    if ! kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" > /dev/null 2>&1; then
        echo -e "${RED}❌ Secret '$SECRET_NAME' not found in $NAMESPACE ($ENV_NAME).${NC}" >&2
        exit 1
    fi
    kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o json
}

cluster_value() {  # $1 = json, $2 = k8s key
    local v
    v=$(printf '%s' "$1" | jq -r --arg k "$2" '.data[$k] // empty')
    [ -n "$v" ] && printf '%s' "$v" | base64 -d || true
}

# Keys in the env file that the cluster secret does not carry. Named, never
# valued -- the point is to make the gap visible, not to print credentials.
orphan_env_keys() {
    local mapped=" "
    for item in "${MAPPING[@]}"; do mapped="$mapped${item#*:} "; done
    grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" 2>/dev/null \
        | tr -d '=' | sort -u \
        | while read -r k; do
            case "$mapped" in *" $k "*) ;; *) echo "$k";; esac
        done
}

case "$ACTION" in

pull)
    echo -e "${BLUE}=== Pulling $ENV_NAME secrets into $ENV_FILE ===${NC}"
    JSON=$(secret_json)

    TMP=$(mktemp)
    chmod 600 "$TMP"
    echo "# NetworcoID $ENV_NAME secrets, pulled from the cluster on $(date)" > "$TMP"
    echo "# PARTIAL: only keys stored in $SECRET_NAME. See the header of" >> "$TMP"
    echo "# scripts/sync-secrets.sh before using this as an env file." >> "$TMP"
    for item in "${MAPPING[@]}"; do
        K8S_KEY=${item%%:*}; ENV_KEY=${item#*:}
        VALUE=$(cluster_value "$JSON" "$K8S_KEY")
        [ -n "$VALUE" ] && echo "$ENV_KEY=$VALUE" >> "$TMP"
    done

    if [ -f "$ENV_FILE" ]; then
        MISSING=$(orphan_env_keys | tr '\n' ' ')
        cp "$ENV_FILE" "$ENV_FILE.bak"
        chmod 600 "$ENV_FILE.bak"
        echo -e "${YELLOW}Existing file backed up to $(basename "$ENV_FILE").bak${NC}"
        if [ -n "${MISSING// /}" ]; then
            echo -e "${RED}⚠️  These keys exist in your env file but NOT in the cluster,${NC}"
            echo -e "${RED}   and are about to be lost from it:${NC}"
            echo -e "${RED}   $MISSING${NC}"
            echo -e "${YELLOW}   Do not push the result to the GitHub env secret.${NC}"
        fi
    fi

    mv "$TMP" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo -e "${GREEN}✓ Wrote $ENV_FILE (mode 600)${NC}"
    ;;

diff)
    echo -e "${BLUE}=== Comparing $ENV_FILE with the $ENV_NAME cluster ===${NC}"
    [ -f "$ENV_FILE" ] || { echo -e "${RED}❌ $ENV_FILE not found.${NC}" >&2; exit 1; }
    JSON=$(secret_json)

    set -a; . "$ENV_FILE"; set +a

    SAME=0; DIFFERENT=(); ONLY_LOCAL=(); ONLY_CLUSTER=()
    for item in "${MAPPING[@]}"; do
        K8S_KEY=${item%%:*}; ENV_KEY=${item#*:}
        LOCAL="${!ENV_KEY:-}"
        REMOTE=$(cluster_value "$JSON" "$K8S_KEY")
        if [ -n "$LOCAL" ] && [ -n "$REMOTE" ]; then
            if [ "$LOCAL" = "$REMOTE" ]; then SAME=$((SAME+1)); else DIFFERENT+=("$ENV_KEY"); fi
        elif [ -n "$LOCAL" ]; then ONLY_LOCAL+=("$ENV_KEY")
        elif [ -n "$REMOTE" ]; then ONLY_CLUSTER+=("$ENV_KEY")
        fi
    done

    # Values are never printed -- a name is enough to know what to look at.
    echo -e "${GREEN}$SAME key(s) identical${NC}"
    [ ${#DIFFERENT[@]}    -gt 0 ] && echo -e "${RED}differs:      ${DIFFERENT[*]}${NC}"
    [ ${#ONLY_LOCAL[@]}   -gt 0 ] && echo -e "${YELLOW}only local:   ${ONLY_LOCAL[*]}${NC}"
    [ ${#ONLY_CLUSTER[@]} -gt 0 ] && echo -e "${YELLOW}only cluster: ${ONLY_CLUSTER[*]}${NC}"

    ORPHANS=$(orphan_env_keys | tr '\n' ' ')
    [ -n "${ORPHANS// /}" ] && echo -e "${BLUE}not stored in the cluster at all: ${ORPHANS}${NC}"

    [ ${#DIFFERENT[@]} -eq 0 ] || exit 1
    ;;

push)
    echo -e "${BLUE}=== Pushing $ENV_FILE to the $ENV_NAME cluster ===${NC}"
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${RED}❌ $ENV_FILE not found.${NC}" >&2
        echo -e "${YELLOW}Create it, or start from '--env $ENV_NAME --pull' (partial).${NC}" >&2
        exit 1
    fi

    set -a; . "$ENV_FILE"; set +a

    POSTGRES_HOST=${POSTGRES_HOST:-postgres}
    NATS_URL=${NATS_URL:-nats://nats.networco-id.svc.cluster.local:4222}

    # Only keys that actually have a value. An env file that has lost a key
    # must not blank a working credential in the cluster -- it stays until
    # something deliberately replaces it.
    ARGS=(); SKIPPED=()
    for item in "${MAPPING[@]}"; do
        K8S_KEY=${item%%:*}; ENV_KEY=${item#*:}
        VALUE="${!ENV_KEY:-}"
        if [ -n "$VALUE" ]; then
            ARGS+=(--from-literal="$K8S_KEY=$VALUE")
        else
            SKIPPED+=("$ENV_KEY")
        fi
    done

    [ ${#SKIPPED[@]} -gt 0 ] && echo -e "${YELLOW}Unset, left as-is in the cluster: ${SKIPPED[*]}${NC}"

    kubectl create secret generic "$SECRET_NAME" \
        --namespace "$NAMESPACE" "${ARGS[@]}" \
        --dry-run=client -o yaml | kubectl apply -f -

    echo -e "${GREEN}✓ Secret updated${NC}"

    echo -e "${YELLOW}Restarting deployments in $NAMESPACE ($ENV_NAME)…${NC}"
    kubectl rollout restart deployment networcoid networcoid-worker -n "$NAMESPACE"
    kubectl rollout status  deployment networcoid        -n "$NAMESPACE"
    kubectl rollout status  deployment networcoid-worker -n "$NAMESPACE"
    echo -e "${GREEN}✓ Rolled out${NC}"
    ;;

esac
