#!/bin/bash
set -e

# Configuration
SERVER="217.170.206.215"
USER="root"
LOCAL_PORT=6443
KUBECONFIG_PATH="$(pwd)/.kubeconfig"

if [ "$1" == "tunnel" ]; then
    echo "🌐 Opening SSH tunnel to $SERVER..."
    echo "Keep this process running to use kubectl."
    ssh -L $LOCAL_PORT:127.0.0.1:6443 $USER@$SERVER -N
elif [ "$1" == "setup" ]; then
    echo "📥 Fetching k3s config from $SERVER..."
    ssh $USER@$SERVER "cat /etc/rancher/k3s/k3s.yaml" > "$KUBECONFIG_PATH"
    
    # Update server to localhost and set restrictive permissions
    sed -i '' "s/$SERVER/127.0.0.1/g" "$KUBECONFIG_PATH" 2>/dev/null || sed -i "s/$SERVER/127.0.0.1/g" "$KUBECONFIG_PATH"
    chmod 600 "$KUBECONFIG_PATH"
    
    echo "✅ Config saved to $KUBECONFIG_PATH"
    echo "🚀 To use: export KUBECONFIG=$KUBECONFIG_PATH"
else
    echo "Usage:"
    echo "  $0 setup  - Fetches and configures .kubeconfig"
    echo "  $0 tunnel - Opens the SSH tunnel (required if API is not public)"
fi
