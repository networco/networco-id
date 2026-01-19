#!/bin/bash
# =============================================================================
# NetworcoID - Build and Push Images
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
VERSION_FILE="$REPO_ROOT/VERSION"
REGISTRY="ghcr.io/networco"
NO_PUSH=false
NEW_VERSION=""

# Parse arguments
for arg in "$@"; do
    case $arg in
        --no-push)
            NO_PUSH=true
            ;;
        major)
            BUMP="major"
            ;;
        minor)
            BUMP="minor"
            ;;
        patch)
            BUMP="patch"
            ;;
        *)
            if [[ "$arg" == *"."* ]]; then
                NEW_VERSION="$arg"
            fi
            ;;
    esac
done

# Version Management
read_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE"
    else
        echo "0.0.1.0"
    fi
}

parse_version() {
    local version="$1"
    IFS='.' read -r MAJOR MINOR PATCH BUILD <<< "$version"
    MAJOR="${MAJOR:-0}"
    MINOR="${MINOR:-0}"
    PATCH="${PATCH:-0}"
    BUILD="${BUILD:-0}"
}

increment_version() {
    case $BUMP in
        major)
            MAJOR=$((MAJOR + 1))
            MINOR=0
            PATCH=0
            ;;
        minor)
            MINOR=$((MINOR + 1))
            PATCH=0
            ;;
        patch)
            PATCH=$((PATCH + 1))
            ;;
    esac
    BUILD=$((BUILD + 1))
}

format_version() {
    echo "${MAJOR}.${MINOR}.${PATCH}.${BUILD}"
}

format_semver() {
    echo "${MAJOR}.${MINOR}.${PATCH}"
}

CURRENT_VERSION=$(read_version)
parse_version "$CURRENT_VERSION"

if [[ -n "$NEW_VERSION" ]]; then
    PART_COUNT=$(echo "$NEW_VERSION" | tr '.' '\n' | wc -l)
    if [[ $PART_COUNT -eq 3 ]]; then
        IFS='.' read -r NEW_MAJOR NEW_MINOR NEW_PATCH <<< "$NEW_VERSION"
        MAJOR="$NEW_MAJOR"
        MINOR="$NEW_MINOR"
        PATCH="$NEW_PATCH"
        BUILD=$((BUILD + 1))
    else
        parse_version "$NEW_VERSION"
        BUILD=$((BUILD + 1))
    fi
else
    increment_version
fi

VERSION=$(format_version)
SEMVER=$(format_semver)
echo "$VERSION" > "$VERSION_FILE"

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo -e "${BLUE}=== NetworcoID Image Builder ===${NC}"
echo "Registry: $REGISTRY"
echo "Version:  $VERSION"
echo "Git SHA:  $GIT_SHA"
echo ""

cd "$REPO_ROOT"

# Build ID Provider
echo -e "${YELLOW}Building NetworcoID image...${NC}"
docker buildx build \
    --platform linux/amd64 \
    -f src/NetworcoId/Dockerfile \
    -t "$REGISTRY/networco-id:$VERSION" \
    -t "$REGISTRY/networco-id:latest" \
    --build-arg APP_VERSION="$VERSION" \
    --push \
    .

# Build Worker
echo -e "${YELLOW}Building Worker image...${NC}"
docker buildx build \
    --platform linux/amd64 \
    -f src/NetworcoId.Worker/Dockerfile \
    -t "$REGISTRY/networco-id-worker:$VERSION" \
    -t "$REGISTRY/networco-id-worker:latest" \
    --build-arg APP_VERSION="$VERSION" \
    --push \
    .

if [[ "$NO_PUSH" == "false" ]]; then
    echo -e "${GREEN}✓ Success!${NC}"
fi
