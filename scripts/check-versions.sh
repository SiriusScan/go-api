#!/bin/bash
# Check which version of go-api each dependent project is using

BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECTS=("app-scanner" "app-agent")

echo "📊 go-api version check across projects"
echo "========================================"
echo ""

# Get latest go-api version
cd "$BASE_DIR/go-api"
LATEST_VERSION=$(git tag -l "v*" --sort=-version:refname | head -1)
echo "Latest go-api version: $LATEST_VERSION"
echo ""

for project in "${PROJECTS[@]}"; do
    PROJECT_PATH="$BASE_DIR/$project"
    
    if [ ! -f "$PROJECT_PATH/go.mod" ]; then
        echo "⚠️  $project: go.mod not found"
        continue
    fi
    
    CURRENT_VERSION=$(grep "github.com/SiriusScan/go-api" "$PROJECT_PATH/go.mod" | grep -v "replace" | awk '{print $2}')
    
    if [ -z "$CURRENT_VERSION" ]; then
        echo "⚠️  $project: version not found in go.mod"
        continue
    fi
    
    if [ "$CURRENT_VERSION" == "$LATEST_VERSION" ]; then
        echo "✅ $project: $CURRENT_VERSION (up to date)"
    else
        echo "⚠️  $project: $CURRENT_VERSION (outdated, latest: $LATEST_VERSION)"
    fi
done

echo ""

# Check container usage
echo "🐳 Container go-api usage"
echo "=========================="
echo ""

SIRIUS_ROOT="$(cd "$BASE_DIR/.." && pwd)"
if [ -f "$SIRIUS_ROOT/Sirius/docker-compose.dev.yaml" ]; then
    echo "✅ sirius-engine: Uses volume mount (../minor-projects/go-api:/go-api)"
    echo "✅ sirius-api: Uses volume mount (../minor-projects/go-api:/go-api)"
    echo ""
    echo "ℹ️  Container changes take effect immediately (no version update needed)"
    echo "ℹ️  For production, rebuild images with updated version"
else
    echo "⚠️  docker-compose.dev.yaml not found"
fi

echo ""
echo "To update projects to latest version:"
echo "  cd $BASE_DIR/go-api"
echo "  ./scripts/update-dependents.sh $LATEST_VERSION"








