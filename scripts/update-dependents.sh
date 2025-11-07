#!/bin/bash
# Update go-api version across all dependent projects

set -e

NEW_VERSION=$1
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.0.11"
    exit 1
fi

PROJECTS=("app-scanner" "app-agent")
BASE_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "🚀 Updating go-api to $NEW_VERSION across dependent projects..."

for project in "${PROJECTS[@]}"; do
    PROJECT_PATH="$BASE_DIR/$project"
    
    if [ ! -d "$PROJECT_PATH" ]; then
        echo "⚠️  Project $project not found at $PROJECT_PATH"
        continue
    fi
    
    echo ""
    echo "📦 Updating $project..."
    cd "$PROJECT_PATH"
    
    # Update go.mod
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|github.com/SiriusScan/go-api v[0-9.]*|github.com/SiriusScan/go-api $NEW_VERSION|g" go.mod
    else
        # Linux
        sed -i "s|github.com/SiriusScan/go-api v[0-9.]*|github.com/SiriusScan/go-api $NEW_VERSION|g" go.mod
    fi
    
    # Run go mod tidy
    go mod tidy
    
    # Test build
    echo "  🔨 Testing build..."
    if go build -o /dev/null .; then
        echo "  ✅ Build successful"
    else
        echo "  ❌ Build failed - manual intervention required"
        continue
    fi
    
    # Run tests (with timeout)
    echo "  🧪 Running tests..."
    if timeout 60 go test ./... -short 2>/dev/null; then
        echo "  ✅ Tests passed"
    else
        echo "  ⚠️  Tests failed or timed out - review required"
    fi
    
    # Commit changes
    git add go.mod go.sum 2>/dev/null || true
    if git commit -m "chore: update go-api SDK to $NEW_VERSION" 2>/dev/null; then
        echo "  ✅ Changes committed"
    else
        echo "  ℹ️  No changes to commit"
    fi
    
    echo "  ✅ $project updated successfully"
done

echo ""
echo "✅ All projects updated to go-api $NEW_VERSION"
echo ""
echo "Next steps:"
echo "  1. Review and test changes manually"
echo "  2. Push commits: cd <project> && git push origin main"
echo "  3. Monitor dependent project CI/CD"








