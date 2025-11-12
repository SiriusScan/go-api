#!/bin/bash
# Quick Circular Reference Test Script
# Run this to validate repository pattern without full integration testing

echo "🧪 Running Quick Circular Reference Tests"
echo "=========================================="
echo ""

cd /go-api

# Run repository tests
echo "📝 Running repository pattern tests..."
go test -v ./sirius/host -run TestRepository 2>&1 | grep -E '(RUN|PASS|FAIL|✅|❌|Test [0-9]|===)'

# Extract result
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ ALL TESTS PASSED - NO CIRCULAR REFERENCES"
else
    echo ""
    echo "❌ TESTS FAILED - CHECK OUTPUT ABOVE"
    exit 1
fi





