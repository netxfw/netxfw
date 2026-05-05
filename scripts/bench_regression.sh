#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="${NETXFW_BENCH_DIR:-$HOME/.netxfw/benchmarks}"

echo "🔧 Setting up performance regression testing..."
echo "   Benchmark directory: $BENCH_DIR"

mkdir -p "$BENCH_DIR"

echo ""
echo "📊 Running baseline benchmarks..."

cd "$PROJECT_ROOT"

export GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
export NETXFW_BENCH_DIR="$BENCH_DIR"

go test -bench=. -benchmem -run=^$ ./test/performance/... 2>&1 | tee "$BENCH_DIR/bench_output.txt"

echo ""
echo "💾 Saving baseline results..."

if [ -f "$BENCH_DIR/results.json" ]; then
    cp "$BENCH_DIR/results.json" "$BENCH_DIR/baseline.json"
    echo "✅ Baseline saved to $BENCH_DIR/baseline.json"
else
    echo "⚠️  No results found. Creating empty baseline..."
    echo '{}' > "$BENCH_DIR/baseline.json"
fi

echo ""
echo "📈 Running regression tests..."

go test -v ./test/performance/... -run TestPerformanceRegression

echo ""
echo "✅ Performance regression testing complete!"
echo "   Results: $BENCH_DIR/results.json"
echo "   Baseline: $BENCH_DIR/baseline.json"
echo "   Report: $BENCH_DIR/regression_report.json"
