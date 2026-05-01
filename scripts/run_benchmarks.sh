#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="benches/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=== SyscallMind: Benchmark Suite ==="
echo "Results directory: $RESULTS_DIR/$TIMESTAMP"
echo

mkdir -p "$RESULTS_DIR/$TIMESTAMP"

echo "--- End-to-End Benchmark ---"
cargo bench --bench end_to_end 2>&1 | tee "$RESULTS_DIR/$TIMESTAMP/end_to_end.txt"

echo
echo "--- Saving baseline ---"
cargo bench --bench end_to_end -- --save-baseline "baseline_$TIMESTAMP" 2>/dev/null || true

echo
echo "=== Benchmarks complete. Results saved to $RESULTS_DIR/$TIMESTAMP ==="
