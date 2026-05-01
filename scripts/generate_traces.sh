#!/usr/bin/env bash
set -euo pipefail

TRANSACTIONS="${1:-1000000}"
OUTPUT="traces/workload_${TRANSACTIONS}.jsonl"

echo "=== SyscallMind: Trace Generation ==="
echo "Transactions : $TRANSACTIONS"
echo "Output       : $OUTPUT"
echo

mkdir -p traces

echo "Building workload-generator..."
cargo build --release --bin workload-generator 2>&1 | tail -3

echo "Generating $TRANSACTIONS synthetic transactions..."
time cargo run --release --bin workload-generator -- \
    --transactions "$TRANSACTIONS" \
    --output "$OUTPUT"

echo
echo "Output size: $(du -sh "$OUTPUT" | cut -f1)"
echo "Line count:  $(wc -l < "$OUTPUT")"
echo "Done: $OUTPUT"
