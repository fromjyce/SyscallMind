#!/usr/bin/env bash
set -euo pipefail

TRACES="${1:-traces/workload_1000000.jsonl}"
MODELS_DIR="ml/inference/models"

echo "=== SyscallMind: Train All Models ==="
echo "Traces : $TRACES"
echo "Output : $MODELS_DIR"
echo

if [ ! -f "$TRACES" ]; then
    echo "Trace file not found: $TRACES"
    echo "Run scripts/generate_traces.sh first."
    exit 1
fi

mkdir -p "$MODELS_DIR"

echo "--- [1/3] Training Transformer Sequence Model ---"
python ml/training/transformer/train.py \
    --traces "$TRACES" \
    --output "$MODELS_DIR/transformer.onnx" \
    --epochs 20 \
    --batch-size 64
echo "Transformer training complete."
echo

echo "--- [2/3] Training Isolation Forest Anomaly Detector ---"
python ml/training/anomaly/isolation_forest.py \
    --traces "$TRACES" \
    --output "$MODELS_DIR/anomaly.onnx" \
    --contamination 0.05
echo "Anomaly model training complete."
echo

echo "--- [3/3] Training Graph Model (optional, CPU-intensive) ---"
if [ "${SKIP_GRAPH:-0}" = "1" ]; then
    echo "Skipped (SKIP_GRAPH=1)."
else
    python ml/training/graph/train_graph.py \
        --traces "$TRACES" \
        --output "$MODELS_DIR/graph.onnx" \
        --epochs 10 \
        --embed-dim 64
    echo "Graph model training complete."
fi

echo
echo "=== All models ready in $MODELS_DIR ==="
ls -lh "$MODELS_DIR"
