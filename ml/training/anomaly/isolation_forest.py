"""Train an Isolation Forest for syscall anomaly detection."""
import argparse
import json
import math
import os
import sys
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import joblib

CRYPTO_IDS = {20, 21, 22, 23}  # SHA256, KECCAK256, SECP256K1, ED25519


def extract_features(windows: list) -> np.ndarray:
    """Extract an 8-element feature vector from each execution window."""
    features = []
    for window in windows:
        events = window.get("events", [])
        if not events:
            features.append(np.zeros(8))
            continue

        ids = [e["syscall_id"] for e in events]
        timestamps = [e.get("timestamp_ns", 0) for e in events]
        depths = [e.get("depth", 0) for e in events]
        total = len(ids)

        # Feature 1: crypto syscall ratio
        crypto_count = sum(1 for i in ids if i in CRYPTO_IDS)
        crypto_ratio = crypto_count / total

        # Feature 2: CPI depth
        max_cpi_depth = max(depths) if depths else 0

        # Feature 3: mean inter-call delay (normalized to ms)
        if len(timestamps) > 1:
            delays = [abs(timestamps[i+1] - timestamps[i]) for i in range(len(timestamps) - 1)]
            mean_delay = sum(delays) / len(delays) / 1_000_000  # ns → ms
        else:
            mean_delay = 0.0

        # Feature 4: syscall diversity (Shannon entropy)
        freq = {}
        for i in ids:
            freq[i] = freq.get(i, 0) + 1
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)

        # Feature 5: log total calls
        log_calls = math.log1p(total)

        # Features 6-8: top-3 syscall frequencies
        sorted_freqs = sorted((c / total for c in freq.values()), reverse=True)
        sorted_freqs += [0.0] * 3
        f6, f7, f8 = sorted_freqs[0], sorted_freqs[1], sorted_freqs[2]

        features.append([crypto_ratio, max_cpi_depth, mean_delay, entropy, log_calls, f6, f7, f8])

    return np.array(features, dtype=np.float32)


def load_windows(path: str) -> list:
    windows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                windows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return windows


def train_isolation_forest(
    features: np.ndarray,
    contamination: float = 0.05,
    n_estimators: int = 100,
) -> IsolationForest:
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        max_samples=min(256, len(features)),
    )
    model.fit(features)
    return model


def evaluate_model(model: IsolationForest, features: np.ndarray, labels=None) -> dict:
    scores = model.score_samples(features)
    preds = model.predict(features)  # 1 = normal, -1 = anomaly
    result = {"mean_score": float(scores.mean()), "std_score": float(scores.std())}
    if labels is not None:
        bin_preds = (preds == -1).astype(int)
        result["precision"] = precision_score(labels, bin_preds, zero_division=0)
        result["recall"] = recall_score(labels, bin_preds, zero_division=0)
        result["f1"] = f1_score(labels, bin_preds, zero_division=0)
    return result


def main():
    parser = argparse.ArgumentParser(description="Train Isolation Forest anomaly detector")
    parser.add_argument("--traces", required=True, help="Path to NDJSON trace file")
    parser.add_argument("--output", required=True, help="Output model path (.joblib or .onnx)")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--n-estimators", type=int, default=100)
    args = parser.parse_args()

    print(f"Loading windows from {args.traces}...")
    windows = load_windows(args.traces)
    if not windows:
        print("No windows found. Run workload-generator first.", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {len(windows)} windows")

    features = extract_features(windows)
    print(f"Feature matrix: {features.shape}")

    model = train_isolation_forest(features, args.contamination, args.n_estimators)
    metrics = evaluate_model(model, features)
    print(f"Training metrics: {metrics}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    joblib_path = args.output.replace(".onnx", ".joblib")
    joblib.dump(model, joblib_path)
    print(f"Model saved to {joblib_path}")

    # Export to ONNX
    from export_onnx import export_isolation_forest_to_onnx
    export_isolation_forest_to_onnx(model, args.output, n_features=features.shape[1])


if __name__ == "__main__":
    main()
