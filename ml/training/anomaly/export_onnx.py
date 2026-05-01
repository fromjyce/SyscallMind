"""Export sklearn IsolationForest to ONNX using skl2onnx."""
import argparse
import os
import numpy as np


def export_isolation_forest_to_onnx(model, output_path: str, n_features: int = 8):
    """Convert a fitted sklearn IsolationForest to an ONNX model file."""
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        print("skl2onnx not installed. Run: pip install skl2onnx")
        print(f"Skipping ONNX export. Model available as .joblib file.")
        return

    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(model, initial_types=initial_type)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"ONNX model exported to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True, help="Path to .joblib model")
    parser.add_argument("--output", required=True, help="Output .onnx path")
    parser.add_argument("--n-features", type=int, default=8)
    args = parser.parse_args()

    import joblib
    model = joblib.load(args.checkpoint)
    export_isolation_forest_to_onnx(model, args.output, args.n_features)
