"""Export SyscallMind Transformer to ONNX format."""
import argparse
import os
import torch
from model import SyscallTransformer, create_model


def export_to_onnx(
    model_or_path,
    output_path: str,
    vocab_size: int = 256,
    max_seq_len: int = 64,
):
    """Export a trained model to ONNX.

    Args:
        model_or_path: Either an nn.Module or a string path to a .pt checkpoint.
        output_path: Destination .onnx file path.
    """
    if isinstance(model_or_path, str):
        model = create_model(vocab_size=vocab_size)
        model.load_state_dict(torch.load(model_or_path, map_location="cpu"))
    else:
        model = model_or_path

    model.eval()
    dummy_input = torch.zeros(1, max_seq_len, dtype=torch.long)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    torch.onnx.export(
        model,
        dummy_input,
        output_path,
        input_names=["input_ids"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size", 1: "seq_len"},
            "logits": {0: "batch_size", 1: "seq_len"},
        },
        opset_version=14,
        do_constant_folding=True,
    )
    print(f"Exported ONNX model to {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True, help="Path to .pt checkpoint")
    parser.add_argument("--output", required=True, help="Output .onnx path")
    parser.add_argument("--vocab-size", type=int, default=256)
    parser.add_argument("--max-seq-len", type=int, default=64)
    args = parser.parse_args()
    export_to_onnx(args.checkpoint, args.output, args.vocab_size, args.max_seq_len)
