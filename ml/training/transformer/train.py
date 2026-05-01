"""Train the SyscallMind Transformer model for next-syscall prediction."""
import argparse
import json
import os
import sys
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, random_split
from tqdm import tqdm

from model import SyscallDataset, create_model


def load_traces(path: str) -> list:
    """Load JSON-lines execution windows, extracting syscall_id sequences."""
    sequences = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                window = json.loads(line)
                ids = [e["syscall_id"] for e in window.get("events", [])]
                if len(ids) >= 2:
                    sequences.append(ids)
            except (json.JSONDecodeError, KeyError):
                continue
    return sequences


def top_k_accuracy(logits: torch.Tensor, targets: torch.Tensor, k: int) -> float:
    _, topk = logits.topk(k, dim=-1)
    correct = topk.eq(targets.unsqueeze(-1).expand_as(topk))
    return correct.any(dim=-1).float().mean().item()


def train_epoch(model, loader, optimizer, criterion, device) -> float:
    model.train()
    total_loss = 0.0
    for inputs, targets in loader:
        inputs, targets = inputs.to(device), targets.to(device)
        optimizer.zero_grad()
        logits = model(inputs)
        B, T, V = logits.shape
        loss = criterion(logits.reshape(B * T, V), targets.reshape(B * T))
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        total_loss += loss.item()
    return total_loss / max(len(loader), 1)


def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    top1_acc = 0.0
    top3_acc = 0.0
    n_batches = 0
    with torch.no_grad():
        for inputs, targets in loader:
            inputs, targets = inputs.to(device), targets.to(device)
            logits = model(inputs)
            B, T, V = logits.shape
            loss = criterion(logits.reshape(B * T, V), targets.reshape(B * T))
            total_loss += loss.item()
            top1_acc += top_k_accuracy(logits[:, -1], targets[:, -1], 1)
            top3_acc += top_k_accuracy(logits[:, -1], targets[:, -1], 3)
            n_batches += 1
    n = max(n_batches, 1)
    return total_loss / n, top1_acc / n, top3_acc / n


def main():
    parser = argparse.ArgumentParser(description="Train SyscallMind Transformer")
    parser.add_argument("--traces", required=True, help="Path to NDJSON trace file")
    parser.add_argument("--output", required=True, help="Output path for ONNX model")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--checkpoint", default=None, help="Save checkpoint .pt file")
    args = parser.parse_args()

    device = torch.device(args.device)
    print(f"Training on device: {device}")

    print(f"Loading traces from {args.traces}...")
    sequences = load_traces(args.traces)
    if not sequences:
        print("No sequences found. Generate traces first with workload-generator.", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {len(sequences)} sequences")

    dataset = SyscallDataset(sequences)
    n_val = max(1, len(dataset) // 10)
    n_train = len(dataset) - n_val
    train_set, val_set = random_split(dataset, [n_train, n_val])
    train_loader = DataLoader(train_set, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=args.batch_size)

    model = create_model().to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)
    criterion = nn.CrossEntropyLoss(ignore_index=0)

    print(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")

    for epoch in range(1, args.epochs + 1):
        train_loss = train_epoch(model, train_loader, optimizer, criterion, device)
        val_loss, top1, top3 = evaluate(model, val_loader, criterion, device)
        scheduler.step()
        print(
            f"Epoch {epoch:3d}/{args.epochs} | "
            f"train_loss={train_loss:.4f} | val_loss={val_loss:.4f} | "
            f"top1={top1:.3f} | top3={top3:.3f}"
        )

    if args.checkpoint:
        torch.save(model.state_dict(), args.checkpoint)
        print(f"Checkpoint saved to {args.checkpoint}")

    # Export to ONNX
    from export_onnx import export_to_onnx
    export_to_onnx(model, args.output)
    print(f"ONNX model exported to {args.output}")


if __name__ == "__main__":
    main()
