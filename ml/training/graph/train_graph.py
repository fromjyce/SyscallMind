"""Train the GraphSAGE model for program-syscall-resource link prediction."""
import argparse
import json
import os
import sys
import torch
import torch.nn.functional as F
from torch.optim import Adam
from tqdm import tqdm

from graph_model import GraphDataset, ProgramSyscallGraph


def link_prediction_loss(embeddings: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
    """Contrastive loss: push connected nodes together, unconnected apart."""
    src, dst = edge_index[0], edge_index[1]
    pos_score = (embeddings[src] * embeddings[dst]).sum(dim=-1)
    pos_loss = F.binary_cross_entropy_with_logits(pos_score, torch.ones_like(pos_score))

    # Negative samples: random unconnected pairs
    neg_src = torch.randint(0, embeddings.size(0), (src.size(0),), device=embeddings.device)
    neg_dst = torch.randint(0, embeddings.size(0), (src.size(0),), device=embeddings.device)
    neg_score = (embeddings[neg_src] * embeddings[neg_dst]).sum(dim=-1)
    neg_loss = F.binary_cross_entropy_with_logits(neg_score, torch.zeros_like(neg_score))

    return pos_loss + neg_loss


def train(args):
    device = torch.device("cpu")
    dataset = GraphDataset(num_samples=args.epochs * 50)
    model = ProgramSyscallGraph(
        num_nodes=dataset.total_nodes,
        embed_dim=args.embed_dim,
    ).to(device)
    optimizer = Adam(model.parameters(), lr=1e-3)

    print(f"Training GraphSAGE | nodes={dataset.total_nodes} | embed_dim={args.embed_dim}")

    for epoch in range(1, args.epochs + 1):
        model.train()
        epoch_loss = 0.0
        n_batches = 0
        for sample in tqdm(dataset, desc=f"Epoch {epoch}", leave=False):
            edge_index = sample["edge_index"].to(device)
            if edge_index.size(1) == 0:
                continue
            optimizer.zero_grad()
            embeddings = model(edge_index)
            loss = link_prediction_loss(embeddings, edge_index)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            n_batches += 1
        avg_loss = epoch_loss / max(n_batches, 1)
        print(f"Epoch {epoch:3d}/{args.epochs} | loss={avg_loss:.4f}")

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    torch.save(model.state_dict(), args.output.replace(".onnx", ".pt"))
    print(f"Model saved to {args.output.replace('.onnx', '.pt')}")
    print("Note: ONNX export for graph models requires manual tracing — see export_onnx.py")


def main():
    parser = argparse.ArgumentParser(description="Train GraphSAGE for syscall analysis")
    parser.add_argument("--traces", default=None, help="Optional traces file (not used for synthetic training)")
    parser.add_argument("--output", required=True, help="Output model path")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--embed-dim", type=int, default=64)
    args = parser.parse_args()
    train(args)


if __name__ == "__main__":
    main()
