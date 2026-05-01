# ML Design — SyscallMind

## Model 1: Transformer Sequence Model

### Architecture

A decoder-only (causal) Transformer trained as a language model over a vocabulary of 256 syscall IDs.

| Hyperparameter | Value |
|---|---|
| Architecture | 4-layer Transformer encoder with causal mask |
| Embedding dimension | 128 |
| Attention heads | 4 |
| Feed-forward dimension | 512 (4× embed) |
| Max context length | 64 syscalls |
| Vocabulary size | 256 |
| Dropout | 0.1 |
| Parameters | ~2.4M |

The model uses a standard token embedding + learned positional embedding. A causal mask ensures the model cannot attend to future tokens, matching the autoregressive inference requirement.

### Training

**Data format**: Each training sample is a sliding window over an `ExecutionWindow`, shifted by 1 to create (input, target) pairs for next-token prediction.

**Loss**: Cross-entropy over the vocabulary, with padding tokens (ID=0) ignored.

**Optimizer**: AdamW with cosine annealing LR schedule. Initial LR = 1e-3, weight decay = 1e-4, gradient clipping at 1.0.

**Data volume**: 10M+ execution windows from simulated workloads are needed for convergence. Each window yields up to 64 training samples.

### ONNX Export

The trained model is exported via `torch.onnx.export` with dynamic batch and sequence length axes, opset 14. The exported model takes `input_ids: int64[batch, seq_len]` and returns `logits: float32[batch, seq_len, 256]`.

### Inference

At runtime, the Rust `TransformerPredictor` calls the ONNX model with the current syscall history (padded to the context length). The top-k logits from the last position are extracted and softmax-normalized to yield `Vec<(SyscallId, f32)>`.

**Inference latency target**: <2ms p95 on CPU with 2 inference threads.

### Performance vs Accuracy Trade-offs

- Increasing `num_layers` from 4 to 8 improves top-3 accuracy by ~3% but doubles inference latency.
- Reducing `embed_dim` to 64 cuts latency by 40% but drops top-1 accuracy by ~5%.
- The current 4-layer/128-dim config is the Pareto-optimal point for the <2ms latency budget.

---

## Model 2: Program-Syscall-Resource Graph Model

### Architecture

A 2-layer GraphSAGE model over a tripartite graph:

```
Program ──calls──► Syscall ──accesses──► Resource
```

Node types:
- **Program nodes**: smart contract address (P nodes)
- **Syscall nodes**: syscall ID (256 nodes, fixed vocabulary)
- **Resource nodes**: account addresses / sysvars (R nodes)

GraphSAGE uses mean aggregation: each node's new embedding is computed from its own embedding concatenated with the mean of its neighbors' embeddings, passed through a linear layer + ReLU.

### Training

Trained on a link prediction task: given the graph structure, predict whether a (program, syscall) edge exists. Positive edges come from observed execution windows; negatives are randomly sampled unconnected pairs.

Loss: binary cross-entropy on positive and negative edge scores (dot product of node embeddings).

### Cross-Program Transfer

The key benefit of the graph model: programs with structurally similar call graphs get similar node embeddings. This enables zero-shot prediction for newly deployed programs by finding their nearest neighbors in embedding space.

This model is expensive (graph construction overhead) and is used offline for baseline construction and anomaly feature enrichment, not in the real-time optimization path.

---

## Model 3: Isolation Forest

### Feature Engineering

Each execution window is mapped to an 8-dimensional feature vector:

| Index | Feature | Description |
|---|---|---|
| 0 | `crypto_ratio` | Fraction of calls that are crypto ops |
| 1 | `max_cpi_depth` / 10 | Normalized maximum CPI call depth |
| 2 | `mean_inter_call_delay` (ms) | Mean time between consecutive syscalls, capped at 100ms |
| 3 | `syscall_diversity` | # unique syscall IDs / 30 |
| 4 | `log_total_calls` | log(1 + total calls in window) |
| 5–7 | Top-3 syscall frequencies | Most common syscall frequencies |

### Isolation Forest Configuration

- 100 estimators
- max_samples = 256 (or dataset size if smaller)
- contamination = 0.05 (tunable per deployment)

The contamination parameter controls the threshold: 5% of training samples are expected to be anomalous. Decrease for more conservative flagging (fewer false positives); increase for higher recall.

### Online Learning Considerations

The current approach retrains the full model from scratch on new data. Research directions:

1. **Reservoir sampling**: maintain a fixed-size reservoir of ~100K windows, updated with new arrivals. Retrain every 5 minutes on the reservoir.
2. **Incremental PCA**: maintain a running PCA of the feature space; detect drift as new batches shift the principal components.
3. **Per-program fine-tuning**: keep a separate lightweight model per high-traffic program, updated incrementally.

The transformer sequence model presents a harder online learning challenge due to catastrophic forgetting. Gradient episodic memory (GEM) or elastic weight consolidation (EWC) are candidate approaches.
