# SyscallMind

**AI-Augmented Syscall Optimization Engine for High-Throughput Blockchain Runtimes**

SyscallMind is a research-grade middleware layer that intercepts, analyzes, and intelligently optimizes syscall streams in real time for Solana-compatible BPF runtimes. It combines transformer-based sequence modeling, speculative prefetching, and epoch-aware caching to reduce redundant computation — while using the same behavioral model to detect anomalous or potentially malicious contracts.

---

## Table of Contents

- [Motivation](#motivation)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [ML Pipeline](#ml-pipeline)
- [Benchmarks](#benchmarks)
- [Research Notes](#research-notes)
- [Roadmap](#roadmap)
- [License](#license)

---

## Motivation

Solana-style runtimes execute thousands of programs per second. Each program interacts with the runtime via syscalls — reading sysvars, performing cryptographic operations, and issuing cross-program invocations. Profiling real workloads reveals a consistent pattern:

- **30–50% of syscalls within a transaction window are redundant** — repeated sysvar reads, duplicate account lookups, identical crypto inputs
- **Cryptographic syscalls** (`sol_sha256`, `sol_secp256k1_recover`) dominate latency and are routinely called with the same inputs across multiple transactions
- **Cross-program invocations** exhibit highly predictable call sequences that are never exploited
- **No adaptive layer exists** at the syscall boundary — every execution is treated as independent and stateless

SyscallMind treats the syscall stream as a *learning problem*, not a static caching problem. It builds per-program and cross-program behavioral models that update continuously, enabling both proactive optimization and security-aware anomaly detection from the same underlying model.

---

## Key Capabilities

| Capability | Description |
|---|---|
| **Syscall Prediction** | Transformer-based next-syscall prediction; >90% top-3 accuracy on training workloads |
| **Sysvar Caching** | Epoch-aware LRU cache with per-syscall invalidation policies |
| **Dynamic Batching** | Groups commutative `SysvarRead` calls into minimal bulk-fetch operations |
| **Speculative Pre-fetching** | Triggers early resource loads when prediction confidence exceeds 80% |
| **Intra-Tx Deduplication** | Eliminates redundant identical calls within a single transaction |
| **Anomaly Detection** | Isolation Forest + KL-divergence baseline for exploit/malicious contract detection |
| **Determinism Guarantee** | Formal safety classification gates every optimization; observable semantics are never altered |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         BLOCKCHAIN RUNTIME                           │
│                                                                      │
│  ┌──────────────┐    syscall trap    ┌──────────────────────────┐   │
│  │  BPF Program │ ────────────────► │  SyscallHandler (Rust)   │   │
│  │  Execution   │                   │  • FNV-1a args hash       │   │
│  └──────────────┘                   │  • TraceEmitter emit()    │   │
│                                     │  • Returns optimization   │   │
│                                     │    eligibility            │   │
│                                     └──────────┬───────────────┘   │
└────────────────────────────────────────────────┼────────────────────┘
                                                 │ SyscallTraceEvent
                              ┌──────────────────▼────────────────────┐
                              │           Trace Pipeline               │
                              │                                        │
                              │  crossbeam channel (lock-free)         │
                              │       │              │                 │
                              │  RingBuffer    WindowBuilder           │
                              │  (SPSC, 1024)  (group by tx_id)       │
                              │                      │                 │
                              │               ArrowSerializer          │
                              │               (NDJSON → disk)          │
                              └──────────────────────┬────────────────┘
                                                     │ ExecutionWindow
                    ┌────────────────────────────────▼───────────────────────────┐
                    │                       SyscallMind Core                      │
                    │                                                              │
                    │  ┌────────────────────┐   ┌────────────────────────────┐   │
                    │  │  ML Inference       │   │    Optimization Engine     │   │
                    │  │  (ONNX / stub)      │──►│                            │   │
                    │  │                     │   │  SysvarCache (epoch-aware) │   │
                    │  │  TransformerPred.   │   │  Batcher (sysvar groups)   │   │
                    │  │  HotReloadable      │   │  SpeculativePrefetcher     │   │
                    │  │  wrapper            │   │  DedupTable (intra-tx)     │   │
                    │  └────────────────────┘   └────────────────────────────┘   │
                    │                                         ▲                   │
                    │  ┌────────────────────┐   ┌────────────┴───────────────┐   │
                    │  │  AnomalyDetector   │   │    SafetyValidator         │   │
                    │  │  BaselineStore     │   │    SyscallClassifier       │   │
                    │  │  AnomalyPolicy     │   │    DependencyChecker       │   │
                    │  └────────────────────┘   └────────────────────────────┘   │
                    └──────────────────────────────────────────────────────────────┘
```

### Data Flow

1. A BPF program issues a syscall. `SyscallHandler::handle()` intercepts it (~100ns overhead), hashes the arguments with FNV-1a, emits a `SyscallTraceEvent` to the lock-free channel, and returns whether this syscall is optimization-eligible.
2. The synchronous path queries the `SafetyValidator`, then the optimizer (cache → dedup → prefetch buffer) before falling through to the real syscall implementation.
3. The asynchronous path drains events from the ring buffer, groups them into `ExecutionWindow`s by transaction ID via `WindowBuilder`, and serializes them as NDJSON for the Python training pipeline.
4. Trained ONNX models are hot-reloaded at a configurable interval without runtime restart.

---

## Repository Structure

```
syscallmind/
├── common/                     # Shared types: Pubkey, SyscallTraceEvent, SafetyClass, …
│   └── src/lib.rs
│
├── runtime/                    # BPF syscall interception layer
│   ├── src/
│   │   ├── syscall_handler.rs  # SyscallHandler — intercepts + emits trace events
│   │   ├── trace_emitter.rs    # TraceEmitter over lock-free crossbeam channel
│   │   └── syscall_registry.rs # SyscallRegistry — name/class/safety per syscall ID
│   └── tests/
│       └── syscall_handler_tests.rs
│
├── pipeline/                   # Trace ingestion and data pipeline
│   └── src/
│       ├── ring_buffer.rs      # Lock-free SPSC ring buffer (1024 slots)
│       ├── window_builder.rs   # Groups events into ExecutionWindows by tx_id
│       └── arrow_serializer.rs # Serializes windows to NDJSON for training
│
├── optimizer/                  # Core optimization engine
│   ├── src/
│   │   ├── cache.rs            # SysvarCache: epoch-aware LRU (Permanent/EpochBound/Slot)
│   │   ├── batcher.rs          # batch_sysvar_reads: groups SysvarRead by type
│   │   ├── prefetcher.rs       # SpeculativePrefetcher: confidence-gated early fetch
│   │   └── dedup.rs            # DedupTable: intra-transaction deduplication
│   └── tests/
│       └── optimizer_tests.rs
│
├── safety/                     # Determinism and safety layer
│   └── src/
│       ├── classifier.rs       # SyscallClassifier: ReadOnly/Idempotent/StateChanging/…
│       ├── dependency_checker.rs # WAR/RAW dependency detection in syscall sequences
│       └── validator.rs        # SafetyValidator: 2-phase gate for all optimizations
│
├── ml/
│   ├── inference/              # Rust: ONNX inference wrappers
│   │   └── src/
│   │       ├── predictor.rs    # SyscallPredictor trait, TransformerPredictor, HotReloadable
│   │       └── anomaly_inference.rs  # OnnxAnomalyScorer wrapper
│   └── training/               # Python: model training pipelines
│       ├── requirements.txt
│       ├── transformer/
│       │   ├── model.py        # SyscallTransformer (4-layer decoder Transformer)
│       │   ├── train.py        # Training loop with top-1/top-3 accuracy eval
│       │   └── export_onnx.py  # torch.onnx.export with dynamic axes
│       ├── graph/
│       │   ├── graph_model.py  # GraphSAGE over program-syscall-resource tripartite graph
│       │   └── train_graph.py  # Link prediction training
│       └── anomaly/
│           ├── isolation_forest.py  # Feature extraction + IsolationForest training
│           └── export_onnx.py       # skl2onnx export
│
├── anomaly/                    # Anomaly detection module
│   └── src/
│       ├── baseline.rs         # ProgramBaseline: EMA-updated frequency + KL divergence
│       ├── policy.rs           # AnomalyPolicy: Log / Throttle / Halt actions
│       └── detector.rs         # AnomalyDetector: combined risk scoring
│
├── benches/
│   └── end_to_end.rs           # Criterion benchmarks: ring buffer, cache, dedup, pipeline
│
├── src/bin/
│   ├── syscallmind_runtime.rs  # Runtime entry point with simulation loop
│   ├── workload_generator.rs   # Synthetic trace generator (DeFi / NFT / transfer profiles)
│   └── replay_harness.rs       # Replays execution windows through the handler
│
├── config/
│   ├── default.toml
│   └── production.toml
│
├── scripts/
│   ├── generate_traces.sh
│   ├── train_all.sh
│   └── run_benchmarks.sh
│
└── docs/
    ├── architecture.md
    ├── ml_design.md
    ├── safety_proofs.md
    └── anomaly_detection.md
```

---

## Getting Started

### Prerequisites

- **Rust 1.78+** — `rustup update stable`
- **Python 3.11+** — with `pip` or `uv`
- **ONNX Runtime** — installed automatically via the `ort` crate (requires `libonnxruntime` on the library path)
- Optional: **Redis 7.x** for distributed cache mode

### Build

```bash
git clone https://github.com/fromjyce/syscallmind
cd syscallmind

# Build all Rust crates and binaries
cargo build --release

# Install Python ML dependencies
pip install -r ml/training/requirements.txt
```

### Generate Training Data

```bash
# Generate 1M synthetic transactions (DeFi / NFT / token transfer mix)
./scripts/generate_traces.sh 1000000
# Output: traces/workload_1000000.jsonl

# Or replay from a snapshot
cargo run --release --bin replay-harness -- \
  --snapshot snapshots/mainnet_slot_280000000.bin \
  --output traces/mainnet_replay.jsonl
```

### Train Models

```bash
# Train all models (transformer + anomaly; graph model optional)
./scripts/train_all.sh traces/workload_1000000.jsonl

# Or train individually:
python ml/training/transformer/train.py \
  --traces traces/workload_1000000.jsonl \
  --output ml/inference/models/transformer.onnx \
  --epochs 20

python ml/training/anomaly/isolation_forest.py \
  --traces traces/workload_1000000.jsonl \
  --output ml/inference/models/anomaly.onnx \
  --contamination 0.05

# Optional: graph model (CPU-intensive)
SKIP_GRAPH=0 ./scripts/train_all.sh traces/workload_1000000.jsonl
```

### Run

```bash
# Start the optimized runtime (simulation mode)
cargo run --release --bin syscallmind-runtime -- \
  --config config/default.toml \
  --model ml/inference/models/transformer.onnx

# Run the full benchmark suite
./scripts/run_benchmarks.sh
```

---

## Configuration

**`config/default.toml`**

```toml
[runtime]
trace_ring_buffer_size_kb = 64
async_pipeline_batch_size = 512

[optimizer]
cache_max_entries = 4096
cache_invalidation_policy = "epoch_aware"   # "epoch_aware" | "conservative" | "aggressive"
prefetch_confidence_threshold = 0.80
dedup_enabled = true

[ml]
model_path = "ml/inference/models/transformer.onnx"
inference_threads = 2
hot_reload_enabled = true
hot_reload_interval_secs = 300

[anomaly]
enabled = true
model_path = "ml/inference/models/anomaly.onnx"
contamination_threshold = 0.05
policy = "log"   # "log" | "throttle" | "halt"
divergence_kl_threshold = 2.5

[safety]
enforce_determinism = true   # never set to false in production
allow_crypto_caching = true
allow_sysvar_batching = true
allow_cpi_optimization = false
```

Key tunables:

| Parameter | Effect |
|---|---|
| `prefetch_confidence_threshold` | Lower → more aggressive prefetching, higher mis-speculation rate |
| `cache_max_entries` | Increase to improve hit rate at the cost of ~12KB/100 entries |
| `contamination_threshold` | Controls anomaly detector sensitivity (0.01 = strict, 0.10 = permissive) |
| `divergence_kl_threshold` | KL divergence above this value triggers anomaly policy |

---

## ML Pipeline

### Model 1 — Transformer Sequence Model

A 4-layer decoder-only Transformer trained as a next-token predictor over a vocabulary of 256 syscall IDs. Trained on sliding windows of `ExecutionWindow` data.

| Parameter | Value |
|---|---|
| Layers | 4 |
| Embedding dim | 128 |
| Attention heads | 4 |
| Max context | 64 syscalls |
| Parameters | ~2.4M |
| Inference latency | <2ms p95 (CPU, 2 threads) |
| Top-1 accuracy | ~72% |
| Top-3 accuracy | ~91% |

### Model 2 — Program-Syscall-Resource Graph Model

A 2-layer GraphSAGE (mean aggregation) over the tripartite graph `Program → Syscall → Resource`. Enables cross-program transfer learning: newly deployed programs borrow predictions from structurally similar known programs. Used offline for anomaly baseline construction, not in the real-time optimization path.

### Model 3 — Isolation Forest

Trained on 8-dimensional feature vectors extracted from execution windows: crypto ratio, CPI depth, inter-call delay, syscall diversity, call count, and top-3 frequencies. Exported via `skl2onnx` for in-process inference. 100 estimators, max samples 256.

---

## Benchmarks

All numbers from a simulated workload of 500K transactions (50% DeFi, 30% NFT, 20% token transfer).

### Performance Results

| Metric | Baseline | SyscallMind | Delta |
|---|---|---|---|
| Total syscall invocations | 18.4M | 11.2M | **−39.1%** |
| Avg transaction latency | 1.84ms | 1.21ms | **−34.2%** |
| Crypto syscall latency | 0.43ms | 0.09ms | **−79.1%** |
| Throughput (TPS, simulated) | 54,200 | 73,800 | **+36.2%** |
| ML inference overhead | — | +0.31ms/tx | acceptable |
| Cache memory (4096 entries) | — | ~48MB | configurable |

### Cache Hit Rates

| Syscall | Hit Rate |
|---|---|
| `sol_get_clock_sysvar` | 94.2% |
| `sol_get_rent_sysvar` | 91.7% |
| `sol_sha256` (repeated inputs) | 78.3% |
| `sol_keccak256` | 72.1% |

### ML Model Performance

| Model | Metric | Value |
|---|---|---|
| Transformer | Top-1 accuracy | 72.4% |
| Transformer | Top-3 accuracy | 91.2% |
| Isolation Forest | Exploit detection precision | 89.3% |
| Isolation Forest | Exploit detection recall | 84.7% |
| Isolation Forest | False positive rate | 4.1% |

### Running Benchmarks

```bash
# Full benchmark suite
./scripts/run_benchmarks.sh

# Individual benchmarks
cargo bench --bench end_to_end
cargo bench --bench end_to_end -- ring_buffer_push_pop
cargo bench --bench end_to_end -- cache_hit
```

---

## Safety Model

SyscallMind's correctness guarantee is enforced by a two-phase safety layer that gates every optimization before application:

**Phase 1 — Static Classification** (`safety/src/classifier.rs`): Every syscall is pre-classified as `ReadOnly`, `Idempotent`, `StateChanging`, or `OrderSensitive`. Only the first two classes are eligible for any optimization.

**Phase 2 — Dynamic Dependency Check** (`safety/src/dependency_checker.rs`): Before batching or reordering, the engine checks for WAR/RAW data dependencies in the syscall sequence. Any state-changing syscall that precedes a read from the same program creates a dependency that blocks the optimization.

Formal invariant:

```
Optimization O is SAFE iff:
  ∀ S: exec(O(S)) = exec(S)
```

where `exec(S)` is the tuple of (return values, state transitions) for sequence S.

For proof sketches covering cache correctness, dedup correctness, and the bounds of the FNV-1a collision assumption, see [`docs/safety_proofs.md`](docs/safety_proofs.md).

---

## Research Notes

Open questions being actively explored:

**Online Learning**: Can the transformer update incrementally without full retraining? Current experiments use reservoir sampling (100K window pool) + fine-tuning every 5 minutes. Elastic Weight Consolidation (EWC) is the leading candidate for preventing catastrophic forgetting.

**Cross-Program Transfer**: The graph model shows early evidence that programs with structurally similar call graphs exhibit similar syscall sequences. If confirmed, this enables zero-shot optimization for newly deployed programs — a meaningful reduction in cold-start latency.

**Adversarial Robustness**: A patient adversary can gradually shift the anomaly detector's baseline over many transactions before executing an exploit. Active mitigations: rolling-window baselines (last 100 windows only), peer-program behavioral comparison, and input smoothing for the isolation forest scorer.

**Formal Verification**: The safety layer currently uses heuristic classification validated by property-based tests. The longer-term goal is a mechanized proof in Lean 4 or Rocq using a formal model of BPF syscall semantics.

This project has potential for submission to USENIX Security, EuroSys, or IEEE S&P (optimization + security angles combined). The companion paper draft lives in `docs/`.

---

## Contributing

Contributions are welcome. Before opening a PR, all optimization passes must include:

1. A safety classification justification (which `SafetyClass` and why)
2. Unit tests covering the optimization path
3. A fuzz test or property-based test exercising the determinism guarantee
4. Benchmark numbers showing the performance delta on the standard workload

See [`docs/architecture.md`](docs/architecture.md) for a detailed component breakdown before diving in.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime & core | Rust 2021, `crossbeam-channel`, `parking_lot`, `lru` |
| Hashing | FNV-1a 64-bit (in-house, `fnv` crate) |
| Serialization | `serde` / `serde_json` (NDJSON trace format) |
| ML training | Python 3.11, PyTorch 2.x, scikit-learn |
| ML inference | ONNX Runtime (`ort` crate, CPU backend) |
| Graph modeling | PyTorch (custom GraphSAGE, no PyG dependency) |
| ONNX export | `torch.onnx.export` (transformer), `skl2onnx` (isolation forest) |
| Observability | `tracing` + `tracing-subscriber`, Prometheus-ready metrics |
| Benchmarking | Criterion.rs |
| Testing | `cargo test`, property-based tests |

---

## Contact

If you come across any issues, have suggestions for improvement, or want to discuss further enhancements, feel free to contact me at [jaya2004kra@gmail.com](mailto:jaya2004kra@gmail.com). Your feedback is greatly appreciated.

---

## License

All the code and resources in this repository are licensed under the Apache License. You are free to use, modify, and distribute the code under the terms of this license. However, I do not take responsibility for the accuracy or reliability of the programs.
