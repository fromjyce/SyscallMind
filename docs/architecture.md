# SyscallMind Architecture

## System Overview

SyscallMind is a middleware layer that sits between a BPF program execution environment and the underlying syscall implementations. It intercepts every syscall, emits structured trace events, and applies a set of learned optimizations — all while guaranteeing that observable program semantics are never altered.

### Data Flow

```
BPF Program
    │  syscall invocation
    ▼
SyscallHandler  ──emit──►  TraceEmitter  ──channel──►  RingBuffer
    │                                                        │
    │                                          ┌────────────┘
    │  optimization result                     │ WindowBuilder
    │◄──────────────────────────────────┐      │ (groups by tx)
    │                                   │      ▼
    │                             Optimizer    ArrowSerializer ──► Training pipeline
    │                             ┌──────┐     (async path)
    │                             │Cache │
    │                             │Dedup │
    │                             │Batch │
    │                             │Prefetch
    │                             └──────┘
    │                                ▲
    │                         SafetyValidator
    │                                ▲
    │                         TransformerPredictor
    │                         (ML inference)
    ▼
Actual syscall dispatch (if not served from cache/dedup)
```

## Component Descriptions

### 1. Runtime Layer (`runtime/`)

The entry point for all optimization. `SyscallHandler::handle()` is called for every syscall invocation and does three things:

- Computes an FNV-1a hash of the input arguments (used as a cache key)
- Emits a `SyscallTraceEvent` to the trace channel (lock-free, non-blocking)
- Returns whether the syscall is eligible for optimization

The `SyscallRegistry` maps syscall IDs to their name, class (`SysvarRead`, `Crypto`, etc.), and safety classification (`ReadOnly`, `Idempotent`, `StateChanging`, `OrderSensitive`).

### 2. Pipeline (`pipeline/`)

Three components process the trace stream:

**RingBuffer**: A lock-free SPSC ring buffer (1024 slots) used as the first hop for trace events. Push is O(1) with no allocation.

**WindowBuilder**: Groups individual trace events into `ExecutionWindow`s, keyed by `transaction_id`. A window is "finalized" when a transaction completes, producing the base unit for ML training.

**ArrowSerializer**: Writes execution windows as newline-delimited JSON (NDJSON) for the Python training pipeline. The format is structurally equivalent to Arrow IPC record batches, but uses JSON encoding for portability.

### 3. Optimizer (`optimizer/`)

Four independent optimization passes:

**SysvarCache**: An epoch-aware LRU cache keyed on `(syscall_id, args_hash)`. Crypto syscalls use `Permanent` invalidation (deterministic outputs). Sysvar reads use `EpochBound` (stale after epoch advance). Clock/slot-hashes use `Slot` (stale every slot).

**Batcher**: Groups concurrent `SysvarRead` syscalls (IDs 1–9) by type and deduplicates by args_hash before bulk-fetching.

**SpeculativePrefetcher**: When the ML predictor outputs confidence ≥ 0.8, triggers a background prefetch. On hit, the main thread reads from the buffer at zero latency.

**DedupTable**: Intra-transaction deduplication. Identical `(tx_id, syscall_id, args_hash)` tuples within a single transaction return the cached result without re-executing.

### 4. Safety Layer (`safety/`)

All optimizations must pass through the `SafetyValidator` before being applied. Validation is two-phase:

1. **Static classification** (`SyscallClassifier`): every syscall is pre-classified. Only `ReadOnly` and `Idempotent` syscalls are eligible for any optimization.
2. **Dynamic dependency check** (`DependencyChecker`): before reordering or batching, the engine checks whether any state-changing syscall creates a WAR/RAW dependency in the sequence.

### 5. ML Inference (`ml/inference/`)

**TransformerPredictor**: Implements the `SyscallPredictor` trait. In production, loads a compiled ONNX model via the `ort` crate. In the current stub, uses a hardcoded Markov transition table derived from profiled workloads.

**HotReloadablePredictor**: Wraps any predictor with periodic model reload. When `hot_reload_interval_secs` elapses, swaps the inner model without restarting the runtime.

**OnnxAnomalyScorer**: Wraps the ONNX-exported Isolation Forest for feature-vector scoring.

### 6. Anomaly Detection (`anomaly/`)

**BaselineStore**: Maintains per-program behavioral baselines updated via exponential moving average. Each baseline tracks syscall frequencies, mean inter-call delay, max CPI depth, and crypto ratio.

**AnomalyDetector**: Computes a combined risk score from KL divergence (distribution shift) and a feature-vector L2 norm (proxy for isolation forest score). Triggers policy actions when thresholds are exceeded.

**AnomalyPolicy**: Maps risk scores to actions (`Log`, `Throttle`, `Halt`).

## Key Design Decisions

**Lock-free trace emission**: Trace events must not add significant latency to the syscall hot path. The channel approach (bounded crossbeam channel as ring buffer interface) gives ~80–120ns overhead per syscall — acceptable for a ≥0.4ms transaction budget.

**Determinism first**: The safety layer is not an afterthought. Every optimization is classified and validated before application. `SafetyValidator::validate_cache()` etc. are called at optimization decision points, not as a post-hoc audit.

**Separate async training path**: The ML training pipeline runs asynchronously. Trace windows are serialized to disk (NDJSON) and consumed by the Python training code. This decouples model training from runtime latency and allows training on historical data.

**ONNX for cross-language inference**: Models are trained in Python (PyTorch, sklearn) and exported to ONNX. The Rust inference layer uses the `ort` crate to load and run them in-process, avoiding IPC overhead.
