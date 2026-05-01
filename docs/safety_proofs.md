# Safety Proofs — SyscallMind

## Formal Definition of Safe Optimization

An optimization applied to a syscall sequence `S` is **safe** if and only if:

1. The optimized execution produces identical state transitions as the unoptimized execution.
2. The optimized execution produces identical return values for every syscall.
3. No optimization is applied to state-mutating syscalls.
4. Reordering only occurs within groups of commutative, read-only syscalls.

Formally, let `exec(S)` denote the observable outputs of executing sequence `S` (return values + state changes). An optimization `O` is safe iff `exec(O(S)) = exec(S)` for all valid programs.

## Syscall Classification

### ReadOnly
A syscall `f` is `ReadOnly` if `f` reads shared state but makes no writes. Its output depends only on its inputs and the current state. Consecutive `ReadOnly` calls are commutative: `exec([f, g]) = exec([g, f])` when both are `ReadOnly` and operate on independent state.

Examples: `sol_get_clock_sysvar`, `sol_get_rent_sysvar`, `sol_get_return_data`.

### Idempotent
A syscall `f` is `Idempotent` if it is a pure function of its inputs: `f(x) = f(x)` always, regardless of order or context. May have observable side effects (e.g., logging) but those effects are identical on re-execution.

Examples: `sol_sha256`, `sol_log`. Safe for caching and deduplication, but **not** for reordering (reordering two `sol_log` calls would change the log output order, which is observable).

### StateChanging
A syscall `f` is `StateChanging` if its execution modifies program-visible state in a way that may affect the output of subsequent syscalls on the same program.

Examples: `sol_set_return_data`, `sol_panic`, `sol_abort`. **No optimization is ever applied to these.**

### OrderSensitive
A syscall `f` is `OrderSensitive` if its output depends on the sequence position relative to other calls, or if it may trigger side effects in external programs.

Examples: `sol_invoke_signed` (CPI). Currently excluded from all optimizations pending deeper analysis.

## Proof Sketch: Cache Correctness

**Claim**: The `SysvarCache` with `EpochBound` invalidation produces correct results for `ReadOnly` sysvar reads.

**Proof sketch**:
- A sysvar's value is constant within an epoch (by Solana protocol invariant).
- The cache stores `(syscall_id, args_hash) → (result, epoch)`.
- On lookup, if `stored_epoch != current_epoch`, the entry is rejected and a fresh syscall is issued.
- Therefore, a cache hit can only occur when `stored_epoch == current_epoch`, meaning the sysvar value has not changed since caching. The returned result is identical to a fresh execution. ∎

**Proof sketch for `Permanent` (crypto)**:
- Crypto syscalls are pure functions: `sha256(x) = sha256(x)` always.
- The cache key includes `args_hash = FNV1a(input_bytes)`. A collision would produce an incorrect result.
- FNV-1a 64-bit has 2^64 possible outputs. For the workload sizes considered (≤10^9 distinct inputs), the collision probability is negligible (birthday bound: ~5×10^{-10} per pair). ∎

## Proof Sketch: Dedup Correctness

**Claim**: Intra-transaction deduplication does not alter observable semantics for `Idempotent` and `ReadOnly` syscalls.

**Proof sketch**:
- The dedup table is scoped to a single transaction (`tx_id` is part of the key).
- For `ReadOnly` syscalls: the result of `f(args)` is fixed for the duration of the transaction (state does not change within a transaction for read-only operations). Therefore, re-executing `f(args)` with the same arguments returns the same value, and returning the cached value is equivalent.
- For `Idempotent` syscalls (e.g., `sol_sha256`): the output is a pure function of the inputs. Returning the cached result is trivially equivalent. ∎
- **Boundary condition**: dedup is **not** applied across transaction boundaries (`clear_transaction()` is called at transaction completion), preventing stale results from persisting.

## Future Work: Formal Verification

The current safety layer uses heuristic classification and correctness-by-argument. Longer-term goals:

1. **Separation logic formalization**: Model the runtime heap and account state as a separation logic resource. Prove that each optimization preserves the heap predicate. Target: Iris/Coq or RustBelt.
2. **Mechanized syscall semantics**: Encode a subset of the BPF syscall semantics in a formal model (e.g., using Lean 4 or Rocq) and prove the classification table is correct with respect to those semantics.
3. **Fuzz-based validation**: The `safety/fuzz/` harness generates random syscall sequences, applies random optimizations, and checks output equivalence against the reference implementation. This provides empirical confidence while the formal proof is in progress.
