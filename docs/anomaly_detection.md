# Anomaly Detection — SyscallMind

## Overview

SyscallMind's anomaly detection module reuses the same behavioral model built for runtime optimization to detect malicious or buggy smart contracts. A contract that has learned to evade static analysis may still exhibit unusual syscall patterns at runtime.

Two detection strategies run in parallel and are combined into a single risk score.

## Strategy A: Isolation Forest

The Isolation Forest is an ensemble of random decision trees that partition the feature space. Anomalous points are isolated more quickly (fewer splits) than normal ones, yielding lower "path length" scores.

### Feature Vector (8-dimensional)

| Feature | Rationale |
|---|---|
| Crypto ratio | Unusually high ratio may indicate hash grinding or brute-force key derivation |
| Max CPI depth | Deep CPI chains are a common reentrancy/exploit pattern |
| Mean inter-call delay | Anomalously short delays may indicate a tightly packed attack sequence |
| Syscall diversity | Very low diversity (same syscall repeated many times) is suspicious |
| Log total calls | Unusually large or small transaction sizes |
| Top-3 syscall frequencies | Captures dominant behavior patterns |

### Threshold Tuning

The `contamination` parameter (default: 0.05) sets the expected fraction of anomalies in training data. Lower values produce fewer false positives but may miss novel attack patterns.

Recommended tuning process:
1. Train on known-good mainnet traffic.
2. Inject a small set of known attack sequences (e.g., reentrancy, flash loan patterns).
3. Sweep contamination from 0.01 to 0.10 and plot precision-recall.
4. Select the threshold that minimizes false positive rate at ≥80% recall for known attacks.

## Strategy B: KL Divergence from Learned Baseline

Each program builds a per-program behavioral baseline using exponential moving average over historical execution windows. The baseline tracks:

- Syscall frequency histogram (normalized to sum to 1)
- Mean inter-call delay
- Max CPI depth
- Crypto ratio

For a new execution window, we compute the KL divergence between the observed syscall frequency distribution and the baseline:

```
D_KL(observed || baseline) = Σ p(x) * log(p(x) / q(x))
```

A high KL divergence (> `divergence_kl_threshold`, default 2.5) indicates the program is behaving significantly differently from its learned norm — a strong indicator of exploitation or a program bug.

### Smoothing

The baseline uses EMA with α = 0.1, meaning recent windows contribute 10% to the baseline. This makes the baseline adaptive to legitimate program upgrades while remaining sensitive to sudden behavioral changes.

### Cold Start

New programs have no baseline. For the first `min_observations` windows (default: 10), anomaly checking is skipped. This prevents false positives on first-time deployments.

## Combined Risk Score

The final risk score combines both signals:

```
risk = 0.6 * (kl_divergence / 5.0).clamp(0, 1) + 0.4 * isolation_score
```

The 0.6/0.4 split was empirically chosen: KL divergence is a stronger signal for behavior that deviates from a known baseline, while the isolation forest is better at catching novel patterns with no baseline.

## Policy Actions

| Action | When to use |
|---|---|
| `Log` | Development/testing. All anomalies are recorded with full detail. |
| `Throttle` | Production. Anomalous programs are rate-limited (e.g., 1 execution per block). |
| `Halt` | High-security deployments. Anomalous programs are rejected immediately. |

## Adversarial Robustness

An adversary aware of the detection system could craft a syscall sequence that:
1. Mimics the normal distribution (low KL divergence) while hiding malicious calls within the noise.
2. Gradually shifts the baseline (slow drift attack) over many transactions before launching the exploit.

Mitigations under exploration:
- **Rolling window baseline**: Use only the last 100 windows, limiting how much a patient adversary can shift the baseline.
- **Peer comparison**: Cross-program anomaly detection — if Program A suddenly starts invoking Program B (which it has never called), flag the interaction.
- **Gradient-based detection**: Detect adversarial perturbations designed to fool the classifier using input smoothing or certified defenses.

These are active research areas; the current implementation is not hardened against a sophisticated adversary.
