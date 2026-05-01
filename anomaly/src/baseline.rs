use std::collections::HashMap;
use syscallmind_common::{syscall_ids::*, Pubkey, SyscallId, SyscallTraceEvent};

#[derive(Debug, Clone)]
pub struct ProgramBaseline {
    pub program_id: Pubkey,
    pub syscall_frequencies: HashMap<SyscallId, f64>,
    pub mean_inter_call_delay_ns: f64,
    pub max_cpi_depth: u8,
    pub crypto_ratio: f64,
    pub total_observations: u64,
}

const CRYPTO_IDS: &[SyscallId] = &[SOL_SHA256, SOL_KECCAK256, SOL_SECP256K1_RECOVER, SOL_ED25519_VERIFY];

impl ProgramBaseline {
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            syscall_frequencies: HashMap::new(),
            mean_inter_call_delay_ns: 0.0,
            max_cpi_depth: 0,
            crypto_ratio: 0.0,
            total_observations: 0,
        }
    }

    /// Update statistics from a batch of trace events.
    pub fn update(&mut self, events: &[SyscallTraceEvent]) {
        if events.is_empty() {
            return;
        }

        // Update call counts
        let mut counts: HashMap<SyscallId, u64> = HashMap::new();
        let mut total = 0u64;
        let mut crypto_count = 0u64;
        let mut max_depth: u8 = 0;

        for e in events {
            *counts.entry(e.syscall_id).or_insert(0) += 1;
            total += 1;
            if CRYPTO_IDS.contains(&e.syscall_id) {
                crypto_count += 1;
            }
            if e.depth > max_depth {
                max_depth = e.depth;
            }
        }

        // Blend new frequencies with existing (exponential moving average)
        let alpha = 0.1_f64; // learning rate
        for (&id, &count) in &counts {
            let new_freq = count as f64 / total as f64;
            let old_freq = self.syscall_frequencies.get(&id).copied().unwrap_or(0.0);
            self.syscall_frequencies.insert(id, (1.0 - alpha) * old_freq + alpha * new_freq);
        }

        // Compute inter-call delay
        if events.len() > 1 {
            let delays: Vec<f64> = events.windows(2)
                .map(|w| (w[1].timestamp_ns as i64 - w[0].timestamp_ns as i64).unsigned_abs() as f64)
                .collect();
            let mean_delay = delays.iter().sum::<f64>() / delays.len() as f64;
            let old_delay = self.mean_inter_call_delay_ns;
            self.mean_inter_call_delay_ns = (1.0 - alpha) * old_delay + alpha * mean_delay;
        }

        let new_crypto_ratio = if total > 0 { crypto_count as f64 / total as f64 } else { 0.0 };
        self.crypto_ratio = (1.0 - alpha) * self.crypto_ratio + alpha * new_crypto_ratio;

        if max_depth > self.max_cpi_depth {
            self.max_cpi_depth = max_depth;
        }

        self.total_observations += total;
    }

    /// KL divergence: D_KL(observed || baseline).
    pub fn kl_divergence(&self, observed_freqs: &HashMap<SyscallId, f64>) -> f64 {
        let epsilon = 1e-10;
        let mut kl = 0.0_f64;
        for (&id, &p) in observed_freqs {
            let q = self.syscall_frequencies.get(&id).copied().unwrap_or(epsilon);
            if p > 0.0 {
                kl += p * (p / q.max(epsilon)).ln();
            }
        }
        kl
    }

    /// Returns an 8-element feature vector for the anomaly detector.
    pub fn feature_vector(&self) -> Vec<f64> {
        let total = self.total_observations.max(1) as f64;
        let delay_norm = (self.mean_inter_call_delay_ns / 1_000_000.0).min(100.0); // ms, capped
        let depth_norm = self.max_cpi_depth as f64 / 10.0;
        let diversity = self.syscall_frequencies.len() as f64 / 30.0; // normalize by ~30 syscalls

        // Top-5 syscall frequencies by value
        let mut freqs: Vec<f64> = self.syscall_frequencies.values().copied().collect();
        freqs.sort_by(|a, b| b.partial_cmp(a).unwrap());
        freqs.resize(5, 0.0);

        vec![
            self.crypto_ratio,
            depth_norm,
            delay_norm,
            diversity,
            freqs[0],
            freqs[1],
            freqs[2],
            freqs[3],
        ]
    }
}

pub struct BaselineStore {
    baselines: HashMap<Pubkey, ProgramBaseline>,
}

impl BaselineStore {
    pub fn new() -> Self {
        Self { baselines: HashMap::new() }
    }

    pub fn update_program(&mut self, program_id: Pubkey, events: &[SyscallTraceEvent]) {
        self.baselines
            .entry(program_id)
            .or_insert_with(|| ProgramBaseline::new(program_id))
            .update(events);
    }

    pub fn get(&self, program_id: &Pubkey) -> Option<&ProgramBaseline> {
        self.baselines.get(program_id)
    }

    pub fn len(&self) -> usize {
        self.baselines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.baselines.is_empty()
    }
}

impl Default for BaselineStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{zero_pubkey, zero_tx_id};

    fn make_events(ids: &[u32]) -> Vec<SyscallTraceEvent> {
        ids.iter().enumerate().map(|(i, &id)| SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id: id,
            args_hash: 0,
            timestamp_ns: i as u64 * 1000,
            slot: 1,
            transaction_id: zero_tx_id(),
            depth: 0,
        }).collect()
    }

    #[test]
    fn update_sets_frequencies() {
        let mut baseline = ProgramBaseline::new(zero_pubkey());
        let events = make_events(&[1, 1, 20]);
        baseline.update(&events);
        assert!(baseline.total_observations > 0);
        assert!(baseline.syscall_frequencies.contains_key(&1));
        assert!(baseline.syscall_frequencies.contains_key(&20));
    }

    #[test]
    fn crypto_ratio_increases_with_crypto_calls() {
        let mut baseline = ProgramBaseline::new(zero_pubkey());
        let events = make_events(&[SOL_SHA256, SOL_SHA256, SOL_SHA256, SOL_LOG]);
        baseline.update(&events);
        assert!(baseline.crypto_ratio > 0.0);
    }

    #[test]
    fn kl_divergence_zero_for_same_distribution() {
        let mut baseline = ProgramBaseline::new(zero_pubkey());
        let events = make_events(&[1, 2, 1, 2]);
        baseline.update(&events);
        // Create identical observed distribution
        let observed = baseline.syscall_frequencies.clone();
        let kl = baseline.kl_divergence(&observed);
        assert!(kl < 0.01, "KL divergence should be near 0 for identical distributions");
    }

    #[test]
    fn feature_vector_has_correct_length() {
        let mut baseline = ProgramBaseline::new(zero_pubkey());
        baseline.update(&make_events(&[1, 20, 30]));
        assert_eq!(baseline.feature_vector().len(), 8);
    }
}
