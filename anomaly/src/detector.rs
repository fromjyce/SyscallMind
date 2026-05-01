use std::collections::HashMap;
use syscallmind_common::{Pubkey, SyscallId, SyscallTraceEvent};
use tracing::{info, warn};
use crate::{
    baseline::BaselineStore,
    policy::{AnomalyAction, AnomalyEvent, AnomalyPolicy},
};

pub struct AnomalyDetector {
    baseline_store: BaselineStore,
    policy: AnomalyPolicy,
    contamination_threshold: f64,
    events_log: Vec<AnomalyEvent>,
}

impl AnomalyDetector {
    pub fn new(policy: AnomalyPolicy, contamination_threshold: f64) -> Self {
        Self {
            baseline_store: BaselineStore::new(),
            policy,
            contamination_threshold,
            events_log: Vec::new(),
        }
    }

    /// Ingest a window of events to update the behavioral baseline.
    pub fn ingest_window(&mut self, program_id: Pubkey, events: &[SyscallTraceEvent]) {
        self.baseline_store.update_program(program_id, events);
    }

    /// Compute a risk score [0, 1] for a program given a fresh set of events.
    pub fn score_program(&self, program_id: &Pubkey, events: &[SyscallTraceEvent]) -> f64 {
        let Some(baseline) = self.baseline_store.get(program_id) else {
            // No baseline yet — score as low risk
            return 0.0;
        };

        // Compute observed frequency distribution
        let mut counts: HashMap<SyscallId, u64> = HashMap::new();
        let total = events.len() as f64;
        if total == 0.0 {
            return 0.0;
        }
        for e in events {
            *counts.entry(e.syscall_id).or_insert(0) += 1;
        }
        let observed_freqs: HashMap<SyscallId, f64> = counts
            .into_iter()
            .map(|(id, c)| (id, c as f64 / total))
            .collect();

        let kl_div = baseline.kl_divergence(&observed_freqs);

        // Isolation score: use L2 norm of feature vector as a proxy for outlierness
        let fv = baseline.feature_vector();
        let l2: f64 = fv.iter().map(|x| x * x).sum::<f64>().sqrt();
        let isolation_score = (l2 / 3.0).min(1.0); // normalize: typical l2 ≈ 1–3

        // Combined score
        let kl_component = (kl_div / 5.0).min(1.0); // normalize: KL > 5 is very anomalous
        let score = 0.6 * kl_component + 0.4 * isolation_score;
        score.min(1.0)
    }

    /// Check for anomaly and record event if detected.
    pub fn check_anomaly(
        &mut self,
        program_id: Pubkey,
        events: &[SyscallTraceEvent],
    ) -> Option<AnomalyEvent> {
        let Some(baseline) = self.baseline_store.get(&program_id) else {
            return None;
        };

        let mut counts: HashMap<SyscallId, u64> = HashMap::new();
        let total = events.len() as f64;
        if total == 0.0 {
            return None;
        }
        for e in events {
            *counts.entry(e.syscall_id).or_insert(0) += 1;
        }
        let observed_freqs: HashMap<SyscallId, f64> = counts
            .into_iter()
            .map(|(id, c)| (id, c as f64 / total))
            .collect();

        let kl_div = baseline.kl_divergence(&observed_freqs);
        let fv = baseline.feature_vector();
        let l2: f64 = fv.iter().map(|x| x * x).sum::<f64>().sqrt();
        let isolation_score = (l2 / 3.0).min(1.0);

        let result = self.policy.evaluate(program_id, kl_div, isolation_score);
        if let Some(ref ev) = result {
            warn!(
                risk_score = ev.risk_score,
                kl_divergence = ev.kl_divergence,
                action = ?ev.action_taken,
                "anomaly detected"
            );
            self.events_log.push(ev.clone());
        } else {
            info!("anomaly check passed");
        }
        result
    }

    pub fn event_log(&self) -> &[AnomalyEvent] {
        &self.events_log
    }

    pub fn default_policy() -> AnomalyPolicy {
        AnomalyPolicy::new(AnomalyAction::Log, 2.5, 0.7)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};

    fn make_events(ids: &[u32]) -> Vec<SyscallTraceEvent> {
        ids.iter().enumerate().map(|(i, &id)| SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id: id,
            args_hash: 0,
            timestamp_ns: i as u64 * 100,
            slot: 1,
            transaction_id: zero_tx_id(),
            depth: 0,
        }).collect()
    }

    #[test]
    fn no_anomaly_without_baseline() {
        let policy = AnomalyDetector::default_policy();
        let mut detector = AnomalyDetector::new(policy, 0.05);
        let events = make_events(&[SOL_SHA256, SOL_LOG]);
        let result = detector.check_anomaly(zero_pubkey(), &events);
        assert!(result.is_none());
    }

    #[test]
    fn score_zero_without_baseline() {
        let policy = AnomalyDetector::default_policy();
        let detector = AnomalyDetector::new(policy, 0.05);
        let score = detector.score_program(&zero_pubkey(), &make_events(&[1]));
        assert_eq!(score, 0.0);
    }

    #[test]
    fn ingest_window_builds_baseline() {
        let policy = AnomalyDetector::default_policy();
        let mut detector = AnomalyDetector::new(policy, 0.05);
        let events = make_events(&[1, 1, 20, 20, 2]);
        detector.ingest_window(zero_pubkey(), &events);
        assert!(detector.baseline_store.get(&zero_pubkey()).is_some());
    }
}
