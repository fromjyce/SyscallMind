use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use syscallmind_common::Pubkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnomalyAction {
    Log,
    Throttle,
    Halt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvent {
    pub program_id: Pubkey,
    pub risk_score: f64,
    pub kl_divergence: f64,
    pub isolation_score: f64,
    pub timestamp_ns: u64,
    pub action_taken: AnomalyAction,
}

impl AnomalyEvent {
    pub fn is_high_risk(&self) -> bool {
        self.risk_score > 0.8
    }
}

pub struct AnomalyPolicy {
    pub action: AnomalyAction,
    pub kl_threshold: f64,
    pub isolation_threshold: f64,
}

impl AnomalyPolicy {
    pub fn new(action: AnomalyAction, kl_threshold: f64, isolation_threshold: f64) -> Self {
        Self { action, kl_threshold, isolation_threshold }
    }

    /// Returns Some(AnomalyEvent) if either score exceeds its threshold.
    pub fn evaluate(
        &self,
        program_id: Pubkey,
        kl_div: f64,
        isolation_score: f64,
    ) -> Option<AnomalyEvent> {
        let kl_triggered = kl_div > self.kl_threshold;
        let iso_triggered = isolation_score > self.isolation_threshold;

        if !kl_triggered && !iso_triggered {
            return None;
        }

        // Combined risk score: weighted average
        let risk_score = (kl_div / (self.kl_threshold + 1.0) * 0.5
            + isolation_score * 0.5)
            .min(1.0);

        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Some(AnomalyEvent {
            program_id,
            risk_score,
            kl_divergence: kl_div,
            isolation_score,
            timestamp_ns,
            action_taken: self.action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::zero_pubkey;

    #[test]
    fn no_event_below_thresholds() {
        let policy = AnomalyPolicy::new(AnomalyAction::Log, 2.5, 0.7);
        assert!(policy.evaluate(zero_pubkey(), 1.0, 0.3).is_none());
    }

    #[test]
    fn event_triggered_on_high_kl() {
        let policy = AnomalyPolicy::new(AnomalyAction::Log, 2.5, 0.7);
        let ev = policy.evaluate(zero_pubkey(), 5.0, 0.3);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().action_taken, AnomalyAction::Log);
    }

    #[test]
    fn event_triggered_on_high_isolation() {
        let policy = AnomalyPolicy::new(AnomalyAction::Throttle, 2.5, 0.7);
        let ev = policy.evaluate(zero_pubkey(), 0.5, 0.9);
        assert!(ev.is_some());
        assert_eq!(ev.unwrap().action_taken, AnomalyAction::Throttle);
    }

    #[test]
    fn risk_score_capped_at_one() {
        let policy = AnomalyPolicy::new(AnomalyAction::Halt, 1.0, 0.5);
        let ev = policy.evaluate(zero_pubkey(), 100.0, 1.0).unwrap();
        assert!(ev.risk_score <= 1.0);
    }
}
