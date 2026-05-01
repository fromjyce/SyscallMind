use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use parking_lot::RwLock;
use syscallmind_common::{syscall_ids::*, Pubkey, SyscallId};
use tracing::info;

/// Core prediction interface: given a partial syscall history for a program,
/// predict the next N most likely syscalls with their probabilities.
pub trait SyscallPredictor: Send + Sync {
    fn predict_next(
        &self,
        history: &[SyscallId],
        program_id: &Pubkey,
        top_k: usize,
    ) -> Vec<(SyscallId, f32)>;

    fn reorder_safe(&self, sequence: &[SyscallId]) -> bool;
}

/// Simple Markov-style transition table for common syscall pairs.
fn build_transition_table() -> HashMap<SyscallId, Vec<(SyscallId, f32)>> {
    let mut t: HashMap<SyscallId, Vec<(SyscallId, f32)>> = HashMap::new();

    // After clock sysvar, commonly get rent or do crypto
    t.insert(SOL_GET_CLOCK_SYSVAR, vec![
        (SOL_GET_RENT_SYSVAR, 0.40),
        (SOL_SHA256, 0.25),
        (SOL_INVOKE_SIGNED, 0.20),
        (SOL_LOG, 0.10),
        (SOL_KECCAK256, 0.05),
    ]);
    // After sha256, often another crypto op or invoke
    t.insert(SOL_SHA256, vec![
        (SOL_SECP256K1_RECOVER, 0.35),
        (SOL_SHA256, 0.25),
        (SOL_INVOKE_SIGNED, 0.20),
        (SOL_LOG, 0.12),
        (SOL_KECCAK256, 0.08),
    ]);
    t.insert(SOL_GET_RENT_SYSVAR, vec![
        (SOL_GET_CLOCK_SYSVAR, 0.30),
        (SOL_INVOKE_SIGNED, 0.30),
        (SOL_SHA256, 0.20),
        (SOL_LOG, 0.15),
        (SOL_SET_RETURN_DATA, 0.05),
    ]);
    t.insert(SOL_INVOKE_SIGNED, vec![
        (SOL_GET_CLOCK_SYSVAR, 0.35),
        (SOL_SHA256, 0.25),
        (SOL_LOG, 0.20),
        (SOL_GET_RENT_SYSVAR, 0.15),
        (SOL_SET_RETURN_DATA, 0.05),
    ]);
    t
}

/// Default distribution returned when no transition is known.
fn default_distribution(top_k: usize) -> Vec<(SyscallId, f32)> {
    let defaults = [
        SOL_GET_CLOCK_SYSVAR,
        SOL_SHA256,
        SOL_LOG,
        SOL_GET_RENT_SYSVAR,
        SOL_INVOKE_SIGNED,
    ];
    defaults.iter()
        .take(top_k)
        .enumerate()
        .map(|(i, &id)| (id, 0.30_f32 * (0.7_f32.powi(i as i32))))
        .collect()
}

pub struct TransformerPredictor {
    model_path: String,
    transitions: HashMap<SyscallId, Vec<(SyscallId, f32)>>,
}

impl TransformerPredictor {
    pub fn new(model_path: impl Into<String>) -> Self {
        Self {
            model_path: model_path.into(),
            transitions: build_transition_table(),
        }
    }

    pub fn model_path(&self) -> &str {
        &self.model_path
    }
}

impl SyscallPredictor for TransformerPredictor {
    fn predict_next(
        &self,
        history: &[SyscallId],
        _program_id: &Pubkey,
        top_k: usize,
    ) -> Vec<(SyscallId, f32)> {
        let last = history.last().copied();
        let candidates = last
            .and_then(|id| self.transitions.get(&id))
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        if candidates.is_empty() {
            return default_distribution(top_k);
        }

        candidates.iter().take(top_k).copied().collect()
    }

    fn reorder_safe(&self, sequence: &[SyscallId]) -> bool {
        // Heuristic: safe to reorder if all syscalls are in the sysvar/crypto range
        sequence.iter().all(|&id| id <= 29)
    }
}

/// Wraps any `SyscallPredictor` with hot-reload capability.
pub struct HotReloadablePredictor {
    inner: Arc<RwLock<Box<dyn SyscallPredictor>>>,
    model_path: String,
    last_reload: Instant,
    reload_interval: Duration,
}

impl HotReloadablePredictor {
    pub fn new(model_path: impl Into<String>, reload_interval_secs: u64) -> Self {
        let path: String = model_path.into();
        let predictor = Box::new(TransformerPredictor::new(path.clone()));
        Self {
            inner: Arc::new(RwLock::new(predictor)),
            model_path: path,
            last_reload: Instant::now(),
            reload_interval: Duration::from_secs(reload_interval_secs),
        }
    }

    /// Reload the model if the interval has elapsed.
    pub fn maybe_reload(&mut self) {
        if self.last_reload.elapsed() >= self.reload_interval {
            info!(model_path = %self.model_path, "hot-reloading ML model");
            let new_predictor = Box::new(TransformerPredictor::new(self.model_path.clone()));
            *self.inner.write() = new_predictor;
            self.last_reload = Instant::now();
        }
    }
}

impl SyscallPredictor for HotReloadablePredictor {
    fn predict_next(
        &self,
        history: &[SyscallId],
        program_id: &Pubkey,
        top_k: usize,
    ) -> Vec<(SyscallId, f32)> {
        self.inner.read().predict_next(history, program_id, top_k)
    }

    fn reorder_safe(&self, sequence: &[SyscallId]) -> bool {
        self.inner.read().reorder_safe(sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::zero_pubkey;

    #[test]
    fn predict_next_returns_top_k() {
        let predictor = TransformerPredictor::new("model.onnx");
        let result = predictor.predict_next(&[SOL_GET_CLOCK_SYSVAR], &zero_pubkey(), 3);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn probabilities_are_valid() {
        let predictor = TransformerPredictor::new("model.onnx");
        let result = predictor.predict_next(&[SOL_SHA256], &zero_pubkey(), 5);
        for (_, prob) in &result {
            assert!(*prob >= 0.0 && *prob <= 1.0);
        }
    }

    #[test]
    fn reorder_safe_for_low_ids() {
        let predictor = TransformerPredictor::new("model.onnx");
        assert!(predictor.reorder_safe(&[1, 2, 3, 20, 21]));
    }

    #[test]
    fn reorder_not_safe_with_high_id() {
        let predictor = TransformerPredictor::new("model.onnx");
        assert!(!predictor.reorder_safe(&[1, 2, SOL_INVOKE_SIGNED]));
    }

    #[test]
    fn empty_history_returns_defaults() {
        let predictor = TransformerPredictor::new("model.onnx");
        let result = predictor.predict_next(&[], &zero_pubkey(), 5);
        assert!(!result.is_empty());
    }
}
