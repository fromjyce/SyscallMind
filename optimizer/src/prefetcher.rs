use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use parking_lot::RwLock;
use syscallmind_common::{syscall_ids::*, ArgsHash, SyscallId};
use tracing::debug;

/// Simulate the result of a prefetched syscall.
/// In production this would call the actual syscall implementation on a background thread.
fn simulate_fetch(syscall_id: SyscallId) -> Vec<u8> {
    match syscall_id {
        SOL_GET_CLOCK_SYSVAR | SOL_GET_RENT_SYSVAR | SOL_GET_EPOCH_SCHEDULE_SYSVAR => {
            vec![0u8; 64]  // sysvar structs are typically 32–64 bytes
        }
        SOL_SHA256 | SOL_KECCAK256 => vec![0u8; 32], // 256-bit hash output
        SOL_SECP256K1_RECOVER => vec![0u8; 64],       // recovered public key
        SOL_ED25519_VERIFY => vec![1u8],               // boolean result
        _ => vec![],
    }
}

#[derive(Debug, Clone)]
pub struct PrefetchEntry {
    pub syscall_id: SyscallId,
    pub args_hash: ArgsHash,
    pub result: Vec<u8>,
    pub is_ready: bool,
}

pub struct SpeculativePrefetcher {
    buffer: Arc<RwLock<HashMap<(SyscallId, ArgsHash), PrefetchEntry>>>,
    confidence_threshold: f32,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl SpeculativePrefetcher {
    pub fn new(confidence_threshold: f32) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(HashMap::new())),
            confidence_threshold,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Trigger speculative prefetches for high-confidence predictions.
    ///
    /// `predictions` carries `(syscall_id, predicted_args_hash, confidence)`.
    /// The args_hash is derived from the current transaction context by the caller
    /// (e.g., the most recent observed args_hash for that syscall_id in this program's history).
    /// Entries with confidence below the threshold are silently dropped.
    pub fn trigger(&self, predictions: Vec<(SyscallId, ArgsHash, f32)>) {
        for (syscall_id, args_hash, confidence) in predictions {
            if confidence < self.confidence_threshold {
                continue;
            }
            let key = (syscall_id, args_hash);

            if self.buffer.read().contains_key(&key) {
                continue; // already in-flight
            }

            // In a real implementation this would kick off an async sysvar read or
            // crypto pre-computation on a background thread, storing the result when
            // ready. Here we record a ready entry immediately as a stand-in.
            let result = simulate_fetch(syscall_id);
            let entry = PrefetchEntry {
                syscall_id,
                args_hash,
                result,
                is_ready: true,
            };
            debug!(syscall_id, args_hash, confidence, "speculative prefetch triggered");
            self.buffer.write().insert(key, entry);
        }
    }

    /// Consume a ready prefetch result, removing it from the buffer.
    pub fn consume(&self, syscall_id: SyscallId, args_hash: ArgsHash) -> Option<Vec<u8>> {
        let key = (syscall_id, args_hash);
        let entry = self.buffer.write().remove(&key)?;
        if entry.is_ready {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.result)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_above_threshold() {
        let pf = SpeculativePrefetcher::new(0.8);
        pf.trigger(vec![(1, 0xAABB, 0.9), (2, 0xCCDD, 0.5), (3, 0xEEFF, 0.85)]);
        // IDs 1 and 3 are above threshold; 2 is below
        assert_eq!(pf.buffer_len(), 2);
    }

    #[test]
    fn consume_hit() {
        let pf = SpeculativePrefetcher::new(0.5);
        pf.trigger(vec![(SOL_SHA256, 0xDEADBEEF, 0.9)]);
        let result = pf.consume(SOL_SHA256, 0xDEADBEEF);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 32); // SHA256 output is 32 bytes
        let (hits, _) = pf.stats();
        assert_eq!(hits, 1);
    }

    #[test]
    fn consume_miss_when_not_prefetched() {
        let pf = SpeculativePrefetcher::new(0.5);
        let result = pf.consume(99, 0);
        assert!(result.is_none());
    }

    #[test]
    fn all_below_threshold_nothing_prefetched() {
        let pf = SpeculativePrefetcher::new(0.99);
        pf.trigger(vec![(1, 0, 0.5), (2, 0, 0.7), (3, 0, 0.98)]);
        assert_eq!(pf.buffer_len(), 0);
    }

    #[test]
    fn duplicate_key_not_inserted_twice() {
        let pf = SpeculativePrefetcher::new(0.5);
        pf.trigger(vec![(SOL_GET_CLOCK_SYSVAR, 0xABC, 0.9)]);
        pf.trigger(vec![(SOL_GET_CLOCK_SYSVAR, 0xABC, 0.9)]);
        assert_eq!(pf.buffer_len(), 1);
    }
}
