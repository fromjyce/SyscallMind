use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use syscallmind_common::{fnv_hash, Pubkey, SyscallId, SyscallTraceEvent, TransactionId};
use tracing::trace;

use crate::{syscall_registry::SyscallRegistry, trace_emitter::TraceEmitter};

pub struct SyscallHandler {
    registry: Arc<SyscallRegistry>,
    emitter: TraceEmitter,
    current_slot: Arc<AtomicU64>,
    call_counts: Arc<Mutex<HashMap<SyscallId, u64>>>,
    total_calls: AtomicU64,
}

impl SyscallHandler {
    pub fn new(emitter: TraceEmitter, slot: Arc<AtomicU64>) -> Self {
        Self {
            registry: Arc::new(SyscallRegistry::new()),
            emitter,
            current_slot: slot,
            call_counts: Arc::new(Mutex::new(HashMap::new())),
            total_calls: AtomicU64::new(0),
        }
    }

    /// Intercept a syscall invocation, emit a trace event, and return whether
    /// the syscall is eligible for optimization.
    pub fn handle(
        &self,
        program_id: Pubkey,
        syscall_id: SyscallId,
        args: &[u8],
        tx_id: TransactionId,
        depth: u8,
    ) -> bool {
        let args_hash = fnv_hash(args);
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let slot = self.current_slot.load(Ordering::Relaxed);

        let event = SyscallTraceEvent {
            program_id,
            syscall_id,
            args_hash,
            timestamp_ns,
            slot,
            transaction_id: tx_id,
            depth,
        };

        self.emitter.emit(event);
        self.total_calls.fetch_add(1, Ordering::Relaxed);

        {
            let mut counts = self.call_counts.lock().unwrap();
            *counts.entry(syscall_id).or_insert(0) += 1;
        }

        let name = self.registry.get_name(syscall_id);
        let eligible = self.registry.is_optimization_eligible(syscall_id);
        trace!(syscall_id, name, eligible, "syscall intercepted");

        eligible
    }

    pub fn stats(&self) -> HashMap<SyscallId, u64> {
        self.call_counts.lock().unwrap().clone()
    }

    pub fn total_calls(&self) -> u64 {
        self.total_calls.load(Ordering::Relaxed)
    }

    pub fn registry(&self) -> &SyscallRegistry {
        &self.registry
    }

    pub fn advance_slot(&self) {
        self.current_slot.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};

    fn make_handler() -> (SyscallHandler, crossbeam_channel::Receiver<SyscallTraceEvent>) {
        let (emitter, rx) = TraceEmitter::new();
        let slot = Arc::new(AtomicU64::new(1));
        (SyscallHandler::new(emitter, slot), rx)
    }

    #[test]
    fn handle_emits_trace_event() {
        let (handler, rx) = make_handler();
        handler.handle(zero_pubkey(), SOL_GET_CLOCK_SYSVAR, b"", zero_tx_id(), 0);
        let ev = rx.try_recv().expect("should have event");
        assert_eq!(ev.syscall_id, SOL_GET_CLOCK_SYSVAR);
        assert_eq!(ev.slot, 1);
    }

    #[test]
    fn stats_increments_per_syscall() {
        let (handler, _rx) = make_handler();
        handler.handle(zero_pubkey(), SOL_SHA256, b"data", zero_tx_id(), 0);
        handler.handle(zero_pubkey(), SOL_SHA256, b"data2", zero_tx_id(), 0);
        handler.handle(zero_pubkey(), SOL_KECCAK256, b"x", zero_tx_id(), 0);
        let stats = handler.stats();
        assert_eq!(stats[&SOL_SHA256], 2);
        assert_eq!(stats[&SOL_KECCAK256], 1);
    }

    #[test]
    fn total_calls_accumulates() {
        let (handler, _rx) = make_handler();
        for _ in 0..5 {
            handler.handle(zero_pubkey(), SOL_LOG, b"msg", zero_tx_id(), 0);
        }
        assert_eq!(handler.total_calls(), 5);
    }

    #[test]
    fn state_changing_syscall_not_eligible() {
        let (handler, _rx) = make_handler();
        let eligible = handler.handle(zero_pubkey(), SOL_PANIC, b"", zero_tx_id(), 0);
        assert!(!eligible);
    }

    #[test]
    fn readonly_syscall_is_eligible() {
        let (handler, _rx) = make_handler();
        let eligible = handler.handle(zero_pubkey(), SOL_GET_CLOCK_SYSVAR, b"", zero_tx_id(), 0);
        assert!(eligible);
    }
}
