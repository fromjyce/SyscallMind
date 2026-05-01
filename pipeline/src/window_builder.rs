use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use syscallmind_common::{SyscallTraceEvent, TransactionId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionWindow {
    pub transaction_id: TransactionId,
    pub slot: u64,
    pub events: Vec<SyscallTraceEvent>,
    pub start_ts: u64,
    pub end_ts: u64,
}

impl ExecutionWindow {
    pub fn syscall_ids(&self) -> Vec<u32> {
        self.events.iter().map(|e| e.syscall_id).collect()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

pub struct WindowBuilder {
    pending: HashMap<TransactionId, Vec<SyscallTraceEvent>>,
    max_window_size: usize,
}

impl WindowBuilder {
    pub fn new(max_window_size: usize) -> Self {
        Self {
            pending: HashMap::new(),
            max_window_size,
        }
    }

    pub fn ingest(&mut self, event: SyscallTraceEvent) {
        let window = self.pending.entry(event.transaction_id).or_default();
        if window.len() < self.max_window_size {
            window.push(event);
        }
    }

    pub fn finalize(&mut self, tx_id: TransactionId) -> Option<ExecutionWindow> {
        let events = self.pending.remove(&tx_id)?;
        if events.is_empty() {
            return None;
        }
        let start_ts = events.first().map(|e| e.timestamp_ns).unwrap_or(0);
        let end_ts = events.last().map(|e| e.timestamp_ns).unwrap_or(0);
        let slot = events.first().map(|e| e.slot).unwrap_or(0);
        Some(ExecutionWindow {
            transaction_id: tx_id,
            slot,
            events,
            start_ts,
            end_ts,
        })
    }

    pub fn drain_all(&mut self) -> Vec<ExecutionWindow> {
        let keys: Vec<_> = self.pending.keys().cloned().collect();
        keys.into_iter().filter_map(|k| self.finalize(k)).collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{zero_pubkey, zero_tx_id};

    fn event(syscall_id: u32, tx: TransactionId) -> SyscallTraceEvent {
        SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id,
            args_hash: 0,
            timestamp_ns: syscall_id as u64 * 1000,
            slot: 1,
            transaction_id: tx,
            depth: 0,
        }
    }

    #[test]
    fn ingest_and_finalize() {
        let mut wb = WindowBuilder::new(64);
        let tx = zero_tx_id();
        wb.ingest(event(1, tx));
        wb.ingest(event(2, tx));
        let w = wb.finalize(tx).unwrap();
        assert_eq!(w.events.len(), 2);
        assert_eq!(w.syscall_ids(), vec![1, 2]);
    }

    #[test]
    fn finalize_unknown_tx_returns_none() {
        let mut wb = WindowBuilder::new(64);
        let mut tx = zero_tx_id();
        tx[0] = 99;
        assert!(wb.finalize(tx).is_none());
    }

    #[test]
    fn max_window_size_respected() {
        let mut wb = WindowBuilder::new(3);
        let tx = zero_tx_id();
        for i in 0..10u32 {
            wb.ingest(event(i, tx));
        }
        let w = wb.finalize(tx).unwrap();
        assert_eq!(w.events.len(), 3);
    }

    #[test]
    fn drain_all_clears_pending() {
        let mut wb = WindowBuilder::new(64);
        let tx1 = zero_tx_id();
        let mut tx2 = zero_tx_id();
        tx2[0] = 1;
        wb.ingest(event(1, tx1));
        wb.ingest(event(2, tx2));
        let windows = wb.drain_all();
        assert_eq!(windows.len(), 2);
        assert_eq!(wb.pending_count(), 0);
    }
}
