use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use syscallmind_common::SyscallTraceEvent;
use tracing::warn;

const CHANNEL_CAPACITY: usize = 65_536;

pub struct TraceEmitter {
    sender: Sender<SyscallTraceEvent>,
    dropped: std::sync::atomic::AtomicU64,
}

impl TraceEmitter {
    pub fn new() -> (Self, Receiver<SyscallTraceEvent>) {
        let (sender, receiver) = bounded(CHANNEL_CAPACITY);
        (
            Self {
                sender,
                dropped: std::sync::atomic::AtomicU64::new(0),
            },
            receiver,
        )
    }

    /// Emit a trace event. Non-blocking; drops the event if the channel is full.
    pub fn emit(&self, event: SyscallTraceEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!(
                    syscall_id = event.syscall_id,
                    "trace channel full; dropping event"
                );
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for TraceEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceEmitter")
            .field("dropped", &self.dropped_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{zero_pubkey, zero_tx_id};

    fn make_event(id: u32) -> SyscallTraceEvent {
        SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id: id,
            args_hash: 0,
            timestamp_ns: 0,
            slot: 1,
            transaction_id: zero_tx_id(),
            depth: 0,
        }
    }

    #[test]
    fn emit_and_receive() {
        let (emitter, rx) = TraceEmitter::new();
        emitter.emit(make_event(1));
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.syscall_id, 1);
    }

    #[test]
    fn dropped_count_increments_when_full() {
        let (tx, _rx) = bounded::<SyscallTraceEvent>(2);
        // Fill it manually
        let _ = tx.try_send(make_event(1));
        let _ = tx.try_send(make_event(2));
        // Now construct an emitter over a saturated channel to test drop path
        let emitter = TraceEmitter { sender: tx, dropped: std::sync::atomic::AtomicU64::new(0) };
        emitter.emit(make_event(3));
        assert_eq!(emitter.dropped_count(), 1);
    }
}
