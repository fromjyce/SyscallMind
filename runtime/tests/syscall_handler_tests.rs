use std::sync::{atomic::AtomicU64, Arc};
use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};
use syscallmind_runtime::{SyscallHandler, TraceEmitter};

fn make_handler() -> (SyscallHandler, crossbeam_channel::Receiver<syscallmind_common::SyscallTraceEvent>) {
    let (emitter, rx) = TraceEmitter::new();
    let slot = Arc::new(AtomicU64::new(42));
    (SyscallHandler::new(emitter, slot), rx)
}

#[test]
fn handle_records_slot_in_event() {
    let (handler, rx) = make_handler();
    handler.handle(zero_pubkey(), SOL_GET_CLOCK_SYSVAR, b"", zero_tx_id(), 0);
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.slot, 42);
}

#[test]
fn handle_computes_args_hash() {
    let (handler, rx) = make_handler();
    handler.handle(zero_pubkey(), SOL_SHA256, b"hello", zero_tx_id(), 0);
    let ev = rx.try_recv().unwrap();
    // Hash must be non-zero for non-empty input
    assert_ne!(ev.args_hash, 0);
}

#[test]
fn multiple_calls_produce_multiple_events() {
    let (handler, rx) = make_handler();
    handler.handle(zero_pubkey(), SOL_LOG, b"a", zero_tx_id(), 0);
    handler.handle(zero_pubkey(), SOL_LOG, b"b", zero_tx_id(), 0);
    handler.handle(zero_pubkey(), SOL_LOG, b"c", zero_tx_id(), 0);
    assert_eq!(handler.total_calls(), 3);
    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(count, 3);
}

#[test]
fn depth_is_recorded() {
    let (handler, rx) = make_handler();
    handler.handle(zero_pubkey(), SOL_INVOKE_SIGNED, b"", zero_tx_id(), 3);
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.depth, 3);
}
