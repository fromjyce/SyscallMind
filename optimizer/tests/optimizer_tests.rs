use std::sync::{atomic::AtomicU64, Arc};
use syscallmind_common::{syscall_ids::*, zero_tx_id, CacheKey};
use syscallmind_optimizer::{
    batch_sysvar_reads, DedupTable, PendingSyscall, SpeculativePrefetcher, SysvarCache,
};
use syscallmind_optimizer::cache::CachedResult;

fn make_cache() -> SysvarCache {
    let epoch = Arc::new(AtomicU64::new(1));
    let slot = Arc::new(AtomicU64::new(5));
    SysvarCache::new(256, epoch, slot)
}

#[test]
fn cache_hit_rate_accuracy() {
    let mut cache = make_cache();
    let key = CacheKey { syscall_id: SOL_SHA256, args_hash: 1234 };
    cache.insert(key, CachedResult { data: vec![0], epoch: 1, cached_at_slot: 5 });
    cache.get(&key); // hit
    cache.get(&CacheKey { syscall_id: SOL_SHA256, args_hash: 9999 }); // miss
    let rate = cache.hit_rate();
    assert!((rate - 0.5).abs() < 0.001);
}

#[test]
fn batcher_groups_by_syscall_id() {
    let pending = vec![
        PendingSyscall { syscall_id: 1, args_hash: 0, args: vec![], sequence_index: 0 },
        PendingSyscall { syscall_id: 1, args_hash: 1, args: vec![], sequence_index: 1 },
        PendingSyscall { syscall_id: 2, args_hash: 0, args: vec![], sequence_index: 2 },
    ];
    let batches = batch_sysvar_reads(&pending);
    assert_eq!(batches.len(), 2);
    let total_fetches: usize = batches.iter().map(|b| b.args_hashes.len()).sum();
    assert_eq!(total_fetches, 3);
}

#[test]
fn dedup_returns_cached_on_second_call() {
    let mut table = DedupTable::new();
    let tx = zero_tx_id();
    table.record(tx, SOL_SHA256, 100, vec![0xAB]);
    let result = table.check_and_count(tx, SOL_SHA256, 100);
    assert_eq!(result.unwrap(), vec![0xAB]);
    assert_eq!(table.dedup_count(), 1);
}

#[test]
fn prefetcher_only_prefetches_above_threshold() {
    let pf = SpeculativePrefetcher::new(0.8);
    // (syscall_id, predicted_args_hash, confidence)
    pf.trigger(vec![
        (SOL_GET_CLOCK_SYSVAR, 0x1111, 0.95),
        (SOL_GET_RENT_SYSVAR,  0x2222, 0.70),  // below threshold
        (SOL_SHA256,           0x3333, 0.85),
    ]);
    assert_eq!(pf.buffer_len(), 2);
}
