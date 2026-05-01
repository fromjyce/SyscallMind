use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id, CacheKey, SyscallTraceEvent};
use syscallmind_optimizer::{cache::CachedResult, DedupTable, SysvarCache};
use syscallmind_pipeline::{RingBuffer, WindowBuilder};

fn make_event(id: u32, slot: u64) -> SyscallTraceEvent {
    SyscallTraceEvent {
        program_id: zero_pubkey(),
        syscall_id: id,
        args_hash: id as u64 * 7919,
        timestamp_ns: slot * 400_000,
        slot,
        transaction_id: zero_tx_id(),
        depth: 0,
    }
}

fn bench_ring_buffer(c: &mut Criterion) {
    let rb = RingBuffer::new();
    let event = make_event(SOL_GET_CLOCK_SYSVAR, 1);

    c.bench_function("ring_buffer_push_pop", |b| {
        b.iter(|| {
            rb.push(event);
            rb.pop();
        });
    });
}

fn bench_cache_lookup(c: &mut Criterion) {
    let epoch = Arc::new(AtomicU64::new(1));
    let slot = Arc::new(AtomicU64::new(1));
    let mut cache = SysvarCache::new(4096, epoch, slot);

    // Pre-populate
    for i in 0..1000u64 {
        let key = CacheKey { syscall_id: SOL_SHA256, args_hash: i };
        cache.insert(key, CachedResult { data: vec![0u8; 32], epoch: 1, cached_at_slot: 1 });
    }

    let hit_key = CacheKey { syscall_id: SOL_SHA256, args_hash: 500 };
    let miss_key = CacheKey { syscall_id: SOL_SHA256, args_hash: 99999 };

    c.bench_function("cache_hit", |b| {
        b.iter(|| cache.get(&hit_key));
    });

    c.bench_function("cache_miss", |b| {
        b.iter(|| cache.get(&miss_key));
    });
}

fn bench_window_builder(c: &mut Criterion) {
    c.bench_function("window_builder_ingest_100", |b| {
        b.iter(|| {
            let mut wb = WindowBuilder::new(128);
            let tx = zero_tx_id();
            for i in 0..100u32 {
                wb.ingest(make_event(i % 24 + 1, 1));
            }
            wb.finalize(tx)
        });
    });
}

fn bench_dedup(c: &mut Criterion) {
    c.bench_function("dedup_check_hit", |b| {
        let mut table = DedupTable::new();
        let tx = zero_tx_id();
        table.record(tx, SOL_SHA256, 12345, vec![0xAB; 32]);
        b.iter(|| table.check(tx, SOL_SHA256, 12345));
    });
}

fn bench_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("pipeline");

    for n in [10, 50, 100, 500].iter() {
        group.bench_with_input(BenchmarkId::new("ring_buffer_bulk", n), n, |b, &n| {
            let rb = RingBuffer::new();
            b.iter(|| {
                for i in 0..n {
                    rb.push(make_event((i % 24) as u32 + 1, 1));
                }
                while rb.pop().is_some() {}
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_ring_buffer,
    bench_cache_lookup,
    bench_window_builder,
    bench_dedup,
    bench_pipeline,
);
criterion_main!(benches);
