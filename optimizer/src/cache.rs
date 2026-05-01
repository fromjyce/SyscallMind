use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use lru::LruCache;
use syscallmind_common::{syscall_ids::*, ArgsHash, CacheKey, SyscallId};

#[derive(Debug, Clone)]
pub struct CachedResult {
    pub data: Vec<u8>,
    pub epoch: u64,
    pub cached_at_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationPolicy {
    /// Invalidate when the epoch advances.
    EpochBound,
    /// Deterministic result — never auto-invalidate.
    Permanent,
    /// Invalidate on every new slot.
    Slot,
}

pub struct SysvarCache {
    inner: LruCache<(SyscallId, ArgsHash), CachedResult>,
    current_epoch: Arc<AtomicU64>,
    current_slot: Arc<AtomicU64>,
    invalidation_map: HashMap<SyscallId, InvalidationPolicy>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl SysvarCache {
    pub fn new(
        capacity: usize,
        epoch: Arc<AtomicU64>,
        slot: Arc<AtomicU64>,
    ) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        let mut invalidation_map = HashMap::new();
        invalidation_map.insert(SOL_GET_CLOCK_SYSVAR, InvalidationPolicy::EpochBound);
        invalidation_map.insert(SOL_GET_RENT_SYSVAR, InvalidationPolicy::EpochBound);
        invalidation_map.insert(SOL_GET_EPOCH_SCHEDULE_SYSVAR, InvalidationPolicy::EpochBound);
        invalidation_map.insert(SOL_GET_FEES_SYSVAR, InvalidationPolicy::EpochBound);
        invalidation_map.insert(SOL_GET_SLOT_HASHES_SYSVAR, InvalidationPolicy::Slot);
        invalidation_map.insert(SOL_SHA256, InvalidationPolicy::Permanent);
        invalidation_map.insert(SOL_KECCAK256, InvalidationPolicy::Permanent);
        invalidation_map.insert(SOL_SECP256K1_RECOVER, InvalidationPolicy::Permanent);
        invalidation_map.insert(SOL_ED25519_VERIFY, InvalidationPolicy::Permanent);

        Self {
            inner: LruCache::new(cap),
            current_epoch: epoch,
            current_slot: slot,
            invalidation_map,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn insert(&mut self, key: CacheKey, result: CachedResult) {
        self.inner.put((key.syscall_id, key.args_hash), result);
    }

    pub fn get(&mut self, key: &CacheKey) -> Option<&CachedResult> {
        let policy = self
            .invalidation_map
            .get(&key.syscall_id)
            .copied()
            .unwrap_or(InvalidationPolicy::EpochBound);

        let current_epoch = self.current_epoch.load(Ordering::Relaxed);
        let current_slot = self.current_slot.load(Ordering::Relaxed);

        if let Some(entry) = self.inner.peek(&(key.syscall_id, key.args_hash)) {
            let valid = match policy {
                InvalidationPolicy::Permanent => true,
                InvalidationPolicy::EpochBound => entry.epoch == current_epoch,
                InvalidationPolicy::Slot => entry.cached_at_slot == current_slot,
            };
            if valid {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return self.inner.get(&(key.syscall_id, key.args_hash));
            } else {
                self.inner.pop(&(key.syscall_id, key.args_hash));
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn invalidate_slot(&mut self) {
        let current_slot = self.current_slot.load(Ordering::Relaxed);
        let to_remove: Vec<_> = self
            .inner
            .iter()
            .filter(|(&(id, _), entry)| {
                self.invalidation_map.get(&id).copied() == Some(InvalidationPolicy::Slot)
                    && entry.cached_at_slot != current_slot
            })
            .map(|(k, _)| *k)
            .collect();
        for k in to_remove {
            self.inner.pop(&k);
        }
    }

    pub fn invalidate_epoch(&mut self) {
        let current_epoch = self.current_epoch.load(Ordering::Relaxed);
        let to_remove: Vec<_> = self
            .inner
            .iter()
            .filter(|(&(id, _), entry)| {
                self.invalidation_map.get(&id).copied() == Some(InvalidationPolicy::EpochBound)
                    && entry.epoch != current_epoch
            })
            .map(|(k, _)| *k)
            .collect();
        for k in to_remove {
            self.inner.pop(&k);
        }
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    fn make_cache() -> SysvarCache {
        let epoch = Arc::new(AtomicU64::new(1));
        let slot = Arc::new(AtomicU64::new(10));
        SysvarCache::new(128, epoch, slot)
    }

    #[test]
    fn basic_hit_miss() {
        let mut cache = make_cache();
        let key = CacheKey { syscall_id: SOL_SHA256, args_hash: 42 };
        assert!(cache.get(&key).is_none());
        cache.insert(key, CachedResult { data: vec![1, 2], epoch: 1, cached_at_slot: 10 });
        assert!(cache.get(&key).is_some());
        let (hits, misses) = cache.stats();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn epoch_invalidation() {
        let epoch = Arc::new(AtomicU64::new(1));
        let slot = Arc::new(AtomicU64::new(10));
        let mut cache = SysvarCache::new(128, epoch.clone(), slot.clone());
        let key = CacheKey { syscall_id: SOL_GET_CLOCK_SYSVAR, args_hash: 1 };
        cache.insert(key, CachedResult { data: vec![0], epoch: 1, cached_at_slot: 10 });
        assert!(cache.get(&key).is_some());
        epoch.store(2, Ordering::Relaxed);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn permanent_entry_survives_epoch_change() {
        let epoch = Arc::new(AtomicU64::new(1));
        let slot = Arc::new(AtomicU64::new(10));
        let mut cache = SysvarCache::new(128, epoch.clone(), slot.clone());
        let key = CacheKey { syscall_id: SOL_SHA256, args_hash: 99 };
        cache.insert(key, CachedResult { data: vec![0xAB], epoch: 1, cached_at_slot: 10 });
        epoch.store(5, Ordering::Relaxed);
        assert!(cache.get(&key).is_some());
    }
}
