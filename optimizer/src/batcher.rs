use std::collections::HashMap;
use syscallmind_common::{ArgsHash, SyscallId};

#[derive(Debug, Clone)]
pub struct PendingSyscall {
    pub syscall_id: SyscallId,
    pub args_hash: ArgsHash,
    pub args: Vec<u8>,
    pub sequence_index: usize,
}

#[derive(Debug, Clone)]
pub struct BatchedFetch {
    pub syscall_ids: Vec<SyscallId>,
    pub args_hashes: Vec<ArgsHash>,
}

/// Returns true if the syscall ID is a sysvar read that can be batched
/// (IDs 1–9 are sysvar reads per the registry).
pub fn can_batch(syscall_id: SyscallId) -> bool {
    (1..=9).contains(&syscall_id)
}

/// Groups batchable syscalls by type, deduplicating by args_hash within each group.
pub fn batch_sysvar_reads(pending: &[PendingSyscall]) -> Vec<BatchedFetch> {
    // Group by syscall_id; use LinkedHashMap ordering via HashMap + sorted keys for determinism
    let mut groups: HashMap<SyscallId, Vec<ArgsHash>> = HashMap::new();

    for p in pending {
        if !can_batch(p.syscall_id) {
            continue;
        }
        let hashes = groups.entry(p.syscall_id).or_default();
        if !hashes.contains(&p.args_hash) {
            hashes.push(p.args_hash);
        }
    }

    let mut result = Vec::new();
    let mut sorted_ids: Vec<_> = groups.keys().copied().collect();
    sorted_ids.sort_unstable();

    for id in sorted_ids {
        let hashes = groups.remove(&id).unwrap();
        result.push(BatchedFetch {
            syscall_ids: vec![id; hashes.len()],
            args_hashes: hashes,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(id: u32, hash: u64) -> PendingSyscall {
        PendingSyscall { syscall_id: id, args_hash: hash, args: vec![], sequence_index: 0 }
    }

    #[test]
    fn batches_sysvar_reads() {
        let pending = vec![p(1, 100), p(1, 200), p(2, 300)];
        let batches = batch_sysvar_reads(&pending);
        assert_eq!(batches.len(), 2); // group per syscall_id
    }

    #[test]
    fn deduplicates_identical_hashes() {
        let pending = vec![p(1, 100), p(1, 100), p(1, 100)];
        let batches = batch_sysvar_reads(&pending);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].args_hashes.len(), 1);
    }

    #[test]
    fn non_batchable_syscalls_excluded() {
        let pending = vec![p(20, 0), p(30, 0), p(60, 0)]; // crypto, cpi, abort
        let batches = batch_sysvar_reads(&pending);
        assert!(batches.is_empty());
    }

    #[test]
    fn can_batch_boundaries() {
        assert!(can_batch(1));
        assert!(can_batch(9));
        assert!(!can_batch(10));
        assert!(!can_batch(0));
    }
}
