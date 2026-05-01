use std::collections::HashMap;
use syscallmind_common::{ArgsHash, SyscallId, TransactionId};

pub struct DedupTable {
    table: HashMap<(TransactionId, SyscallId, ArgsHash), Vec<u8>>,
    dedup_count: u64,
}

impl DedupTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            dedup_count: 0,
        }
    }

    /// Returns a cached result if the exact same call was made in this transaction.
    pub fn check(
        &self,
        tx_id: TransactionId,
        syscall_id: SyscallId,
        args_hash: ArgsHash,
    ) -> Option<&Vec<u8>> {
        self.table.get(&(tx_id, syscall_id, args_hash))
    }

    /// Record a call result so future identical calls in the same transaction are deduped.
    pub fn record(
        &mut self,
        tx_id: TransactionId,
        syscall_id: SyscallId,
        args_hash: ArgsHash,
        result: Vec<u8>,
    ) {
        self.table.insert((tx_id, syscall_id, args_hash), result);
    }

    /// Check and auto-increment dedup counter if a hit is found.
    pub fn check_and_count(
        &mut self,
        tx_id: TransactionId,
        syscall_id: SyscallId,
        args_hash: ArgsHash,
    ) -> Option<Vec<u8>> {
        if let Some(cached) = self.table.get(&(tx_id, syscall_id, args_hash)) {
            self.dedup_count += 1;
            Some(cached.clone())
        } else {
            None
        }
    }

    /// Remove all entries for a completed transaction.
    pub fn clear_transaction(&mut self, tx_id: TransactionId) {
        self.table.retain(|(t, _, _), _| *t != tx_id);
    }

    pub fn dedup_count(&self) -> u64 {
        self.dedup_count
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl Default for DedupTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::zero_tx_id;

    #[test]
    fn miss_on_empty() {
        let table = DedupTable::new();
        assert!(table.check(zero_tx_id(), 1, 0).is_none());
    }

    #[test]
    fn hit_after_record() {
        let mut table = DedupTable::new();
        let tx = zero_tx_id();
        table.record(tx, 20, 12345, vec![0xDE, 0xAD]);
        assert_eq!(table.check(tx, 20, 12345).unwrap(), &vec![0xDE, 0xAD]);
    }

    #[test]
    fn dedup_count_increments() {
        let mut table = DedupTable::new();
        let tx = zero_tx_id();
        table.record(tx, 1, 0, vec![]);
        table.check_and_count(tx, 1, 0);
        table.check_and_count(tx, 1, 0);
        assert_eq!(table.dedup_count(), 2);
    }

    #[test]
    fn clear_transaction_removes_entries() {
        let mut table = DedupTable::new();
        let tx = zero_tx_id();
        let mut tx2 = zero_tx_id();
        tx2[0] = 1;
        table.record(tx, 1, 0, vec![]);
        table.record(tx2, 2, 0, vec![]);
        table.clear_transaction(tx);
        assert!(table.check(tx, 1, 0).is_none());
        assert!(table.check(tx2, 2, 0).is_some());
    }
}
