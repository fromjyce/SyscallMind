use std::collections::HashMap;
use syscallmind_common::{syscall_ids::*, SafetyClass, SyscallId};

pub struct SyscallClassifier {
    classifications: HashMap<SyscallId, SafetyClass>,
}

impl SyscallClassifier {
    pub fn new() -> Self {
        let mut m = HashMap::new();

        // Sysvar reads — ReadOnly (pure reads, no side effects)
        for id in [
            SOL_GET_CLOCK_SYSVAR,
            SOL_GET_RENT_SYSVAR,
            SOL_GET_EPOCH_SCHEDULE_SYSVAR,
            SOL_GET_FEES_SYSVAR,
            SOL_GET_SLOT_HASHES_SYSVAR,
            SOL_GET_STAKE_HISTORY_SYSVAR,
            SOL_GET_RETURN_DATA,
        ] {
            m.insert(id, SafetyClass::ReadOnly);
        }

        // Logging — Idempotent (observable but no state mutation)
        for id in [SOL_LOG, SOL_LOG_64, SOL_LOG_PUBKEY, SOL_LOG_COMPUTE_UNITS] {
            m.insert(id, SafetyClass::Idempotent);
        }

        // Cryptographic operations — Idempotent (deterministic, same input → same output)
        for id in [SOL_SHA256, SOL_KECCAK256, SOL_SECP256K1_RECOVER, SOL_ED25519_VERIFY] {
            m.insert(id, SafetyClass::Idempotent);
        }

        // Memory operations — Idempotent
        for id in [SOL_ALLOC_FREE, SOL_MEMCPY, SOL_MEMMOVE, SOL_MEMSET, SOL_MEMCMP] {
            m.insert(id, SafetyClass::Idempotent);
        }

        // State-mutating / control flow
        m.insert(SOL_SET_RETURN_DATA, SafetyClass::StateChanging);
        m.insert(SOL_PANIC, SafetyClass::StateChanging);
        m.insert(SOL_ABORT, SafetyClass::StateChanging);

        // Cross-program invocations — ordering-sensitive
        m.insert(SOL_INVOKE_SIGNED, SafetyClass::OrderSensitive);

        Self { classifications: m }
    }

    pub fn classify(&self, id: SyscallId) -> SafetyClass {
        self.classifications
            .get(&id)
            .copied()
            .unwrap_or(SafetyClass::StateChanging)
    }

    pub fn is_optimization_eligible(&self, id: SyscallId) -> bool {
        matches!(self.classify(id), SafetyClass::ReadOnly | SafetyClass::Idempotent)
    }

    /// Two syscalls can be reordered only if both are ReadOnly (truly commutative).
    pub fn can_reorder(a: SyscallId, b: SyscallId) -> bool {
        let c = Self::new();
        matches!(c.classify(a), SafetyClass::ReadOnly)
            && matches!(c.classify(b), SafetyClass::ReadOnly)
    }
}

impl Default for SyscallClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysvar_reads_are_readonly() {
        let c = SyscallClassifier::new();
        assert_eq!(c.classify(SOL_GET_CLOCK_SYSVAR), SafetyClass::ReadOnly);
        assert_eq!(c.classify(SOL_GET_RENT_SYSVAR), SafetyClass::ReadOnly);
    }

    #[test]
    fn crypto_is_idempotent() {
        let c = SyscallClassifier::new();
        assert_eq!(c.classify(SOL_SHA256), SafetyClass::Idempotent);
        assert!(c.is_optimization_eligible(SOL_SHA256));
    }

    #[test]
    fn panic_is_state_changing() {
        let c = SyscallClassifier::new();
        assert_eq!(c.classify(SOL_PANIC), SafetyClass::StateChanging);
        assert!(!c.is_optimization_eligible(SOL_PANIC));
    }

    #[test]
    fn invoke_signed_is_order_sensitive() {
        let c = SyscallClassifier::new();
        assert_eq!(c.classify(SOL_INVOKE_SIGNED), SafetyClass::OrderSensitive);
        assert!(!c.is_optimization_eligible(SOL_INVOKE_SIGNED));
    }

    #[test]
    fn unknown_id_is_state_changing() {
        let c = SyscallClassifier::new();
        assert_eq!(c.classify(9999), SafetyClass::StateChanging);
    }

    #[test]
    fn can_reorder_both_readonly() {
        assert!(SyscallClassifier::can_reorder(SOL_GET_CLOCK_SYSVAR, SOL_GET_RENT_SYSVAR));
    }

    #[test]
    fn cannot_reorder_if_one_is_idempotent() {
        assert!(!SyscallClassifier::can_reorder(SOL_GET_CLOCK_SYSVAR, SOL_SHA256));
    }
}
