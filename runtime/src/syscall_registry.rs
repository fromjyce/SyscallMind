use std::collections::HashMap;
use syscallmind_common::{syscall_ids::*, SafetyClass, SyscallClass, SyscallId};

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub name: &'static str,
    pub class: SyscallClass,
    pub safety: SafetyClass,
}

pub struct SyscallRegistry {
    entries: HashMap<SyscallId, SyscallInfo>,
}

impl SyscallRegistry {
    pub fn new() -> Self {
        let mut entries = HashMap::new();

        let register = |entries: &mut HashMap<SyscallId, SyscallInfo>,
                        id: SyscallId,
                        name: &'static str,
                        class: SyscallClass,
                        safety: SafetyClass| {
            entries.insert(id, SyscallInfo { name, class, safety });
        };

        register(&mut entries, SOL_GET_CLOCK_SYSVAR, "sol_get_clock_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_GET_RENT_SYSVAR, "sol_get_rent_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_GET_EPOCH_SCHEDULE_SYSVAR, "sol_get_epoch_schedule_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_GET_FEES_SYSVAR, "sol_get_fees_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_GET_SLOT_HASHES_SYSVAR, "sol_get_slot_hashes_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_GET_STAKE_HISTORY_SYSVAR, "sol_get_stake_history_sysvar", SyscallClass::SysvarRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_LOG, "sol_log", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_LOG_64, "sol_log_64", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_LOG_PUBKEY, "sol_log_pubkey", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_LOG_COMPUTE_UNITS, "sol_log_compute_units", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_SHA256, "sol_sha256", SyscallClass::Crypto, SafetyClass::Idempotent);
        register(&mut entries, SOL_KECCAK256, "sol_keccak256", SyscallClass::Crypto, SafetyClass::Idempotent);
        register(&mut entries, SOL_SECP256K1_RECOVER, "sol_secp256k1_recover", SyscallClass::Crypto, SafetyClass::Idempotent);
        register(&mut entries, SOL_ED25519_VERIFY, "sol_ed25519_verify", SyscallClass::Crypto, SafetyClass::Idempotent);
        register(&mut entries, SOL_INVOKE_SIGNED, "sol_invoke_signed", SyscallClass::CPI, SafetyClass::OrderSensitive);
        register(&mut entries, SOL_SET_RETURN_DATA, "sol_set_return_data", SyscallClass::StateChange, SafetyClass::StateChanging);
        register(&mut entries, SOL_GET_RETURN_DATA, "sol_get_return_data", SyscallClass::AccountRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_ALLOC_FREE, "sol_alloc_free", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_MEMCPY, "sol_memcpy", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_MEMMOVE, "sol_memmove", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_MEMSET, "sol_memset", SyscallClass::AccountRead, SafetyClass::Idempotent);
        register(&mut entries, SOL_MEMCMP, "sol_memcmp", SyscallClass::AccountRead, SafetyClass::ReadOnly);
        register(&mut entries, SOL_PANIC, "sol_panic", SyscallClass::Abort, SafetyClass::StateChanging);
        register(&mut entries, SOL_ABORT, "sol_abort", SyscallClass::Abort, SafetyClass::StateChanging);

        Self { entries }
    }

    pub fn get(&self, id: SyscallId) -> Option<&SyscallInfo> {
        self.entries.get(&id)
    }

    pub fn get_class(&self, id: SyscallId) -> SyscallClass {
        self.entries.get(&id).map(|i| i.class).unwrap_or(SyscallClass::Unknown)
    }

    pub fn get_safety(&self, id: SyscallId) -> SafetyClass {
        self.entries.get(&id).map(|i| i.safety).unwrap_or(SafetyClass::StateChanging)
    }

    pub fn get_name(&self, id: SyscallId) -> &str {
        self.entries.get(&id).map(|i| i.name).unwrap_or("unknown")
    }

    pub fn is_optimization_eligible(&self, id: SyscallId) -> bool {
        matches!(self.get_safety(id), SafetyClass::ReadOnly | SafetyClass::Idempotent)
    }

    pub fn all_ids(&self) -> Vec<SyscallId> {
        self.entries.keys().copied().collect()
    }
}

impl Default for SyscallRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_sysvar_is_readonly() {
        let reg = SyscallRegistry::new();
        assert_eq!(reg.get_safety(SOL_GET_CLOCK_SYSVAR), SafetyClass::ReadOnly);
        assert_eq!(reg.get_class(SOL_GET_CLOCK_SYSVAR), SyscallClass::SysvarRead);
    }

    #[test]
    fn crypto_syscalls_are_idempotent() {
        let reg = SyscallRegistry::new();
        assert_eq!(reg.get_safety(SOL_SHA256), SafetyClass::Idempotent);
        assert_eq!(reg.get_safety(SOL_KECCAK256), SafetyClass::Idempotent);
    }

    #[test]
    fn panic_is_not_eligible() {
        let reg = SyscallRegistry::new();
        assert!(!reg.is_optimization_eligible(SOL_PANIC));
    }

    #[test]
    fn sysvar_reads_are_eligible() {
        let reg = SyscallRegistry::new();
        assert!(reg.is_optimization_eligible(SOL_GET_CLOCK_SYSVAR));
        assert!(reg.is_optimization_eligible(SOL_GET_RENT_SYSVAR));
    }

    #[test]
    fn unknown_id_defaults_to_state_changing() {
        let reg = SyscallRegistry::new();
        assert_eq!(reg.get_safety(9999), SafetyClass::StateChanging);
        assert!(!reg.is_optimization_eligible(9999));
    }
}
