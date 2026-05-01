use fnv::FnvHashMap;
use serde::{Deserialize, Serialize};
use std::fmt;

pub type Pubkey = [u8; 32];
pub type SyscallId = u32;
pub type TransactionId = [u8; 32];
pub type ArgsHash = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SyscallTraceEvent {
    pub program_id: Pubkey,
    pub syscall_id: SyscallId,
    pub args_hash: ArgsHash,
    pub timestamp_ns: u64,
    pub slot: u64,
    pub transaction_id: TransactionId,
    pub depth: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyscallClass {
    SysvarRead,
    AccountRead,
    Crypto,
    StateChange,
    CPI,
    Abort,
    Unknown,
}

impl fmt::Display for SyscallClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SysvarRead => write!(f, "SysvarRead"),
            Self::AccountRead => write!(f, "AccountRead"),
            Self::Crypto => write!(f, "Crypto"),
            Self::StateChange => write!(f, "StateChange"),
            Self::CPI => write!(f, "CPI"),
            Self::Abort => write!(f, "Abort"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SafetyClass {
    ReadOnly,
    Idempotent,
    StateChanging,
    OrderSensitive,
}

impl fmt::Display for SafetyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "ReadOnly"),
            Self::Idempotent => write!(f, "Idempotent"),
            Self::StateChanging => write!(f, "StateChanging"),
            Self::OrderSensitive => write!(f, "OrderSensitive"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub syscall_id: SyscallId,
    pub args_hash: ArgsHash,
}

pub mod syscall_ids {
    pub const SOL_GET_CLOCK_SYSVAR: u32 = 1;
    pub const SOL_GET_RENT_SYSVAR: u32 = 2;
    pub const SOL_GET_EPOCH_SCHEDULE_SYSVAR: u32 = 3;
    pub const SOL_GET_FEES_SYSVAR: u32 = 4;
    pub const SOL_GET_SLOT_HASHES_SYSVAR: u32 = 5;
    pub const SOL_GET_STAKE_HISTORY_SYSVAR: u32 = 6;
    pub const SOL_LOG: u32 = 10;
    pub const SOL_LOG_64: u32 = 11;
    pub const SOL_LOG_PUBKEY: u32 = 12;
    pub const SOL_LOG_COMPUTE_UNITS: u32 = 13;
    pub const SOL_SHA256: u32 = 20;
    pub const SOL_KECCAK256: u32 = 21;
    pub const SOL_SECP256K1_RECOVER: u32 = 22;
    pub const SOL_ED25519_VERIFY: u32 = 23;
    pub const SOL_INVOKE_SIGNED: u32 = 30;
    pub const SOL_SET_RETURN_DATA: u32 = 40;
    pub const SOL_GET_RETURN_DATA: u32 = 41;
    pub const SOL_ALLOC_FREE: u32 = 50;
    pub const SOL_MEMCPY: u32 = 51;
    pub const SOL_MEMMOVE: u32 = 52;
    pub const SOL_MEMSET: u32 = 53;
    pub const SOL_MEMCMP: u32 = 54;
    pub const SOL_PANIC: u32 = 60;
    pub const SOL_ABORT: u32 = 61;
}

/// FNV-1a 64-bit hash.
pub fn fnv_hash(data: &[u8]) -> ArgsHash {
    const OFFSET_BASIS: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Zero-initialized pubkey.
pub fn zero_pubkey() -> Pubkey {
    [0u8; 32]
}

/// Zero-initialized transaction ID.
pub fn zero_tx_id() -> TransactionId {
    [0u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_hash_is_deterministic() {
        let h1 = fnv_hash(b"hello");
        let h2 = fnv_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv_hash_differs_for_different_inputs() {
        assert_ne!(fnv_hash(b"hello"), fnv_hash(b"world"));
    }

    #[test]
    fn syscall_class_display() {
        assert_eq!(SyscallClass::Crypto.to_string(), "Crypto");
        assert_eq!(SafetyClass::ReadOnly.to_string(), "ReadOnly");
    }
}
