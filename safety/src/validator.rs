use syscallmind_common::{SafetyClass, SyscallId, SyscallTraceEvent};
use crate::{classifier::SyscallClassifier, dependency_checker::DependencyChecker};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimizationKind {
    Cache,
    Batch,
    Prefetch,
    Reorder,
    Dedup,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub approved: bool,
    pub reason: String,
    pub kind: OptimizationKind,
}

impl ValidationResult {
    fn approve(kind: OptimizationKind, reason: impl Into<String>) -> Self {
        Self { approved: true, reason: reason.into(), kind }
    }
    fn reject(kind: OptimizationKind, reason: impl Into<String>) -> Self {
        Self { approved: false, reason: reason.into(), kind }
    }
}

pub struct SafetyValidator {
    classifier: SyscallClassifier,
    checker: DependencyChecker,
    enforce_determinism: bool,
}

impl SafetyValidator {
    pub fn new(enforce_determinism: bool) -> Self {
        Self {
            classifier: SyscallClassifier::new(),
            checker: DependencyChecker,
            enforce_determinism,
        }
    }

    pub fn validate_cache(&self, syscall_id: SyscallId) -> ValidationResult {
        if !self.enforce_determinism {
            return ValidationResult::approve(OptimizationKind::Cache, "determinism not enforced");
        }
        if self.classifier.is_optimization_eligible(syscall_id) {
            ValidationResult::approve(
                OptimizationKind::Cache,
                format!("syscall {} is {:?} — cacheable", syscall_id, self.classifier.classify(syscall_id)),
            )
        } else {
            ValidationResult::reject(
                OptimizationKind::Cache,
                format!("syscall {} is {:?} — not cacheable", syscall_id, self.classifier.classify(syscall_id)),
            )
        }
    }

    pub fn validate_batch(&self, syscall_ids: &[SyscallId]) -> ValidationResult {
        for &id in syscall_ids {
            if !self.classifier.is_optimization_eligible(id) {
                return ValidationResult::reject(
                    OptimizationKind::Batch,
                    format!("syscall {} is not eligible for batching", id),
                );
            }
        }
        ValidationResult::approve(OptimizationKind::Batch, "all syscalls are batch-eligible")
    }

    pub fn validate_reorder(&self, sequence: &[SyscallTraceEvent]) -> ValidationResult {
        if DependencyChecker::has_dependencies(sequence) {
            return ValidationResult::reject(
                OptimizationKind::Reorder,
                "sequence has data dependencies — reordering unsafe",
            );
        }
        if !DependencyChecker::is_safe_to_reorder(sequence) {
            return ValidationResult::reject(
                OptimizationKind::Reorder,
                "sequence contains non-ReadOnly syscalls — reordering not permitted",
            );
        }
        ValidationResult::approve(OptimizationKind::Reorder, "all syscalls are ReadOnly and dependency-free")
    }

    pub fn validate_dedup(&self, syscall_id: SyscallId) -> ValidationResult {
        match self.classifier.classify(syscall_id) {
            SafetyClass::ReadOnly | SafetyClass::Idempotent => {
                ValidationResult::approve(OptimizationKind::Dedup, "idempotent — dedup safe")
            }
            other => ValidationResult::reject(
                OptimizationKind::Dedup,
                format!("syscall {} is {:?} — dedup would alter semantics", syscall_id, other),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};

    fn validator() -> SafetyValidator {
        SafetyValidator::new(true)
    }

    fn ev(id: u32) -> SyscallTraceEvent {
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
    fn cache_approved_for_readonly() {
        let v = validator();
        assert!(v.validate_cache(SOL_GET_CLOCK_SYSVAR).approved);
    }

    #[test]
    fn cache_rejected_for_state_changing() {
        let v = validator();
        assert!(!v.validate_cache(SOL_PANIC).approved);
        assert!(!v.validate_cache(SOL_INVOKE_SIGNED).approved);
    }

    #[test]
    fn batch_approved_for_sysvar_reads() {
        let v = validator();
        assert!(v.validate_batch(&[SOL_GET_CLOCK_SYSVAR, SOL_GET_RENT_SYSVAR]).approved);
    }

    #[test]
    fn batch_rejected_if_any_ineligible() {
        let v = validator();
        assert!(!v.validate_batch(&[SOL_GET_CLOCK_SYSVAR, SOL_PANIC]).approved);
    }

    #[test]
    fn reorder_approved_for_all_readonly() {
        let v = validator();
        let seq = vec![ev(SOL_GET_CLOCK_SYSVAR), ev(SOL_GET_RENT_SYSVAR)];
        assert!(v.validate_reorder(&seq).approved);
    }

    #[test]
    fn reorder_rejected_with_state_change() {
        let v = validator();
        let seq = vec![ev(SOL_SET_RETURN_DATA), ev(SOL_GET_RETURN_DATA)];
        assert!(!v.validate_reorder(&seq).approved);
    }

    #[test]
    fn dedup_approved_for_crypto() {
        let v = validator();
        assert!(v.validate_dedup(SOL_SHA256).approved);
    }

    #[test]
    fn dedup_rejected_for_state_changing() {
        let v = validator();
        assert!(!v.validate_dedup(SOL_SET_RETURN_DATA).approved);
    }
}
