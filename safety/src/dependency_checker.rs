use syscallmind_common::{SafetyClass, SyscallTraceEvent};
use crate::classifier::SyscallClassifier;

#[derive(Debug, Clone)]
pub struct DataDependency {
    pub from_index: usize,
    pub to_index: usize,
    pub reason: String,
}

pub struct DependencyChecker;

impl DependencyChecker {
    /// Find WAR/RAW dependencies in a syscall sequence.
    /// Heuristic: any state-changing syscall at index i creates a dependency for
    /// all subsequent reads from the same program_id.
    pub fn check_sequence(sequence: &[SyscallTraceEvent]) -> Vec<DataDependency> {
        let classifier = SyscallClassifier::new();
        let mut deps = Vec::new();

        for (i, from) in sequence.iter().enumerate() {
            if !matches!(classifier.classify(from.syscall_id), SafetyClass::StateChanging | SafetyClass::OrderSensitive) {
                continue;
            }
            for (j, to) in sequence.iter().enumerate().skip(i + 1) {
                // Read after write on same program
                if to.program_id == from.program_id
                    && matches!(classifier.classify(to.syscall_id), SafetyClass::ReadOnly | SafetyClass::Idempotent)
                {
                    deps.push(DataDependency {
                        from_index: i,
                        to_index: j,
                        reason: format!(
                            "syscall[{}] (id={}) mutates state read by syscall[{}] (id={})",
                            i, from.syscall_id, j, to.syscall_id
                        ),
                    });
                }
            }
        }
        deps
    }

    pub fn has_dependencies(sequence: &[SyscallTraceEvent]) -> bool {
        !Self::check_sequence(sequence).is_empty()
    }

    pub fn is_safe_to_reorder(sequence: &[SyscallTraceEvent]) -> bool {
        if Self::has_dependencies(sequence) {
            return false;
        }
        let classifier = SyscallClassifier::new();
        sequence.iter().all(|e| matches!(classifier.classify(e.syscall_id), SafetyClass::ReadOnly))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};

    fn ev(syscall_id: u32) -> SyscallTraceEvent {
        SyscallTraceEvent {
            program_id: zero_pubkey(),
            syscall_id,
            args_hash: 0,
            timestamp_ns: 0,
            slot: 1,
            transaction_id: zero_tx_id(),
            depth: 0,
        }
    }

    #[test]
    fn no_deps_for_all_readonly() {
        let seq = vec![ev(SOL_GET_CLOCK_SYSVAR), ev(SOL_GET_RENT_SYSVAR)];
        assert!(!DependencyChecker::has_dependencies(&seq));
        assert!(DependencyChecker::is_safe_to_reorder(&seq));
    }

    #[test]
    fn dep_detected_after_state_change() {
        let seq = vec![ev(SOL_SET_RETURN_DATA), ev(SOL_GET_RETURN_DATA)];
        let deps = DependencyChecker::check_sequence(&seq);
        assert!(!deps.is_empty());
        assert_eq!(deps[0].from_index, 0);
        assert_eq!(deps[0].to_index, 1);
    }

    #[test]
    fn mixed_sequence_not_safe_to_reorder() {
        let seq = vec![ev(SOL_GET_CLOCK_SYSVAR), ev(SOL_SHA256)];
        // SHA256 is Idempotent, not ReadOnly → not safe to reorder
        assert!(!DependencyChecker::is_safe_to_reorder(&seq));
    }
}
