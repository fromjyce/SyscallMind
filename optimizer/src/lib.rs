pub mod batcher;
pub mod cache;
pub mod dedup;
pub mod prefetcher;

pub use batcher::{batch_sysvar_reads, BatchedFetch, PendingSyscall};
pub use cache::SysvarCache;
pub use dedup::DedupTable;
pub use prefetcher::SpeculativePrefetcher;
