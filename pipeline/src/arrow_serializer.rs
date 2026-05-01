use std::{io::Write as IoWrite, path::PathBuf};
use anyhow::Context;
use serde_json;
use crate::window_builder::ExecutionWindow;

/// Serializes ExecutionWindows to newline-delimited JSON (NDJSON).
/// This acts as a stand-in for Apache Arrow IPC, using the same logical format
/// (record batches of execution windows) but in a text-portable encoding.
pub struct ArrowSerializer {
    output_path: PathBuf,
}

impl ArrowSerializer {
    pub fn new(output_path: impl Into<PathBuf>) -> Self {
        Self { output_path: output_path.into() }
    }

    /// Serialize a single window to JSON bytes.
    pub fn serialize_window(&self, window: &ExecutionWindow) -> anyhow::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(window)
            .context("failed to serialize ExecutionWindow to JSON")?;
        Ok(bytes)
    }

    /// Write a batch of windows as NDJSON to the output path.
    /// Returns the number of windows written.
    pub fn write_batch(&self, windows: &[ExecutionWindow]) -> anyhow::Result<usize> {
        if let Some(parent) = self.output_path.parent() {
            std::fs::create_dir_all(parent)
                .context("failed to create output directory")?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.output_path)
            .context("failed to open output file")?;
        let mut writer = std::io::BufWriter::new(file);
        let mut count = 0;
        for window in windows {
            let bytes = self.serialize_window(window)?;
            writer.write_all(&bytes).context("write failed")?;
            writer.write_all(b"\n").context("write newline failed")?;
            count += 1;
        }
        writer.flush().context("flush failed")?;
        Ok(count)
    }

    /// Read windows back from NDJSON file.
    pub fn read_windows(path: &std::path::Path) -> anyhow::Result<Vec<ExecutionWindow>> {
        let content = std::fs::read_to_string(path).context("failed to read file")?;
        let mut windows = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let w: ExecutionWindow = serde_json::from_str(line)
                .context("failed to deserialize ExecutionWindow")?;
            windows.push(w);
        }
        Ok(windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscallmind_common::{zero_pubkey, zero_tx_id, SyscallTraceEvent};
    use crate::window_builder::ExecutionWindow;

    fn sample_window() -> ExecutionWindow {
        ExecutionWindow {
            transaction_id: zero_tx_id(),
            slot: 5,
            events: vec![SyscallTraceEvent {
                program_id: zero_pubkey(),
                syscall_id: 1,
                args_hash: 42,
                timestamp_ns: 1000,
                slot: 5,
                transaction_id: zero_tx_id(),
                depth: 0,
            }],
            start_ts: 1000,
            end_ts: 1000,
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let ser = ArrowSerializer::new("/tmp/test_windows.jsonl");
        let w = sample_window();
        let bytes = ser.serialize_window(&w).unwrap();
        let w2: ExecutionWindow = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(w2.slot, 5);
        assert_eq!(w2.events[0].syscall_id, 1);
    }
}
