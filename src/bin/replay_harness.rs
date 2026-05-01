use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

use clap::Parser;
use rand::Rng;
use syscallmind_common::{syscall_ids::*, SyscallTraceEvent, zero_pubkey, zero_tx_id};
use syscallmind_pipeline::WindowBuilder;

#[derive(Parser, Debug)]
#[command(name = "replay-harness", about = "Replay syscall traces from a snapshot")]
struct Args {
    #[arg(long)]
    snapshot: String,
    #[arg(long, default_value = "traces/replay.jsonl")]
    output: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Some(parent) = PathBuf::from(&args.output).parent() {
        fs::create_dir_all(parent).ok();
    }

    // If snapshot does not exist, generate mock data
    let snapshot_path = PathBuf::from(&args.snapshot);
    let replay_source = if snapshot_path.exists() {
        eprintln!("Replaying from snapshot: {}", args.snapshot);
        std::fs::read_to_string(&snapshot_path)?
    } else {
        eprintln!("Snapshot not found at {}. Using synthetic mock data.", args.snapshot);
        generate_mock_snapshot()
    };

    let start = Instant::now();
    let mut wb = WindowBuilder::new(128);
    let mut rng = rand::thread_rng();
    let mut total_events = 0usize;
    let mut total_txs = 0usize;

    let output_file = fs::File::create(&args.output)?;
    let mut writer = BufWriter::new(output_file);

    for line in replay_source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(window) = serde_json::from_str::<serde_json::Value>(line) {
            let tx_id_arr = window["transaction_id"]
                .as_array()
                .map(|a| {
                    let mut arr = [0u8; 32];
                    for (i, v) in a.iter().enumerate().take(32) {
                        arr[i] = v.as_u64().unwrap_or(0) as u8;
                    }
                    arr
                })
                .unwrap_or_else(zero_tx_id);

            if let Some(events) = window["events"].as_array() {
                for ev in events {
                    let id = ev["syscall_id"].as_u64().unwrap_or(1) as u32;
                    let ts = ev["timestamp_ns"].as_u64().unwrap_or(0);
                    let slot = window["slot"].as_u64().unwrap_or(0);
                    let event = SyscallTraceEvent {
                        program_id: zero_pubkey(),
                        syscall_id: id,
                        args_hash: id as u64 * 7919,
                        timestamp_ns: ts,
                        slot,
                        transaction_id: tx_id_arr,
                        depth: 0,
                    };
                    wb.ingest(event);
                    total_events += 1;
                }
                if let Some(w) = wb.finalize(tx_id_arr) {
                    writeln!(writer, "{}", serde_json::to_string(&w)?)?;
                    total_txs += 1;
                }
            }
        }
    }

    // Drain any remaining open windows
    let remaining = wb.drain_all();
    for w in &remaining {
        writeln!(writer, "{}", serde_json::to_string(w)?)?;
    }
    total_txs += remaining.len();

    writer.flush()?;
    let elapsed = start.elapsed();
    eprintln!(
        "Replay complete: {} events, {} transactions in {:.2}s → {}",
        total_events,
        total_txs,
        elapsed.as_secs_f64(),
        args.output
    );
    Ok(())
}

fn generate_mock_snapshot() -> String {
    let mut rng = rand::thread_rng();
    let mut lines = Vec::new();
    let syscall_pool = [
        SOL_GET_CLOCK_SYSVAR,
        SOL_GET_RENT_SYSVAR,
        SOL_SHA256,
        SOL_KECCAK256,
        SOL_LOG,
        SOL_INVOKE_SIGNED,
    ];

    for tx_idx in 0..1000u64 {
        let mut tx_id = vec![0u64; 32];
        for v in tx_id.iter_mut() {
            *v = rng.gen_range(0..=255);
        }
        let n_events = rng.gen_range(3..10);
        let events: Vec<serde_json::Value> = (0..n_events)
            .map(|i| {
                let id = syscall_pool[rng.gen_range(0..syscall_pool.len())];
                serde_json::json!({
                    "syscall_id": id,
                    "timestamp_ns": tx_idx * 1_000_000 + i * 400_000u64,
                    "args_hash": id as u64 * 7919 ^ tx_idx,
                    "depth": 0,
                })
            })
            .collect();

        let window = serde_json::json!({
            "transaction_id": tx_id,
            "slot": tx_idx / 432 + 280_000_000,
            "events": events,
        });
        lines.push(serde_json::to_string(&window).unwrap());
    }
    lines.join("\n")
}
