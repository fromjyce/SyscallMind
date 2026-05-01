use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
};

use clap::Parser;
use rand::Rng;
use syscallmind_common::syscall_ids::*;

#[derive(Parser, Debug)]
#[command(name = "workload-generator", about = "Generate synthetic syscall trace data")]
struct Args {
    #[arg(long, default_value = "1000000")]
    transactions: u64,
    #[arg(long, default_value = "traces/workload.jsonl")]
    output: String,
}

/// Workload profiles that mimic DeFi, NFT, and token transfer patterns.
#[derive(Clone, Copy)]
enum WorkloadProfile {
    DeFi,
    Nft,
    TokenTransfer,
}

fn generate_syscall_sequence(profile: WorkloadProfile, rng: &mut impl Rng) -> Vec<u32> {
    match profile {
        WorkloadProfile::DeFi => {
            let mut ids = vec![SOL_GET_CLOCK_SYSVAR, SOL_GET_RENT_SYSVAR];
            let n_crypto = rng.gen_range(2..8);
            const CRYPTO: [u32; 3] = [SOL_SHA256, SOL_KECCAK256, SOL_SECP256K1_RECOVER];
            for _ in 0..n_crypto {
                ids.push(CRYPTO[rng.gen_range(0..CRYPTO.len())]);
            }
            ids.push(SOL_INVOKE_SIGNED);
            ids.push(SOL_LOG);
            ids
        }
        WorkloadProfile::Nft => {
            let mut ids = vec![SOL_GET_CLOCK_SYSVAR];
            let n_reads = rng.gen_range(3..10);
            for _ in 0..n_reads {
                ids.push(SOL_LOG);
            }
            ids.push(SOL_SHA256);
            ids.push(SOL_INVOKE_SIGNED);
            ids.push(SOL_SET_RETURN_DATA);
            ids
        }
        WorkloadProfile::TokenTransfer => {
            vec![
                SOL_GET_CLOCK_SYSVAR,
                SOL_GET_RENT_SYSVAR,
                SOL_LOG,
                SOL_INVOKE_SIGNED,
                SOL_SET_RETURN_DATA,
            ]
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Some(parent) = PathBuf::from(&args.output).parent() {
        fs::create_dir_all(parent).ok();
    }

    let file = fs::File::create(&args.output)?;
    let mut writer = BufWriter::new(file);

    let mut rng = rand::thread_rng();
    let profiles = [WorkloadProfile::DeFi, WorkloadProfile::Nft, WorkloadProfile::TokenTransfer];
    let weights = [0.5f64, 0.3, 0.2]; // DeFi 50%, NFT 30%, Transfer 20%

    let mut slot: u64 = 280_000_000;
    let mut ts: u64 = 1_700_000_000_000_000_000;
    let interval = 400_000u64; // 400µs per syscall

    for tx_idx in 0..args.transactions {
        // Pick profile by weight
        let r: f64 = rng.gen();
        let profile = if r < weights[0] {
            profiles[0]
        } else if r < weights[0] + weights[1] {
            profiles[1]
        } else {
            profiles[2]
        };

        let syscall_ids = generate_syscall_sequence(profile, &mut rng);
        let mut tx_id = [0u8; 32];
        rng.fill(&mut tx_id);
        let mut program_id = [0u8; 32];
        rng.fill(&mut program_id[..4]); // short program ID for diversity

        let events: Vec<serde_json::Value> = syscall_ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                let event_ts = ts + i as u64 * interval;
                serde_json::json!({
                    "syscall_id": id,
                    "args_hash": id as u64 * 7919u64 ^ (tx_idx * 31),
                    "timestamp_ns": event_ts,
                    "slot": slot,
                    "depth": 0u8,
                })
            })
            .collect();

        let window = serde_json::json!({
            "transaction_id": tx_id,
            "slot": slot,
            "events": events,
            "start_ts": ts,
            "end_ts": ts + syscall_ids.len() as u64 * interval,
        });

        writeln!(writer, "{}", serde_json::to_string(&window)?)?;

        ts += syscall_ids.len() as u64 * interval + 50_000; // inter-tx gap
        if tx_idx % 432 == 0 {
            slot += 1; // ~432 txs per slot
        }

        if (tx_idx + 1) % 100_000 == 0 {
            eprintln!("Generated {}/{} transactions...", tx_idx + 1, args.transactions);
        }
    }

    writer.flush()?;
    eprintln!("Done. Written to {}", args.output);
    Ok(())
}
