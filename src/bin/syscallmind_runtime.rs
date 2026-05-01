use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use clap::Parser;
use rand::Rng;
use syscallmind_common::{syscall_ids::*, zero_pubkey, zero_tx_id};
use syscallmind_runtime::{SyscallHandler, TraceEmitter};

#[derive(Parser, Debug)]
#[command(name = "syscallmind-runtime", about = "SyscallMind optimized BPF runtime")]
struct Args {
    #[arg(long, default_value = "config/default.toml")]
    config: String,
    #[arg(long, default_value = "ml/inference/models/transformer.onnx")]
    model: String,
}

const SYSCALL_POOL: &[u32] = &[
    SOL_GET_CLOCK_SYSVAR,
    SOL_GET_RENT_SYSVAR,
    SOL_SHA256,
    SOL_KECCAK256,
    SOL_LOG,
    SOL_INVOKE_SIGNED,
    SOL_SET_RETURN_DATA,
    SOL_GET_RETURN_DATA,
    SOL_ED25519_VERIFY,
    SOL_LOG_64,
];

fn print_banner(args: &Args) {
    eprintln!("╔═══════════════════════════════════════════════════╗");
    eprintln!("║          SyscallMind Runtime  v0.1.0              ║");
    eprintln!("║  AI-Augmented Syscall Optimization Engine         ║");
    eprintln!("╚═══════════════════════════════════════════════════╝");
    eprintln!("  Config : {}", args.config);
    eprintln!("  Model  : {}", args.model);
    eprintln!();
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    print_banner(&args);

    let slot = Arc::new(AtomicU64::new(280_000_000));
    let (emitter, rx) = TraceEmitter::new();
    let handler = SyscallHandler::new(emitter, slot.clone());

    // Drain the trace channel in a background thread
    let rx_thread = std::thread::spawn(move || {
        let mut count = 0u64;
        while let Ok(_event) = rx.recv() {
            count += 1;
            // In a real runtime: events go to pipeline → optimizer
        }
        count
    });

    let mut rng = rand::thread_rng();
    let total_events = 100_000u64;
    let start = Instant::now();

    eprintln!("Running simulation: {} syscall events...", total_events);

    for i in 0..total_events {
        let syscall_id = SYSCALL_POOL[rng.gen_range(0..SYSCALL_POOL.len())];
        let args_data: Vec<u8> = (0..8).map(|_| rng.gen::<u8>()).collect();
        let mut tx_id = zero_tx_id();
        tx_id[0] = (i % 256) as u8;
        tx_id[1] = ((i / 256) % 256) as u8;

        handler.handle(zero_pubkey(), syscall_id, &args_data, tx_id, 0);

        // Advance slot periodically
        if i % 432 == 0 {
            slot.fetch_add(1, Ordering::Relaxed);
        }

        if (i + 1) % 10_000 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let tps = i as f64 / elapsed;
            eprintln!(
                "  [{:>6}/{:>6}] slot={} tps={:.0}  dropped={}",
                i + 1,
                total_events,
                slot.load(Ordering::Relaxed),
                tps,
                handler.stats().len(), // proxy: unique syscall types seen
            );
        }
    }

    // Signal channel close by dropping handler (which drops emitter)
    drop(handler);
    let processed = rx_thread.join().unwrap_or(0);

    let elapsed = start.elapsed().as_secs_f64();
    eprintln!();
    eprintln!("Simulation complete:");
    eprintln!("  Total events : {}", total_events);
    eprintln!("  Processed    : {}", processed);
    eprintln!("  Elapsed      : {:.2}s", elapsed);
    eprintln!("  Throughput   : {:.0} events/s", total_events as f64 / elapsed);

    Ok(())
}
