// brute_rust v0.2 — CUDA-accelerated Bitcoin address brute-forcer.
//
//   * CPU-only path (`--cpu-only`) preserves the original v0.1 behaviour.
//   * GPU path (default) runs the same brute-force loop entirely on the
//     GPU: secp256k1 scalar mul + HASH160 for each candidate. See src/kernel.cu.

mod addr;
mod cpu;

#[cfg(feature = "cuda")]
mod precompute;

#[cfg(feature = "cuda")]
mod gpu;

use clap::Parser;
use std::fs;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of CPU threads to use in CPU-only mode (0 means all available).
    #[arg(short, long, default_value_t = 0)]
    cpu: u32,

    /// Path to the directory with address databases (must contain `btc.tsv`).
    #[arg(long, default_value = "../addrs/")]
    path: String,

    /// Disable GPU and run the original CPU-only loop.
    #[arg(long, default_value_t = false)]
    cpu_only: bool,

    /// CUDA device index (only meaningful when the GPU path is active).
    #[arg(long, default_value_t = 0)]
    gpu_id: usize,

    /// Batch size of the GPU kernel (number of keys per launch).
    #[arg(long, default_value_t = 1_048_576)]
    batch: u32,
}

// Public output payload written to found.json on a hit. Shared by both paths.
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
pub struct FoundKey {
    pub coin: String,
    pub matched_type: String,
    pub private_key_hex: String,
    pub address: String,
    pub wif: String,
}

pub fn report_match(fk: &FoundKey) {
    println!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("!!!!!!!!!! MATCH FOUND !!!!!!!!!!!!!");
    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    println!("{}", serde_json::to_string_pretty(fk).unwrap_or_default());
    if let Err(e) = save_found_key_to_file(fk, "found.json") {
        eprintln!("Failed to save found.json: {}", e);
    } else {
        println!("Found key details saved to found.json");
    }
}

fn save_found_key_to_file(found_key: &FoundKey, file_path: &str) -> std::io::Result<()> {
    let json_data = serde_json::to_string_pretty(found_key)?;
    fs::write(file_path, json_data)
}

fn main() {
    let args = Args::parse();

    let num_threads = if args.cpu == 0 { num_cpus::get() } else { args.cpu as usize };

    println!("--- SETUP ---");
    println!("Available CPU cores: {} (using {} in CPU mode).", num_cpus::get(), num_threads);
    println!("Loading address database...");
    let file_path = format!("{}btc.tsv", args.path);
    println!("Database path: {}", file_path);

    let db = Arc::new(addr::load_addresses_from_file(&file_path));
    println!(
        "Loaded {} unique addresses ({} pubkey-hash160, {} script-hash160).",
        db.len(),
        db.pubkey_hash160.len(),
        db.script_hash160.len(),
    );
    println!("-------------\n");

    if args.cpu_only {
        cpu::run(num_threads, db);
        return;
    }

    // Default: GPU
    #[cfg(feature = "cuda")]
    {
        match gpu::run(args.gpu_id, args.batch, db.clone()) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("GPU run failed: {:#}\nFalling back to CPU-only mode.", e);
                cpu::run(num_threads, db);
            }
        }
    }

    #[cfg(not(feature = "cuda"))]
    {
        eprintln!("Binary was built without the `cuda` feature — falling back to CPU-only mode.");
        cpu::run(num_threads, db);
    }
}
