// CUDA orchestration: compile kernel with NVRTC, launch batches, check
// results, and reconstruct matched private keys on the CPU.

use crate::addr::{AddressDb, Hash160};
use crate::precompute::GTable;
use crate::{report_match, FoundKey};

use anyhow::{Context, Result};
use bitcoin::network::Network;
use cudarc::driver::{CudaContext, CudaFunction, CudaModule, CudaSlice, CudaStream, LaunchConfig, PushKernelArg};
use cudarc::nvrtc::compile_ptx;
use secp256k1::{Secp256k1, SecretKey};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

const KERNEL_SRC: &str = include_str!("kernel.cu");
const KERNEL_NAME: &str = "brute_kernel";
const BLOCK_DIM: u32 = 256;

pub struct GpuRunner {
    stream: Arc<CudaStream>,
    _module: Arc<CudaModule>,
    func: CudaFunction,
    table_x: CudaSlice<u64>,
    table_y: CudaSlice<u64>,
    seed_gpu: CudaSlice<u64>,
    h1_gpu: CudaSlice<u8>,
    h2_gpu: CudaSlice<u8>,
    batch_size: u32,
}

impl GpuRunner {
    pub fn new(gpu_id: usize, batch_size: u32, table: &GTable) -> Result<Self> {
        let ctx = CudaContext::new(gpu_id)
            .with_context(|| format!("cannot open CUDA device {}", gpu_id))?;
        println!("CUDA device {} opened.", gpu_id);

        let start = Instant::now();
        let ptx = compile_ptx(KERNEL_SRC).context("NVRTC compilation of kernel.cu failed")?;
        println!("Kernel compiled in {:.2}s.", start.elapsed().as_secs_f64());

        let module = ctx
            .load_module(ptx)
            .context("failed to load compiled PTX")?;
        let func = module
            .load_function(KERNEL_NAME)
            .with_context(|| format!("kernel function '{}' not found", KERNEL_NAME))?;

        let stream = ctx.default_stream();

        // Upload precomputed G table (allocate + copy in one shot).
        let table_x: CudaSlice<u64> = stream.clone_htod(&table.x)?;
        let table_y: CudaSlice<u64> = stream.clone_htod(&table.y)?;

        let seed_gpu: CudaSlice<u64> = stream.alloc_zeros(4)?;
        let h1_gpu: CudaSlice<u8> = stream.alloc_zeros((batch_size as usize) * 20)?;
        let h2_gpu: CudaSlice<u8> = stream.alloc_zeros((batch_size as usize) * 20)?;

        Ok(Self {
            stream,
            _module: module,
            func,
            table_x,
            table_y,
            seed_gpu,
            h1_gpu,
            h2_gpu,
            batch_size,
        })
    }

    fn launch(&mut self, base_seed: &[u64; 4]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Upload base seed
        self.stream.memcpy_htod(base_seed, &mut self.seed_gpu)?;

        let grid_x = (self.batch_size + BLOCK_DIM - 1) / BLOCK_DIM;
        let cfg = LaunchConfig {
            grid_dim: (grid_x, 1, 1),
            block_dim: (BLOCK_DIM, 1, 1),
            shared_mem_bytes: 0,
        };

        let batch = self.batch_size;
        unsafe {
            let mut launcher = self.stream.launch_builder(&self.func);
            launcher.arg(&self.seed_gpu);
            launcher.arg(&self.table_x);
            launcher.arg(&self.table_y);
            launcher.arg(&mut self.h1_gpu);
            launcher.arg(&mut self.h2_gpu);
            launcher.arg(&batch);
            launcher.launch(cfg)?;
        }

        // Sync stream and copy results back.
        self.stream.synchronize()?;
        let h1_host: Vec<u8> = self.stream.clone_dtoh(&self.h1_gpu)?;
        let h2_host: Vec<u8> = self.stream.clone_dtoh(&self.h2_gpu)?;
        Ok((h1_host, h2_host))
    }
}

// SplitMix64 — must exactly match device implementation in kernel.cu.
#[inline(always)]
fn splitmix64_step(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Reproduce the 256-bit private key that thread `tid` used inside the kernel.
pub fn derive_privkey(base_seed: &[u64; 4], tid: u64) -> [u64; 4] {
    let mut state = base_seed[0] ^ tid;
    let mut out = [0u64; 4];
    out[0] = splitmix64_step(&mut state);
    state ^= base_seed[1];
    out[1] = splitmix64_step(&mut state);
    state ^= base_seed[2];
    out[2] = splitmix64_step(&mut state);
    state ^= base_seed[3];
    out[3] = splitmix64_step(&mut state);
    if out == [0, 0, 0, 0] {
        out[0] = 1;
    }
    out
}

fn privkey_to_be32(k: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // k[0] is least significant limb → occupies bytes 24..32 in big-endian output.
    for i in 0..4 {
        let start = 32 - 8 * (i + 1);
        out[start..start + 8].copy_from_slice(&k[i].to_be_bytes());
    }
    out
}

pub fn run(gpu_id: usize, batch_size: u32, db: Arc<AddressDb>) -> Result<()> {
    println!("--- GPU ---");
    println!("Preparing precomputed G table on CPU...");
    let table = GTable::build();

    let mut runner = GpuRunner::new(gpu_id, batch_size, &table)?;
    println!(
        "Launching batches of {} keys ({} blocks x {} threads).",
        batch_size,
        (batch_size + BLOCK_DIM - 1) / BLOCK_DIM,
        BLOCK_DIM
    );

    let found_flag = Arc::new(AtomicBool::new(false));
    let start_time = Instant::now();
    let mut total: u64 = 0;

    let pubkey_set_empty = db.pubkey_hash160.is_empty();
    let script_set_empty = db.script_hash160.is_empty();
    if pubkey_set_empty && script_set_empty {
        eprintln!(
            "warning: address database is empty after parsing; GPU will run but never match."
        );
    }

    while !found_flag.load(Ordering::Relaxed) {
        // Fresh 256-bit base seed for this batch.
        let mut base_seed = [0u64; 4];
        for w in base_seed.iter_mut() {
            *w = rand::random();
        }

        let (h1, h2) = runner.launch(&base_seed)?;
        total += batch_size as u64;

        // Scan for matches. In principle we could push the address sets to
        // GPU, but for a database of a few tens of millions of entries the
        // 40 MB PCIe roundtrip is dwarfed by the kernel execution time.
        let mut hit: Option<(u64, &'static str)> = None;
        if !pubkey_set_empty {
            for i in 0..batch_size as usize {
                let base = i * 20;
                let mut h: Hash160 = [0u8; 20];
                h.copy_from_slice(&h1[base..base + 20]);
                if db.pubkey_hash160.contains(&h) {
                    hit = Some((i as u64, "P2PKH/P2WPKH"));
                    break;
                }
            }
        }
        if hit.is_none() && !script_set_empty {
            for i in 0..batch_size as usize {
                let base = i * 20;
                let mut h: Hash160 = [0u8; 20];
                h.copy_from_slice(&h2[base..base + 20]);
                if db.script_hash160.contains(&h) {
                    hit = Some((i as u64, "P2SH-P2WPKH"));
                    break;
                }
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            let rate = total as f64 / elapsed;
            println!(
                ">>> [GPU] Total checked: {}. Overall Speed: {:.0} keys/sec.",
                total, rate
            );
        }

        if let Some((tid, kind)) = hit {
            if !found_flag.swap(true, Ordering::SeqCst) {
                report_gpu_hit(&base_seed, tid, kind);
            }
            break;
        }
    }

    Ok(())
}

fn report_gpu_hit(base_seed: &[u64; 4], tid: u64, kind: &str) {
    let k_limbs = derive_privkey(base_seed, tid);
    let priv_be = privkey_to_be32(&k_limbs);

    // Reconstruct via the well-tested secp256k1 crate to produce clean output.
    let secp = Secp256k1::new();
    let sk = match SecretKey::from_slice(&priv_be) {
        Ok(sk) => sk,
        Err(e) => {
            eprintln!(
                "Failed to reconstruct SecretKey from GPU-derived scalar: {}",
                e
            );
            return;
        }
    };
    let private_key_btc = bitcoin::PrivateKey::new(sk, Network::Bitcoin);
    let public_key = private_key_btc.public_key(&secp);

    let a_p2pkh = bitcoin::Address::p2pkh(&public_key, Network::Bitcoin);
    let a_p2sh = bitcoin::Address::p2shwpkh(&public_key, Network::Bitcoin)
        .expect("compressed key required");
    let a_p2wpkh = bitcoin::Address::p2wpkh(&public_key, Network::Bitcoin)
        .expect("compressed key required");

    let fk = FoundKey {
        coin: "BTC".to_string(),
        matched_type: kind.to_string(),
        private_key_hex: sk.display_secret().to_string(),
        address: format!(
            "P2PKH: {} | P2SH-P2WPKH: {} | P2WPKH: {}",
            a_p2pkh, a_p2sh, a_p2wpkh
        ),
        wif: private_key_btc.to_wif(),
    };
    report_match(&fk);
}
