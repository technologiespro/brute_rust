// CPU brute-force loop (unchanged in spirit from v0.1) — kept as a fallback
// when the `--cpu-only` flag is passed or when CUDA is unavailable.

use crate::addr::AddressDb;
use crate::{report_match, FoundKey};
use bitcoin::network::Network;
use rayon::prelude::*;
use secp256k1::{Secp256k1, SecretKey};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub fn run(num_threads: usize, db: Arc<AddressDb>) {
    println!("Running in CPU-only mode with {} threads.", num_threads);

    let found_flag = Arc::new(AtomicBool::new(false));
    let total_keys = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("failed to build rayon pool");

    pool.install(move || {
        (0..u64::MAX).into_par_iter().for_each(|_| {
            if found_flag.load(Ordering::Relaxed) {
                return;
            }

            let current_total = total_keys.fetch_add(1, Ordering::Relaxed);
            if current_total > 0 && current_total % 1_000_000 == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let rate = current_total as f64 / elapsed;
                    println!(
                        ">>> [CPU] Total checked: {}. Overall Speed: {:.0} keys/sec.",
                        current_total, rate
                    );
                }
            }

            let secp = Secp256k1::new();
            let private_key_secp = SecretKey::new(&mut rand::thread_rng());
            let private_key_btc = bitcoin::PrivateKey::new(private_key_secp, Network::Bitcoin);
            let public_key = private_key_btc.public_key(&secp);

            let address_p2pkh = bitcoin::Address::p2pkh(&public_key, Network::Bitcoin);
            let address_p2sh_p2wpkh =
                bitcoin::Address::p2shwpkh(&public_key, Network::Bitcoin).expect("compressed key");
            let address_p2wpkh =
                bitcoin::Address::p2wpkh(&public_key, Network::Bitcoin).expect("compressed key");

            let matched: Option<&'static str> =
                if db.all_strings.contains(&address_p2pkh.to_string()) {
                    Some("P2PKH")
                } else if db.all_strings.contains(&address_p2sh_p2wpkh.to_string()) {
                    Some("P2SH-P2WPKH")
                } else if db.all_strings.contains(&address_p2wpkh.to_string()) {
                    Some("P2WPKH")
                } else {
                    None
                };

            if let Some(kind) = matched {
                if !found_flag.swap(true, Ordering::SeqCst) {
                    let found_key = FoundKey {
                        coin: "BTC".to_string(),
                        matched_type: kind.to_string(),
                        private_key_hex: private_key_secp.display_secret().to_string(),
                        address: format!(
                            "P2PKH: {} | P2SH-P2WPKH: {} | P2WPKH: {}",
                            address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh
                        ),
                        wif: private_key_btc.to_wif(),
                    };
                    report_match(&found_key);
                }
            }
        });
    });
}
