use bitcoin::network::Network;
use clap::Parser;
use rayon::prelude::*;
use secp256k1::{Secp256k1, SecretKey};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

// --- Command line arguments ---
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of CPU threads to use (0 means all available)
    #[arg(short, long, default_value_t = 0)]
    cpu: u32,

    /// Path to the directory with address databases
    #[arg(long, default_value = "../addrs/")]
    path: String,
}

// --- Struct for found key ---
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct FoundKey {
    coin: String, // Always "BTC" for this version
    private_key_hex: String,
    address: String,
    wif: String,
}


fn main() {
    let args = Args::parse();
    let num_threads = if args.cpu == 0 { num_cpus::get() } else { args.cpu as usize };

    println!("--- SETUP ---");
    println!("Using {} CPU threads.", num_threads);

    // --- Load addresses into a shared set ---
    println!("Loading addresses from file...");
    let file_path = format!("{}btc.tsv", args.path);
    println!("Database path: {}", file_path);
    let addresses = Arc::new(load_addresses_from_file(&file_path));
    println!("Loaded {} unique addresses.", addresses.len());
    println!("--------------------
");

    let found_flag = Arc::new(AtomicBool::new(false));
    let total_keys = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();

    // --- Thread pool setup ---
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    pool.install(move || {
        (0..u64::MAX).into_par_iter().for_each(|_| {
            if found_flag.load(Ordering::SeqCst) {
                return;
            }

            // --- Stats reporting ---
            let current_total = total_keys.fetch_add(1, Ordering::SeqCst);
            if current_total % 100_000 == 0 && current_total > 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    let rate = current_total as f64 / elapsed;
                    println!(
                        ">>> Total checked: {}. Overall Speed: {:.0} keys/sec.",
                        current_total, rate
                    );
                }
            }
            
            // --- Key generation ---
            let secp = Secp256k1::new();
            let private_key_secp = SecretKey::new(&mut rand::thread_rng());
            let private_key_btc = bitcoin::PrivateKey::new(private_key_secp, Network::Bitcoin);
            let public_key = private_key_btc.public_key(&secp);

            // Generate different address types
            let address_p2pkh = bitcoin::Address::p2pkh(&public_key, Network::Bitcoin);
            let address_p2sh_p2wpkh = bitcoin::Address::p2shwpkh(&public_key, Network::Bitcoin).unwrap();
            let address_p2wpkh = bitcoin::Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
            
            let wif_str = private_key_btc.to_wif();

            // Check for match
            if addresses.contains(&address_p2pkh.to_string()) ||
               addresses.contains(&address_p2sh_p2wpkh.to_string()) ||
               addresses.contains(&address_p2wpkh.to_string())
            {
                if !found_flag.swap(true, Ordering::SeqCst) {
                    println!("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                    println!("!!!!!!!!!! MATCH FOUND !!!!!!!!!!!!!");
                    println!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

                    let found_key = FoundKey {
                        coin: "BTC".to_string(),
                        private_key_hex: private_key_secp.display_secret().to_string(),
                        address: format!("P2PKH: {} | P2SH-P2WPKH: {} | P2WPKH: {}", 
                                         address_p2pkh, address_p2sh_p2wpkh, address_p2wpkh),
                        wif: wif_str,
                    };

                    save_found_key_to_file(&found_key, "found.json").expect("Failed to save found key");
                    println!("Found key details saved to found.json");
                }
            }
        });
    });

    println!("All threads finished.");
}


// --- Function to save found key details to a JSON file ---
fn save_found_key_to_file(found_key: &FoundKey, file_path: &str) -> Result<(), std::io::Error> {
    let json_data = serde_json::to_string_pretty(found_key)?;
    fs::write(file_path, json_data)?;
    Ok(())
}


// --- Function to load addresses from a .tsv file into a HashSet ---
fn load_addresses_from_file(path: &str) -> HashSet<String> {
    let file = File::open(path).expect("Could not open addresses file.");
    let reader = BufReader::new(file);
    let mut addresses = HashSet::new();

    for line in reader.lines() {
        if let Ok(line_content) = line {
            if let Some(address) = line_content.split('\t').next() {
                addresses.insert(address.to_string());
            }
        }
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_save_and_read_found_key() {
        let test_key = FoundKey {
            coin: "BTC".to_string(),
            private_key_hex: "test_private_key_123".to_string(),
            address: "test_address_abc".to_string(),
            wif: "test_wif_xyz".to_string(),
        };
        let test_file_path = "test_found_key.json";

        let _ = fs::remove_file(test_file_path);

        let save_result = save_found_key_to_file(&test_key, test_file_path);
        assert!(save_result.is_ok());

        let mut file = File::open(test_file_path).expect("Test file should exist");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Should be able to read test file");

        let saved_key: FoundKey = serde_json::from_str(&contents).expect("JSON should be valid");
        assert_eq!(test_key, saved_key);

        fs::remove_file(test_file_path).expect("Should be able to clean up test file");
    }

    // New test for generating BTC address:key pairs
    #[test]
    fn test_generate_btc_address_key_pairs() {
        let num_pairs = 5;
        let pairs = generate_btc_address_key_pairs(num_pairs);

        assert_eq!(pairs.len(), num_pairs);

        // Print the first generated pair for manual testing
        if let Some(first_pair) = pairs.first() {
            println!("--- TEST DATA ---");
            println!("Generated Pair: {}", first_pair);
            println!("-----------------");
        }

        for pair_str in pairs {
            let parts: Vec<&str> = pair_str.split(':').collect();
            // Expecting 4 parts: P2PKH:P2SH-P2WPKH:P2WPKH:WIF
            assert_eq!(parts.len(), 4, "Expected 'P2PKH:P2SH-P2WPKH:P2WPKH:WIF' format, got: {}", pair_str);
            
            // Basic check for non-empty address parts and WIF
            assert!(!parts[0].is_empty(), "P2PKH address is empty in: {}", pair_str);
            assert!(!parts[1].is_empty(), "P2SH-P2WPKH address is empty in: {}", pair_str);
            assert!(!parts[2].is_empty(), "P2WPKH address is empty in: {}", pair_str);
            assert!(!parts[3].is_empty(), "WIF is empty in: {}", pair_str);

            // Optionally, add more rigorous checks for address formats
            assert!(parts[0].starts_with('1') || parts[0].starts_with('m') || parts[0].starts_with('n'), "P2PKH address should start with '1', 'm', or 'n': {}", pair_str);
            assert!(parts[1].starts_with('3') || parts[1].starts_with('2'), "P2SH-P2WPKH address should start with '3' or '2': {}", pair_str);
            assert!(parts[2].starts_with("bc1q") || parts[2].starts_with("tb1q"), "P2WPKH address should start with 'bc1q' or 'tb1q': {}", pair_str);
            assert!(parts[3].starts_with('K') || parts[3].starts_with('L') || parts[3].starts_with('c'), "WIF should start with 'K', 'L', or 'c': {}", pair_str);
        }
    }
}

// Helper function to generate BTC address:key pairs for testing
fn generate_btc_address_key_pairs(count: usize) -> Vec<String> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let mut pairs = Vec::with_capacity(count);

    for _ in 0..count {
        let private_key_secp = SecretKey::new(&mut rng);
        let private_key_btc = bitcoin::PrivateKey::new(private_key_secp, Network::Bitcoin);
        let public_key = private_key_btc.public_key(&secp);

        let address_p2pkh = bitcoin::Address::p2pkh(&public_key, Network::Bitcoin);
        let address_p2sh_p2wpkh = bitcoin::Address::p2shwpkh(&public_key, Network::Bitcoin).unwrap();
        let address_p2wpkh = bitcoin::Address::p2wpkh(&public_key, Network::Bitcoin).unwrap();
        
        let wif_str = private_key_btc.to_wif();

        let pair = format!("{}:{}:{}:{}", 
                           address_p2pkh, 
                           address_p2sh_p2wpkh, 
                           address_p2wpkh, 
                           wif_str);
        pairs.push(pair);
    }
    pairs
}
