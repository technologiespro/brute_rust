// Address parsing and hash160 set construction.
//
// The original code compared full address strings. That works but forces the
// GPU to serialise / base58-encode every candidate address, which is wasteful.
//
// Instead we precompute, on the CPU, three hash160 sets from the address
// database:
//
//   * `pubkey_hash160` — the HASH160(compressed_pubkey) of every P2PKH
//     (`1...`) and P2WPKH (`bc1q...`) address. Both address types encode the
//     same 20-byte value, so they share one set.
//   * `script_hash160` — the HASH160(redeem_script) of every P2SH
//     (`3...`) address. For P2SH-P2WPKH the redeem script is
//     `0x00 0x14 || HASH160(compressed_pubkey)`.
//
// On the GPU we then only need to compute those two hash160 values per key
// and check them against these sets on the CPU.

use ahash::AHashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub type Hash160 = [u8; 20];

#[derive(Default)]
pub struct AddressDb {
    pub pubkey_hash160: AHashSet<Hash160>, // matches P2PKH and P2WPKH
    pub script_hash160: AHashSet<Hash160>, // matches P2SH (incl. P2SH-P2WPKH)
    pub all_strings: AHashSet<String>,     // every address as written (CPU path)
}

impl AddressDb {
    pub fn len(&self) -> usize {
        self.all_strings.len()
    }
}

/// Parse a Bitcoin mainnet address into its canonical 20-byte hash and a
/// category tag ("pubkey" or "script").
///
/// Returns `None` for anything we don't recognise (testnet, unknown prefix,
/// invalid checksum, native-segwit v1+ etc.). Those are placed in the
/// `raw_strings` fallback bucket so they still get checked, though obviously
/// they won't ever match a mainnet key.
fn parse_mainnet_address(addr: &str) -> Option<(&'static str, Hash160)> {
    // ---- Base58 addresses: P2PKH (1...) and P2SH (3...) ----
    if addr.starts_with('1') || addr.starts_with('3') {
        let decoded = bs58::decode(addr).with_check(None).into_vec().ok()?;
        if decoded.len() != 21 {
            return None;
        }
        let version = decoded[0];
        let mut h = [0u8; 20];
        h.copy_from_slice(&decoded[1..21]);
        match version {
            0x00 => Some(("pubkey", h)), // P2PKH mainnet
            0x05 => Some(("script", h)), // P2SH mainnet
            _ => None,
        }
    // ---- Bech32 / Bech32m: bc1... ----
    } else if addr.starts_with("bc1") || addr.starts_with("BC1") {
        use bech32::FromBase32;
        let lower = addr.to_ascii_lowercase();
        let (hrp, data, _variant) = match bech32::decode(&lower) {
            Ok(v) => v,
            Err(_) => return None,
        };
        if hrp != "bc" {
            return None;
        }
        // First byte of `data` is the witness version.
        if data.is_empty() {
            return None;
        }
        let witver = u8::from(data[0]);
        // Convert 5-bit groups back to bytes.
        let prog: Vec<u8> = match Vec::<u8>::from_base32(&data[1..]) {
            Ok(v) => v,
            Err(_) => return None,
        };
        if witver == 0 && prog.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&prog);
            Some(("pubkey", h)) // P2WPKH
        } else {
            None // P2WSH (32 bytes) or taproot — not brute-forced here
        }
    } else {
        None
    }
}

pub fn load_addresses_from_file<P: AsRef<Path>>(path: P) -> AddressDb {
    let mut db = AddressDb::default();

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "Could not open addresses file '{}': {}",
                path.as_ref().display(),
                e
            );
            return db;
        }
    };
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let addr = match line.split('\t').next() {
            Some(a) => a.trim(),
            None => continue,
        };
        if addr.is_empty() {
            continue;
        }
        db.all_strings.insert(addr.to_string());
        match parse_mainnet_address(addr) {
            Some(("pubkey", h)) => {
                db.pubkey_hash160.insert(h);
            }
            Some(("script", h)) => {
                db.script_hash160.insert(h);
            }
            _ => {}
        }
    }

    db
}
