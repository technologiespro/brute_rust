// Precompute an affine multiples-of-G lookup table for use by the CUDA kernel.
//
// We use 4-bit windows: 64 windows × 15 non-zero entries. Entry (i, k)
// (0 ≤ i < 64, 1 ≤ k ≤ 15) stores the affine point `k · 16^i · G`, so that
// any private key can be reconstructed by summing at most 64 mixed point
// additions:
//
//     P = Σ_i table[i][ nibble_i(privkey) - 1 ]     (skipping zero nibbles)
//
// Total size:  64 * 15 * 64 bytes = 60 KiB. Fits comfortably in device memory
// (and is small enough for the read-only cache to keep hot).
//
// We generate the table on the host with the well-tested `secp256k1` crate,
// which spares the GPU kernel from having to bootstrap itself.

use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub const WINDOWS: usize = 64; // 256 / 4
pub const ENTRIES_PER_WINDOW: usize = 15; // k = 1..=15
pub const LIMBS: usize = 4; // 256-bit x/y coordinates as u64[4] little-endian

/// Precomputed table stored as two flat u64 slices (X and Y coordinates).
/// Layout: `[window_0_k1, window_0_k2, ..., window_63_k15]`, each element
/// being 4 u64 limbs in **little-endian** order (limb 0 = least significant).
pub struct GTable {
    pub x: Vec<u64>, // length = WINDOWS * ENTRIES_PER_WINDOW * LIMBS
    pub y: Vec<u64>,
}

impl GTable {
    pub fn build() -> Self {
        let secp = Secp256k1::new();

        // Build once, then repeatedly double / add. Since we only need a small
        // fixed number of points and cargo-secp256k1 is fast, we compute each
        // entry independently by scalar mul k · 16^i · G. This costs ~1000
        // scalar multiplications — done in ~100 ms once at startup.
        let mut x = vec![0u64; WINDOWS * ENTRIES_PER_WINDOW * LIMBS];
        let mut y = vec![0u64; WINDOWS * ENTRIES_PER_WINDOW * LIMBS];

        for i in 0..WINDOWS {
            for k in 1..=ENTRIES_PER_WINDOW {
                // scalar = k << (4 * i)   (as a 256-bit big-endian integer)
                let mut scalar = [0u8; 32];
                let bit_pos = 4 * i;
                let byte_pos_be = 31 - (bit_pos / 8); // little-endian byte -> big-endian index
                let shift = bit_pos % 8;
                // k fits in 4 bits, shift ≤ 4 → result fits in one byte at
                // position byte_pos_be, possibly spilling into byte_pos_be - 1
                // when shift + 4 > 8 (never happens here since shift ∈ {0,4}
                // and k ≤ 15).
                debug_assert!(shift + 4 <= 8);
                scalar[byte_pos_be] = (k as u8) << shift;

                let sk = SecretKey::from_slice(&scalar).expect("valid scalar");
                let pk = PublicKey::from_secret_key(&secp, &sk);
                // Uncompressed serialisation: 0x04 || X (32 bytes BE) || Y (32 bytes BE)
                let ser = pk.serialize_uncompressed();
                debug_assert_eq!(ser[0], 0x04);
                let x_be: &[u8; 32] = ser[1..33].try_into().unwrap();
                let y_be: &[u8; 32] = ser[33..65].try_into().unwrap();

                let base = (i * ENTRIES_PER_WINDOW + (k - 1)) * LIMBS;
                be32_to_limbs_le(x_be, &mut x[base..base + LIMBS]);
                be32_to_limbs_le(y_be, &mut y[base..base + LIMBS]);
            }
        }

        // Silence unused-import warnings when the `cuda` feature is disabled.
        let _ = &secp;

        GTable { x, y }
    }
}

/// Convert a big-endian 32-byte scalar/coordinate into 4 little-endian u64 limbs.
/// limb[0] holds the least significant 64 bits.
pub fn be32_to_limbs_le(be: &[u8; 32], out: &mut [u64]) {
    debug_assert_eq!(out.len(), 4);
    for i in 0..4 {
        // Least significant limb = last 8 bytes of the BE representation.
        let start = 32 - 8 * (i + 1);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&be[start..start + 8]);
        out[i] = u64::from_be_bytes(buf);
    }
}
