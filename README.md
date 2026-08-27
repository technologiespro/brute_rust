# Bitcoin Private Key Brute-Forcer in Rust (v0.2 - CUDA)

A high-speed utility for brute-forcing Bitcoin private keys and searching for matches against a database of addresses. In v0.2, a fully GPU-accelerated (CUDA) execution path has been introduced.

## Features

- **CUDA Acceleration** - key generation (`secp256k1`), compressed public key serialization, and HASH160 computation are performed entirely on the GPU in a custom kernel (see `src/kernel.cu`). The kernel is compiled on-the-fly via NVRTC, so invoking `nvcc` separately is not required.
- **CPU Fallback** - the original multi-threaded CPU mode is preserved and can be enabled with the `--cpu-only` flag (or automatically if the GPU fails to initialize).
- **Fast Lookup** - addresses from the database are parsed into `hash160` sets (for P2PKH/P2WPKH and P2SH-P2WPKH). Instead of parsing strings on every attempt, a fast lookup against a 20-byte key is performed.
- **All three address types** are checked simultaneously:
  - P2PKH (`1...`)
  - P2SH-P2WPKH (`3...`)
  - P2WPKH (`bc1q...`)

## Requirements

| Component | Version |
|-----------|--------|
| Rust      | stable ≥ 1.74 |
| CUDA Toolkit | 13.0+ (feature `cuda-13000`; see `Cargo.toml` if an older version is needed) |
| NVIDIA driver | compatible with the installed Toolkit |
| GPU | any NVIDIA GPU with Compute Capability ≥ 6.0 |

## Build

```sh
cd brute_rust
cargo build --release
```

The executable will be located at `target/release/brute_rust[.exe]`.

If you want to build the **CPU-only version without CUDA** (e.g., on a machine without the CUDA Toolkit):

```sh
cargo build --release --no-default-features
```

The resulting binary will automatically default to the CPU execution path.

## Usage

GPU is used by default:

```sh
target/release/brute_rust --path ../addrs/
```

### Arguments

| Flag | Default | Description |
|------|--------------|----------|
| `--path <PATH>` | `../addrs/` | Directory containing the `btc.tsv` file. |
| `--gpu-id <N>` | `0` | CUDA device index. |
| `--batch <N>` | `1048576` | Number of keys per GPU kernel launch. Increase for powerful GPUs (RTX 4090 / A100: 2–4M), decrease for weaker ones. |
| `--cpu-only` | `false` | Do not use GPU, run on CPU only. |
| `--cpu <N>` | `0` (= all) | Number of threads in CPU mode. |

### Examples

- **GPU, device 0, batch 1M:**
  ```sh
  target/release/brute_rust
  ```
- **GPU device 1, batch 4M:**
  ```sh
  target/release/brute_rust --gpu-id 1 --batch 4194304
  ```
- **CPU only, 4 threads:**
  ```sh
  target/release/brute_rust --cpu-only --cpu 4
  ```

## How it works on the GPU

1. At startup, the CPU builds a precomputed table of multiples of the base point `G`: 64 windows of 15 entries each in the form `k · 16^i · G` in affine coordinates (60 KiB). This table is copied to the GPU once (see `src/precompute.rs`).
2. For each batch, the CPU generates a 256-bit "base seed" and launches the `brute_kernel` with `batch_size` threads.
3. Each thread:
    - derives its private key from `(base_seed, thread_id)` via SplitMix64 (the same implementation exists on the CPU in `src/gpu.rs`, allowing deterministic key recovery upon a match);
    - computes `P = k · G` in Jacobian coordinates by summing the required points from the precomputed table (64 mixed-additions);
    - converts `P` to affine coordinates (modular inversion via Fermat's Little Theorem) and serializes the compressed public key (33 bytes);
    - computes `h1 = HASH160(pubkey)` and `h2 = HASH160(0x00 || 0x14 || h1)` - these are the hash160 values for P2PKH/P2WPKH and P2SH-P2WPKH, respectively;
    - writes `h1` and `h2` to the output buffers.
4. The CPU receives 40 MB of data back (20 bytes per key for each type) and checks them against an `AHashSet<[u8; 20]>`. Upon a match, the private key is deterministically recovered by `thread_id`, and all three addresses plus the WIF are reliably reconstructed using the `secp256k1` crate for logging into `found.json`.

## Found Keys

Upon a match, the program writes `found.json` in the current directory with the following fields:

- `coin` - always `"BTC"` in this version.
- `matched_type` - which address type matched (`P2PKH/P2WPKH` or `P2SH-P2WPKH`).
- `private_key_hex` - private key in HEX format.
- `wif` - private key in WIF format.
- `address` - all three generated addresses.

## Performance Notes

- `src/kernel.cu` is written in a straightforward manner for clarity. The most expensive operation is the modular inversion during the Jacobian → affine conversion (~256 modmuls per thread). On an RTX 3060, expect a few million keys per second; on an RTX 4090, significantly more.
- A significant speedup can be achieved by **batching inversions using Montgomery's trick** (one inversion per 32–256 keys instead of one per key). If desired, this can be added to `to_affine` and the corresponding step in `scalar_mul_g`.
- If your address database is empty after parsing (`AddressDb` shows 0 addresses), check the format of `btc.tsv`: the first column of each row must be the address itself, separated by a tab.


