// ============================================================================
//  brute_rust CUDA kernel — secp256k1 + HASH160 batched brute-force
//  ---------------------------------------------------------------------------
//
//  Compiled at runtime with NVRTC (see src/gpu.rs). No external headers are
//  required; NVRTC provides the CUDA intrinsics (__umul64hi, threadIdx, ...).
//
//  Per-thread work:
//    1. Derive a 256-bit private key from a shared base seed + global tid via
//       SplitMix64 (matches the host derivation in src/gpu.rs::derive_privkey).
//    2. Compute the compressed public key P = k·G, using a precomputed
//       4-bit-window table of multiples of G supplied in global memory.
//    3. Serialise P (33 bytes: parity byte || x-coord BE).
//    4. h1 = HASH160(P)                             — matches P2PKH / P2WPKH.
//    5. h2 = HASH160(0x00 || 0x14 || h1)            — matches P2SH-P2WPKH.
//    6. Write h1, h2 into the output buffers.
//
//  Numerical representation:
//    * 256-bit values are stored as u64[4], little-endian
//      (limb 0 = least significant 64 bits).
//    * The secp256k1 prime is p = 2^256 - C with C = 0x1000003D1, which enables
//      a very cheap reduction: (z_hi·2^256 + z_lo) mod p = z_lo + z_hi·C.
//
//  This is a straightforward "textbook" implementation. It is optimised for
//  clarity and correctness rather than record-breaking throughput; the
//  bottleneck is the per-thread modular inversion inside `to_affine`.
//  Anyone chasing peak performance would batch inversions with Montgomery's
//  trick, but that adds substantial complexity and is left to the user.
// ============================================================================

typedef unsigned long long u64;
typedef unsigned int       u32;
typedef unsigned char      u8;

// -----------------------------------------------------------------------------
// secp256k1 constants
// -----------------------------------------------------------------------------

// p = 2^256 - 0x1000003D1  (little-endian limbs)
__device__ __constant__ u64 P[4] = {
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

// C = 2^256 - p
__device__ __constant__ u64 CVAL = 0x1000003D1ULL;

// p - 2  (used for Fermat's little theorem modular inverse)
__device__ __constant__ u64 P_MINUS_2[4] = {
    0xFFFFFFFEFFFFFC2DULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

// -----------------------------------------------------------------------------
// Tiny helpers
// -----------------------------------------------------------------------------

static __device__ __forceinline__ u64 addc(u64 a, u64 b, u64 *carry) {
    u64 r = a + b;
    u64 c1 = (r < a) ? 1ULL : 0ULL;
    u64 old = r;
    r += *carry;
    u64 c2 = (r < old) ? 1ULL : 0ULL;
    *carry = c1 + c2;
    return r;
}

static __device__ __forceinline__ u64 subb(u64 a, u64 b, u64 *borrow) {
    u64 r = a - b;
    u64 b1 = (r > a) ? 1ULL : 0ULL;
    u64 old = r;
    r -= *borrow;
    u64 b2 = (r > old) ? 1ULL : 0ULL;
    *borrow = b1 + b2;
    return r;
}

static __device__ __forceinline__ void u256_copy(u64 d[4], const u64 s[4]) {
    d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = s[3];
}
static __device__ __forceinline__ int u256_is_zero(const u64 a[4]) {
    return (a[0] | a[1] | a[2] | a[3]) == 0ULL;
}
static __device__ __forceinline__ int u256_eq(const u64 a[4], const u64 b[4]) {
    return (a[0] == b[0]) & (a[1] == b[1]) & (a[2] == b[2]) & (a[3] == b[3]);
}

// -----------------------------------------------------------------------------
// Field arithmetic mod p
// -----------------------------------------------------------------------------

static __device__ void mod_add(u64 r[4], const u64 a[4], const u64 b[4]) {
    u64 c1 = 0;
    u64 s0 = addc(a[0], b[0], &c1);
    u64 s1 = addc(a[1], b[1], &c1);
    u64 s2 = addc(a[2], b[2], &c1);
    u64 s3 = addc(a[3], b[3], &c1);

    // If a+b >= 2^256 (c1==1) or a+b >= p (equivalently: s + C overflows 2^256),
    // subtract p by adding C.
    u64 c2 = 0;
    u64 t0 = addc(s0, CVAL, &c2);
    u64 t1 = addc(s1, 0ULL, &c2);
    u64 t2 = addc(s2, 0ULL, &c2);
    u64 t3 = addc(s3, 0ULL, &c2);

    if (c1 | c2) { r[0]=t0; r[1]=t1; r[2]=t2; r[3]=t3; }
    else         { r[0]=s0; r[1]=s1; r[2]=s2; r[3]=s3; }
}

static __device__ void mod_sub(u64 r[4], const u64 a[4], const u64 b[4]) {
    u64 br = 0;
    u64 s0 = subb(a[0], b[0], &br);
    u64 s1 = subb(a[1], b[1], &br);
    u64 s2 = subb(a[2], b[2], &br);
    u64 s3 = subb(a[3], b[3], &br);
    if (br) {
        // a - b < 0 in integers → add p to normalise. Since p = 2^256 - C, and
        // s already wrapped by +2^256, we just need to subtract C.
        u64 br2 = 0;
        s0 = subb(s0, CVAL, &br2);
        s1 = subb(s1, 0ULL, &br2);
        s2 = subb(s2, 0ULL, &br2);
        s3 = subb(s3, 0ULL, &br2);
    }
    r[0]=s0; r[1]=s1; r[2]=s2; r[3]=s3;
}

// 4x4 → 8-limb schoolbook multiplication.
static __device__ void mul_wide(u64 z[8], const u64 a[4], const u64 b[4]) {
    #pragma unroll
    for (int k = 0; k < 8; k++) z[k] = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        u64 carry = 0;
        #pragma unroll
        for (int j = 0; j < 4; j++) {
            u64 lo = a[i] * b[j];
            u64 hi = __umul64hi(a[i], b[j]);
            u64 old = z[i+j];
            z[i+j] += lo;
            u64 c1 = (z[i+j] < old) ? 1ULL : 0ULL;
            u64 old2 = z[i+j];
            z[i+j] += carry;
            u64 c2 = (z[i+j] < old2) ? 1ULL : 0ULL;
            carry = hi + c1 + c2;
        }
        z[i+4] = carry;
    }
}

// z (8 limbs) mod p → r (4 limbs), exploiting p = 2^256 - C.
static __device__ void mod_reduce_wide(u64 r[4], const u64 z[8]) {
    // First reduction: t = z_lo + z_hi * C  (fits in 5 limbs)
    u64 t[5] = { z[0], z[1], z[2], z[3], 0ULL };

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        u64 mlo = z[4+i] * CVAL;
        u64 mhi = __umul64hi(z[4+i], CVAL);

        // add mlo at t[i]
        u64 old = t[i]; t[i] += mlo;
        u64 c1 = (t[i] < old) ? 1ULL : 0ULL;

        // add mhi + c1 at t[i+1]
        old = t[i+1]; t[i+1] += mhi;
        u64 c2 = (t[i+1] < old) ? 1ULL : 0ULL;
        old = t[i+1]; t[i+1] += c1;
        u64 c3 = (t[i+1] < old) ? 1ULL : 0ULL;
        u64 carry = c2 + c3;

        // propagate remaining carry through t[i+2..4]
        for (int j = i + 2; j <= 4; j++) {
            if (!carry) break;
            u64 o = t[j]; t[j] += carry;
            carry = (t[j] < o) ? 1ULL : 0ULL;
        }
    }

    // Second reduction: fold t[4] * C into t[0..3]. t[4] is tiny (< 2^36).
    u64 f_lo = t[4] * CVAL;
    u64 f_hi = __umul64hi(t[4], CVAL);
    u64 s0 = t[0], s1 = t[1], s2 = t[2], s3 = t[3];

    u64 old = s0; s0 += f_lo;
    u64 c = (s0 < old) ? 1ULL : 0ULL;
    old = s1; s1 += f_hi;
    u64 c1 = (s1 < old) ? 1ULL : 0ULL;
    old = s1; s1 += c;
    u64 c2 = (s1 < old) ? 1ULL : 0ULL;
    u64 propagate = c1 + c2;
    old = s2; s2 += propagate;
    u64 c3 = (s2 < old) ? 1ULL : 0ULL;
    old = s3; s3 += c3;
    u64 overflow = (s3 < old) ? 1ULL : 0ULL;

    // Final normalisation: if overflow or s >= p, subtract p (add C).
    u64 uc = 0;
    u64 u0 = addc(s0, CVAL, &uc);
    u64 u1 = addc(s1, 0ULL, &uc);
    u64 u2 = addc(s2, 0ULL, &uc);
    u64 u3 = addc(s3, 0ULL, &uc);
    if (overflow | uc) { r[0]=u0; r[1]=u1; r[2]=u2; r[3]=u3; }
    else               { r[0]=s0; r[1]=s1; r[2]=s2; r[3]=s3; }
}

static __device__ __forceinline__ void mod_mul(u64 r[4], const u64 a[4], const u64 b[4]) {
    u64 z[8];
    mul_wide(z, a, b);
    mod_reduce_wide(r, z);
}

static __device__ __forceinline__ void mod_sqr(u64 r[4], const u64 a[4]) {
    // TODO: a dedicated squaring would be ~30% faster; use mul for simplicity.
    mod_mul(r, a, a);
}

// r = a^(p-2) mod p (Fermat's little theorem, non-constant-time).
static __device__ void mod_inv(u64 r[4], const u64 a[4]) {
    u64 acc[4]; u256_copy(acc, a);       // MSB of p-2 is 1, so seed acc = a.
    const u64 *e = P_MINUS_2;

    for (int bit = 254; bit >= 0; bit--) {
        u64 tmp[4]; mod_sqr(tmp, acc);
        if ((e[bit >> 6] >> (bit & 63)) & 1ULL) {
            mod_mul(acc, tmp, a);
        } else {
            u256_copy(acc, tmp);
        }
    }
    u256_copy(r, acc);
}

// -----------------------------------------------------------------------------
// Elliptic curve arithmetic (Jacobian coordinates, a = 0)
// -----------------------------------------------------------------------------

struct PointJ {
    u64 X[4];
    u64 Y[4];
    u64 Z[4];
};

static __device__ __forceinline__ void point_set_infinity(PointJ *p) {
    p->X[0]=1; p->X[1]=0; p->X[2]=0; p->X[3]=0;
    p->Y[0]=1; p->Y[1]=0; p->Y[2]=0; p->Y[3]=0;
    p->Z[0]=0; p->Z[1]=0; p->Z[2]=0; p->Z[3]=0;
}

static __device__ __forceinline__ int point_is_infinity(const PointJ *p) {
    return u256_is_zero(p->Z);
}

// Point doubling: R = 2*P, using formula "dbl-2009-l" (a=0 case).
static __device__ void point_double(PointJ *r, const PointJ *p) {
    if (point_is_infinity(p)) { *r = *p; return; }

    u64 A[4], B[4], C[4], D[4], E[4], F[4], tmp[4], tmp2[4];
    mod_sqr(A, p->X);                    // A = X^2
    mod_sqr(B, p->Y);                    // B = Y^2
    mod_sqr(C, B);                       // C = B^2
    mod_add(tmp, p->X, B);               // tmp = X + B
    mod_sqr(tmp, tmp);                   // tmp = (X + B)^2
    mod_sub(tmp, tmp, A);                // tmp -= A
    mod_sub(tmp, tmp, C);                // tmp -= C
    mod_add(D, tmp, tmp);                // D = 2 * tmp
    mod_add(E, A, A);                    // E = 2A
    mod_add(E, E, A);                    // E = 3A
    mod_sqr(F, E);                       // F = E^2
    mod_add(tmp, D, D);                  // tmp = 2D
    mod_sub(r->X, F, tmp);               // X3 = F - 2D
    mod_sub(tmp, D, r->X);               // tmp = D - X3
    mod_mul(tmp, E, tmp);                // tmp = E*(D - X3)
    mod_add(tmp2, C, C);                 // tmp2 = 2C
    mod_add(tmp2, tmp2, tmp2);           // 4C
    mod_add(tmp2, tmp2, tmp2);           // 8C
    mod_sub(r->Y, tmp, tmp2);            // Y3 = E*(D-X3) - 8C
    mod_mul(tmp, p->Y, p->Z);            // Y*Z
    mod_add(r->Z, tmp, tmp);             // Z3 = 2*Y*Z
}

// Mixed addition (Z2 = 1). R = P + Q, where Q is affine (Q.X, Q.Y).
// Formula "madd-2007-bl". Handles P == infinity and P == Q (doubling) cases.
static __device__ void point_add_mixed(PointJ *r, const PointJ *p,
                                       const u64 qx[4], const u64 qy[4]) {
    if (point_is_infinity(p)) {
        u256_copy(r->X, qx);
        u256_copy(r->Y, qy);
        r->Z[0]=1; r->Z[1]=0; r->Z[2]=0; r->Z[3]=0;
        return;
    }

    u64 Z1Z1[4], U2[4], S2[4], H[4], HH[4], I[4], J[4], rr[4], V[4];
    u64 tmp[4];

    mod_sqr(Z1Z1, p->Z);                 // Z1^2
    mod_mul(U2, qx, Z1Z1);               // U2 = X2 * Z1^2
    mod_mul(tmp, qy, p->Z);              // Y2 * Z1
    mod_mul(S2, tmp, Z1Z1);              // S2 = Y2 * Z1^3
    mod_sub(H, U2, p->X);                // H = U2 - X1

    // Detect the doubling / point-at-infinity cases.
    u64 rdiff[4];
    mod_sub(rdiff, S2, p->Y);            // r' = S2 - Y1
    if (u256_is_zero(H)) {
        if (u256_is_zero(rdiff)) {
            point_double(r, p);          // P == Q → doubling
        } else {
            point_set_infinity(r);       // P == -Q → infinity
        }
        return;
    }

    mod_sqr(HH, H);                      // HH = H^2
    mod_add(I, HH, HH); mod_add(I, I, I);// I = 4*HH
    mod_mul(J, H, I);                    // J = H*I
    mod_add(rr, rdiff, rdiff);           // r = 2*(S2 - Y1)
    mod_mul(V, p->X, I);                 // V = X1 * I

    mod_sqr(tmp, rr);                    // r^2
    mod_sub(tmp, tmp, J);                // r^2 - J
    u64 twoV[4]; mod_add(twoV, V, V);
    mod_sub(r->X, tmp, twoV);            // X3 = r^2 - J - 2V

    mod_sub(tmp, V, r->X);               // V - X3
    mod_mul(tmp, rr, tmp);               // r*(V - X3)
    u64 y1J[4]; mod_mul(y1J, p->Y, J);
    mod_add(y1J, y1J, y1J);              // 2*Y1*J
    mod_sub(r->Y, tmp, y1J);             // Y3 = r*(V - X3) - 2*Y1*J

    mod_add(tmp, p->Z, H);               // Z1 + H
    mod_sqr(tmp, tmp);                   // (Z1 + H)^2
    mod_sub(tmp, tmp, Z1Z1);
    mod_sub(r->Z, tmp, HH);              // Z3 = (Z1+H)^2 - Z1Z1 - HH
}

// Convert Jacobian (X, Y, Z) → affine (x, y). Costs 1 inv + 3 muls + 1 sqr.
static __device__ void point_to_affine(u64 x[4], u64 y[4], const PointJ *p) {
    u64 Zi[4], Zi2[4], Zi3[4];
    mod_inv(Zi, p->Z);
    mod_sqr(Zi2, Zi);
    mod_mul(Zi3, Zi2, Zi);
    mod_mul(x, p->X, Zi2);
    mod_mul(y, p->Y, Zi3);
}

// -----------------------------------------------------------------------------
// Scalar multiplication using precomputed 4-bit-window table of G
// -----------------------------------------------------------------------------
//
// Table layout matches src/precompute.rs::GTable:
//   table_x / table_y are flat arrays of size 64 * 15 * 4 u64 each.
//   Entry (window i, digit k with 1 <= k <= 15) is at
//   offset (i * 15 + (k - 1)) * 4 limbs, little-endian.
//
// The private key is decomposed into 64 4-bit digits d_0 .. d_63 with
//   k = Σ d_i * 16^i.
// P = k*G = Σ d_i * (16^i * G) = Σ table[i][d_i - 1] (skipping d_i == 0).

static __device__ void scalar_mul_g(PointJ *r, const u64 k[4],
                                    const u64 *table_x,
                                    const u64 *table_y) {
    point_set_infinity(r);

    // 64 nibbles, low-nibble first (matches little-endian limb order).
    #pragma unroll 1
    for (int i = 0; i < 64; i++) {
        u32 limb_idx = i >> 4;                  // which u64 holds this nibble
        u32 nibble_shift = ((u32)i & 0xF) << 2; // 0, 4, 8, ..., 60
        u32 digit = (u32)((k[limb_idx] >> nibble_shift) & 0xFULL);
        if (digit == 0) continue;

        // Fetch table[i][digit-1]
        u64 qx[4], qy[4];
        u32 off = (u32)(i * 15 + (digit - 1)) * 4;
        qx[0] = table_x[off + 0];
        qx[1] = table_x[off + 1];
        qx[2] = table_x[off + 2];
        qx[3] = table_x[off + 3];
        qy[0] = table_y[off + 0];
        qy[1] = table_y[off + 1];
        qy[2] = table_y[off + 2];
        qy[3] = table_y[off + 3];

        PointJ tmp;
        point_add_mixed(&tmp, r, qx, qy);
        *r = tmp;
    }
}

// -----------------------------------------------------------------------------
// PRNG (SplitMix64) — must exactly match src/gpu.rs::derive_privkey.
// -----------------------------------------------------------------------------

static __device__ __forceinline__ u64 splitmix64_step(u64 *state) {
    *state += 0x9E3779B97F4A7C15ULL;
    u64 z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Derive a 256-bit private key from (base_seed, tid). Matches host code.
static __device__ void derive_privkey(u64 out[4], const u64 base_seed[4], u64 tid) {
    u64 state = base_seed[0] ^ tid;
    out[0] = splitmix64_step(&state);
    state ^= base_seed[1];
    out[1] = splitmix64_step(&state);
    state ^= base_seed[2];
    out[2] = splitmix64_step(&state);
    state ^= base_seed[3];
    out[3] = splitmix64_step(&state);
    // If by astronomical chance we drew 0, bump to 1. Doing this uniformly
    // does not detectably change the distribution.
    if (u256_is_zero(out)) out[0] = 1;
}

// -----------------------------------------------------------------------------
// SHA-256 (single 64-byte block, message length ≤ 55 bytes)
// -----------------------------------------------------------------------------

static __device__ __constant__ u32 SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static __device__ __forceinline__ u32 rotr32(u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }

// Compute SHA-256 of `msg` (len ≤ 55 bytes). Writes 32 output bytes (big-endian).
static __device__ void sha256_short(u8 out[32], const u8 *msg, u32 len) {
    // Prepare padded 64-byte block, big-endian message words.
    u8 block[64];
    #pragma unroll
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (u32 i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    u64 bits = (u64)len * 8ULL;
    // 8-byte big-endian length at the end
    block[56] = (u8)(bits >> 56);
    block[57] = (u8)(bits >> 48);
    block[58] = (u8)(bits >> 40);
    block[59] = (u8)(bits >> 32);
    block[60] = (u8)(bits >> 24);
    block[61] = (u8)(bits >> 16);
    block[62] = (u8)(bits >> 8);
    block[63] = (u8)(bits);

    u32 W[64];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        W[i] = ((u32)block[i*4] << 24) | ((u32)block[i*4+1] << 16) |
               ((u32)block[i*4+2] << 8)|  (u32)block[i*4+3];
    }
    #pragma unroll
    for (int i = 16; i < 64; i++) {
        u32 s0 = rotr32(W[i-15], 7)  ^ rotr32(W[i-15], 18) ^ (W[i-15] >> 3);
        u32 s1 = rotr32(W[i-2], 17)  ^ rotr32(W[i-2],  19) ^ (W[i-2]  >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    u32 a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    u32 e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        u32 S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        u32 ch = (e & f) ^ ((~e) & g);
        u32 t1 = h + S1 + ch + SHA256_K[i] + W[i];
        u32 S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        u32 mj = (a & b) ^ (a & c) ^ (b & c);
        u32 t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    u32 H0 = 0x6a09e667 + a, H1 = 0xbb67ae85 + b, H2 = 0x3c6ef372 + c, H3 = 0xa54ff53a + d;
    u32 H4 = 0x510e527f + e, H5 = 0x9b05688c + f, H6 = 0x1f83d9ab + g, H7 = 0x5be0cd19 + h;

    #define STORE_BE(dst, v) do { \
        (dst)[0] = (u8)((v) >> 24); (dst)[1] = (u8)((v) >> 16); \
        (dst)[2] = (u8)((v) >> 8);  (dst)[3] = (u8)(v);         \
    } while (0)
    STORE_BE(out +  0, H0); STORE_BE(out +  4, H1);
    STORE_BE(out +  8, H2); STORE_BE(out + 12, H3);
    STORE_BE(out + 16, H4); STORE_BE(out + 20, H5);
    STORE_BE(out + 24, H6); STORE_BE(out + 28, H7);
    #undef STORE_BE
}

// -----------------------------------------------------------------------------
// RIPEMD-160 (single 64-byte block, message length ≤ 55 bytes)
// -----------------------------------------------------------------------------

static __device__ __forceinline__ u32 rotl32(u32 x, u32 n) { return (x << n) | (x >> (32 - n)); }

// f, g, h, i, j round functions
static __device__ __forceinline__ u32 rmd_f(int j, u32 x, u32 y, u32 z) {
    if (j < 16)      return x ^ y ^ z;
    else if (j < 32) return (x & y) | ((~x) & z);
    else if (j < 48) return (x | (~y)) ^ z;
    else if (j < 64) return (x & z) | (y & (~z));
    else             return x ^ (y | (~z));
}

// K constants (left / right lines)
static __device__ __constant__ u32 RMD_KL[5] = {
    0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
};
static __device__ __constant__ u32 RMD_KR[5] = {
    0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
};

// Message word ordering (left)
static __device__ __constant__ u8 RMD_RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
static __device__ __constant__ u8 RMD_RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};

// Left rotations (left)
static __device__ __constant__ u8 RMD_SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
static __device__ __constant__ u8 RMD_SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

// Compute RIPEMD-160 of `msg` (len ≤ 55 bytes). Writes 20 output bytes (little-endian words).
static __device__ void ripemd160_short(u8 out[20], const u8 *msg, u32 len) {
    u8 block[64];
    #pragma unroll
    for (int i = 0; i < 64; i++) block[i] = 0;
    for (u32 i = 0; i < len; i++) block[i] = msg[i];
    block[len] = 0x80;
    u64 bits = (u64)len * 8ULL;
    // 8-byte little-endian length
    block[56] = (u8)(bits);
    block[57] = (u8)(bits >> 8);
    block[58] = (u8)(bits >> 16);
    block[59] = (u8)(bits >> 24);
    block[60] = (u8)(bits >> 32);
    block[61] = (u8)(bits >> 40);
    block[62] = (u8)(bits >> 48);
    block[63] = (u8)(bits >> 56);

    u32 X[16];
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        X[i] = (u32)block[i*4]        | ((u32)block[i*4+1] << 8) |
              ((u32)block[i*4+2] << 16) | ((u32)block[i*4+3] << 24);
    }

    u32 al = 0x67452301, bl = 0xefcdab89, cl = 0x98badcfe, dl = 0x10325476, el = 0xc3d2e1f0;
    u32 ar = al, br = bl, cr = cl, dr = dl, er = el;

    #pragma unroll 1
    for (int j = 0; j < 80; j++) {
        // Left line
        u32 tl = al + rmd_f(j, bl, cl, dl) + X[RMD_RL[j]] + RMD_KL[j / 16];
        tl = rotl32(tl, RMD_SL[j]) + el;
        al = el; el = dl; dl = rotl32(cl, 10); cl = bl; bl = tl;

        // Right line (uses 79 - j indexing for round function)
        u32 tr = ar + rmd_f(79 - j, br, cr, dr) + X[RMD_RR[j]] + RMD_KR[j / 16];
        tr = rotl32(tr, RMD_SR[j]) + er;
        ar = er; er = dr; dr = rotl32(cr, 10); cr = br; br = tr;
    }

    // Standard RIPEMD-160 single-block final combining step (h0..h4 on the
    // right are the initial values before this block).
    //   T    := h1 + Cl + Dr
    //   h1   := h2 + Dl + Er
    //   h2   := h3 + El + Ar
    //   h3   := h4 + Al + Br
    //   h4   := h0 + Bl + Cr
    //   h0   := T
    u32 out0 = 0xefcdab89 + cl + dr;
    u32 out1 = 0x98badcfe + dl + er;
    u32 out2 = 0x10325476 + el + ar;
    u32 out3 = 0xc3d2e1f0 + al + br;
    u32 out4 = 0x67452301 + bl + cr;

    #define STORE_LE(dst, v) do { \
        (dst)[0] = (u8)(v);        (dst)[1] = (u8)((v) >> 8);  \
        (dst)[2] = (u8)((v) >> 16);(dst)[3] = (u8)((v) >> 24); \
    } while (0)
    STORE_LE(out +  0, out0);
    STORE_LE(out +  4, out1);
    STORE_LE(out +  8, out2);
    STORE_LE(out + 12, out3);
    STORE_LE(out + 16, out4);
    #undef STORE_LE
}

// HASH160(x) = RIPEMD160(SHA256(x)).
static __device__ __forceinline__ void hash160(u8 out[20], const u8 *msg, u32 len) {
    u8 sha[32];
    sha256_short(sha, msg, len);
    ripemd160_short(out, sha, 32);
}

// -----------------------------------------------------------------------------
// Kernel
// -----------------------------------------------------------------------------

extern "C" __global__ void brute_kernel(
        const u64 *base_seed,      // 4 u64s
        const u64 *table_x,        // 64*15*4 u64s
        const u64 *table_y,        // 64*15*4 u64s
        u8        *h1_out,         // batch_size * 20 bytes
        u8        *h2_out,         // batch_size * 20 bytes
        u32        batch_size)
{
    u64 tid = (u64)blockIdx.x * (u64)blockDim.x + (u64)threadIdx.x;
    if (tid >= (u64)batch_size) return;

    // 1) Derive private key
    u64 k[4];
    derive_privkey(k, base_seed, tid);

    // 2) P = k*G in Jacobian coords, then convert to affine
    PointJ P; scalar_mul_g(&P, k, table_x, table_y);
    if (point_is_infinity(&P)) {
        // Vanishingly unlikely, but be defensive: write zeros.
        for (int i = 0; i < 20; i++) { h1_out[tid*20 + i] = 0; h2_out[tid*20 + i] = 0; }
        return;
    }
    u64 ax[4], ay[4];
    point_to_affine(ax, ay, &P);

    // 3) Compressed pubkey = (0x02 | 0x03) || X (32 bytes BE)
    u8 pub[33];
    pub[0] = 0x02 | ((u8)(ay[0] & 1ULL));
    // Serialise ax (little-endian limbs) as 32 bytes big-endian into pub[1..33]
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        u64 limb = ax[3 - i];
        pub[1 + i*8 + 0] = (u8)(limb >> 56);
        pub[1 + i*8 + 1] = (u8)(limb >> 48);
        pub[1 + i*8 + 2] = (u8)(limb >> 40);
        pub[1 + i*8 + 3] = (u8)(limb >> 32);
        pub[1 + i*8 + 4] = (u8)(limb >> 24);
        pub[1 + i*8 + 5] = (u8)(limb >> 16);
        pub[1 + i*8 + 6] = (u8)(limb >> 8);
        pub[1 + i*8 + 7] = (u8)(limb);
    }

    // 4) h1 = HASH160(pub)                                — P2PKH / P2WPKH
    u8 h1[20];
    hash160(h1, pub, 33);

    // 5) h2 = HASH160(0x00 || 0x14 || h1)                 — P2SH-P2WPKH
    u8 script[22];
    script[0] = 0x00;
    script[1] = 0x14;
    #pragma unroll
    for (int i = 0; i < 20; i++) script[2 + i] = h1[i];
    u8 h2[20];
    hash160(h2, script, 22);

    // 6) Write outputs
    u64 base = tid * 20ULL;
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        h1_out[base + i] = h1[i];
        h2_out[base + i] = h2[i];
    }
}
