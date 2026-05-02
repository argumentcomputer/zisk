#include "blake3.hpp"

/// Rotation constants for Blake3 G function (32-bit)
static const uint32_t R1 = 16;
static const uint32_t R2 = 12;
static const uint32_t R3 = 8;
static const uint32_t R4 = 7;

static inline uint32_t rotate_right_32(uint32_t x, unsigned int n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

/// G mixing function for Blake3 (32-bit)
static inline void g(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y) {
    uint32_t va = v[a];
    uint32_t vb = v[b];
    uint32_t vc = v[c];
    uint32_t vd = v[d];

    va = va + vb + x;
    vd = rotate_right_32(vd ^ va, R1);
    vc = vc + vd;
    vb = rotate_right_32(vb ^ vc, R2);

    va = va + vb + y;
    vd = rotate_right_32(vd ^ va, R3);
    vc = vc + vd;
    vb = rotate_right_32(vb ^ vc, R4);

    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

/// BLAKE3 round function: one round = 8 G-function calls.
/// The caller is responsible for applying message permutation between rounds.
void blake3_round(uint32_t v[16], const uint32_t m[16], uint32_t round) {
    (void)round; // unused — message already permuted by caller

    // Column step
    g(v, 0, 4, 8, 12, m[0], m[1]);
    g(v, 1, 5, 9, 13, m[2], m[3]);
    g(v, 2, 6, 10, 14, m[4], m[5]);
    g(v, 3, 7, 11, 15, m[6], m[7]);

    // Diagonal step
    g(v, 0, 5, 10, 15, m[8], m[9]);
    g(v, 1, 6, 11, 12, m[10], m[11]);
    g(v, 2, 7, 8, 13, m[12], m[13]);
    g(v, 3, 4, 9, 14, m[14], m[15]);
}

static const int MSG_PERMUTATION[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

/// Blake3 IV (same as SHA-256 first 8 primes).
static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// Full Blake3 block compression with XOR feed-forward (v2 API).
///
/// `cv` is updated in place. The 16-word state is constructed internally from
/// cv + IV + counter + block_len + flags, then 7 rounds of mixing are applied,
/// then the XOR feed-forward `cv[i] = state[i] ^ state[i+8]` is written back.
void blake3_compress(uint64_t cv[4], const uint64_t message[8], const uint64_t aux[2]) {
    // Unpack cv (4 u64s) into 8 u32 chaining_value words.
    uint32_t cv_u32[8];
    for (int i = 0; i < 4; i++) {
        cv_u32[2 * i]     = (uint32_t) cv[i];
        cv_u32[2 * i + 1] = (uint32_t)(cv[i] >> 32);
    }

    // Unpack message (8 u64s) into 16 u32 message words.
    uint32_t block_words[16];
    for (int i = 0; i < 8; i++) {
        block_words[2 * i]     = (uint32_t) message[i];
        block_words[2 * i + 1] = (uint32_t)(message[i] >> 32);
    }

    uint32_t counter_lo = (uint32_t) aux[0];
    uint32_t counter_hi = (uint32_t)(aux[0] >> 32);
    uint32_t block_len  = (uint32_t) aux[1];
    uint32_t flags      = (uint32_t)(aux[1] >> 32);

    // Build the 16-word initial state.
    uint32_t state[16] = {
        cv_u32[0], cv_u32[1], cv_u32[2], cv_u32[3],
        cv_u32[4], cv_u32[5], cv_u32[6], cv_u32[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_lo, counter_hi, block_len, flags,
    };

    // 7 rounds + message permutation between rounds.
    uint32_t msg[16];
    for (int i = 0; i < 16; i++) msg[i] = block_words[i];

    for (int round = 0; round < 7; round++) {
        blake3_round(state, msg, round);
        if (round < 6) {
            uint32_t permuted[16];
            for (int i = 0; i < 16; i++) {
                permuted[i] = msg[MSG_PERMUTATION[i]];
            }
            for (int i = 0; i < 16; i++) msg[i] = permuted[i];
        }
    }

    // XOR feed-forward — pack new cv back into 4 u64s.
    for (int i = 0; i < 4; i++) {
        uint32_t lo = state[2 * i]     ^ state[2 * i + 8];
        uint32_t hi = state[2 * i + 1] ^ state[2 * i + 1 + 8];
        cv[i] = ((uint64_t) lo) | (((uint64_t) hi) << 32);
    }
}
