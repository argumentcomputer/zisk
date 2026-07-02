#ifndef LIB_C_BLAKE3_HPP
#define LIB_C_BLAKE3_HPP

#include <stdint.h> // uint32_t, uint64_t

#ifdef __cplusplus
extern "C" {
#endif

// Blake3 round function (one round of 8 G-function calls).
void blake3_round(uint32_t v[16], const uint32_t m[16], uint32_t round);

// Full Blake3 block compression with XOR feed-forward (v2 API).
//
// Mirrors `sha256f`'s in-place state update pattern. The cv (8 u32s = 4 u64s)
// is updated in place. The aux (counter, block_len|flags) and message (8 u64s
// = 64 raw bytes) are read-only. After the call, cv contains the new chaining
// value (post-XOR-feed-forward).
//
// `aux` is a 2-u64 array: aux[0] = counter, aux[1] = block_len in low 32 bits
// and flags in high 32 bits.
void blake3_compress(uint64_t cv[4], const uint64_t message[8], const uint64_t aux[2]);

#ifdef __cplusplus
}
#endif

#endif // LIB_C_BLAKE3_HPP
