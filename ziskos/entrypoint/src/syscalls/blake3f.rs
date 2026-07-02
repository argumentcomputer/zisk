//! Blake3 compression function (Blake3f) system call.
//!
//! Performs one Blake3 block compression in a single syscall, including the
//! XOR feed-forward (`h[i] = state[i] ^ state[i+8]`) inside the precompile.
//!
//! API mirrors `syscall_sha256_f`'s in-place state update pattern. The cv +
//! per-block scalars (counter / block_len / flags) are combined into one
//! `Blake3Io` struct so the syscall has only two indirections (io and
//! message), matching how sha256f arranges its (state, input) indirections.
//! The `chaining_value` field of `io` is updated in place by the precompile.

#[cfg(zisk_guest)]
use core::arch::asm;

#[cfg(zisk_guest)]
use crate::ziskos_syscall;

#[cfg(not(zisk_guest))]
use precompiles_helpers::blake3_round;

/// Combined input/output struct for one Blake3 block compression.
///
/// Layout (48 bytes, 8-byte aligned):
///   bytes  0..32 : chaining_value (8 × u32 = 4 u64s) — RW (updated in place)
///   bytes 32..40 : counter (u64) — R
///   bytes 40..48 : block_len_and_flags (u64) — R
///                  low 32 bits = block_len, high 32 bits = flags
///
/// The guest typically declares one `Blake3Io` per chunk, initializes
/// `chaining_value = IV`, then in a loop updates `counter` /
/// `block_len_and_flags` and calls the syscall. The cv flows from one call to
/// the next via the in-place update — no extra copies needed.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(8))]
pub struct Blake3Io {
    pub chaining_value: [u32; 8],
    pub counter: u64,
    pub block_len_and_flags: u64,
}

impl Blake3Io {
    /// Pack `block_len` (low 32 bits) and `flags` (high 32 bits) into a u64.
    ///
    /// Per the Blake3 spec, `block_len` is a byte count in `[0, 64]` and
    /// `flags` is an 8-bit bitfield (CHUNK_START | CHUNK_END | PARENT | ROOT |
    /// KEYED_HASH | DERIVE_KEY_CONTEXT | DERIVE_KEY_MATERIAL). Out-of-spec
    /// values are accepted by the precompile and produce a deterministic but
    /// non-standard hash; the debug asserts here catch likely bugs in non-
    /// release builds without affecting release performance.
    #[inline(always)]
    pub fn pack_block_len_and_flags(block_len: u32, flags: u32) -> u64 {
        debug_assert!(block_len <= 64, "Blake3 block_len must be <= 64, got {block_len}");
        debug_assert!(flags < 256, "Blake3 flags must fit in 8 bits, got {flags:#x}");
        (block_len as u64) | ((flags as u64) << 32)
    }
}

/// Parameters for the Blake3f syscall.
///
/// `io` carries the cv (in-place RW) plus the per-block scalars. `message` is
/// the 64-byte block, passed as a raw `[u64; 8]` slice cast — both x86 and
/// RISC-V are little-endian, so byte order matches Blake3's spec of LE u32
/// message words.
#[derive(Debug)]
#[repr(C)]
pub struct SyscallBlake3Params<'a> {
    pub io: &'a mut Blake3Io,
    pub message: &'a [u64; 8],
}

/// Executes one Blake3 block compression.
///
/// ### Safety
///
/// The caller must ensure that `io` and `message` are aligned to a 64-bit
/// boundary. The `message` slice's underlying bytes are reinterpreted as
/// little-endian u32 words by the precompile.
///
/// The caller must ensure that `io.block_len_and_flags` packs a `block_len` in
/// `[0, 64]` (low 32 bits) and a Blake3 flag bitfield in `[0, 256)` (high 32
/// bits). The PIL constraints accept any 64-bit value here and faithfully
/// compute the compression with whatever scalars are provided; out-of-spec
/// values produce a deterministic but non-standard hash. Use
/// [`Blake3Io::pack_block_len_and_flags`] which debug-asserts the
/// bounds, or check at the call site.
#[allow(unused_variables)]
#[cfg_attr(not(feature = "hints"), no_mangle)]
#[cfg_attr(feature = "hints", export_name = "hints_syscall_blake3_f")]
pub extern "C" fn syscall_blake3_f(
    params: &mut SyscallBlake3Params,
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) {
    #[cfg(zisk_guest)]
    ziskos_syscall!(zisk_definitions::SYSCALL_BLAKE3F_ID, params);

    #[cfg(not(zisk_guest))]
    {
        blake3_compress_software(params.io, params.message);

        #[cfg(feature = "hints")]
        {
            // Hint: updated chaining_value (4 u64s reinterpreted from [u32; 8])
            let cv_64: &[u64; 4] = unsafe {
                &*(params.io.chaining_value.as_ptr() as *const [u64; 4])
            };
            hints.extend_from_slice(cv_64);
        }
    }
}

/// Blake3 IV (same as SHA-256 first 8 primes).
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[cfg(not(zisk_guest))]
fn blake3_compress_software(io: &mut Blake3Io, message: &[u64; 8]) {
    // Unpack message (8 u64s) → 16 u32 message words.
    let mut block_words = [0u32; 16];
    for i in 0..8 {
        block_words[2 * i] = message[i] as u32;
        block_words[2 * i + 1] = (message[i] >> 32) as u32;
    }

    let counter_lo = io.counter as u32;
    let counter_hi = (io.counter >> 32) as u32;
    let block_len = io.block_len_and_flags as u32;
    let flags = (io.block_len_and_flags >> 32) as u32;

    // Build the 16-word initial state.
    let cv = io.chaining_value;
    let mut state: [u32; 16] = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_lo,
        counter_hi,
        block_len,
        flags,
    ];

    // 7 rounds + message permutation.
    let mut msg = block_words;
    for round in 0..7u32 {
        blake3_round(&mut state, &msg, round);
        if round < 6 {
            let mut permuted = [0u32; 16];
            for i in 0..16 {
                permuted[i] = msg[MSG_PERMUTATION[i]];
            }
            msg = permuted;
        }
    }

    // XOR feed-forward — update chaining_value in place.
    for i in 0..8 {
        io.chaining_value[i] = state[i] ^ state[i + 8];
    }
}
