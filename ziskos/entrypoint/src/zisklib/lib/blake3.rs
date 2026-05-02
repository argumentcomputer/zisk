use crate::syscalls::{syscall_blake3_f, Blake3Io, SyscallBlake3Params};

use super::is_aligned_8;

/// Blake3 initialization vectors (same as SHA-256 first 8 primes)
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// Blake3 domain separation flags
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;

/// Blake3 hash function. Hashes arbitrary-length input and returns a 32-byte
/// digest. Implements the full Blake3 algorithm including multi-chunk tree
/// hashing. Reference: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
pub fn blake3(input: &[u8], #[cfg(feature = "hints")] hints: &mut Vec<u64>) -> [u8; 32] {
    let input_len = input.len();

    // Split input into 1024-byte chunks and compute chaining values
    let mut chunk_cvs: Vec<[u32; 8]> = Vec::new();
    let num_chunks = if input_len == 0 { 1 } else { (input_len + 1023) / 1024 };

    for chunk_idx in 0..num_chunks {
        let chunk_start = chunk_idx * 1024;
        let chunk_end = (chunk_start + 1024).min(input_len);
        let chunk = if chunk_start < input_len { &input[chunk_start..chunk_end] } else { &[] as &[u8] };

        let is_root = num_chunks == 1;
        let cv = compress_chunk(
            chunk,
            chunk_idx as u64,
            is_root,
            #[cfg(feature = "hints")]
            hints,
        );
        chunk_cvs.push(cv);
    }

    // Tree hashing: combine chaining values pairwise until one root remains
    while chunk_cvs.len() > 1 {
        let mut parent_cvs = Vec::new();
        let mut i = 0;
        while i + 1 < chunk_cvs.len() {
            let is_root = chunk_cvs.len() == 2 && i == 0;
            let cv = compress_parent(
                &chunk_cvs[i],
                &chunk_cvs[i + 1],
                is_root,
                #[cfg(feature = "hints")]
                hints,
            );
            parent_cvs.push(cv);
            i += 2;
        }
        // If odd number of CVs, carry the last one up
        if i < chunk_cvs.len() {
            parent_cvs.push(chunk_cvs[i]);
        }
        chunk_cvs = parent_cvs;
    }

    // Convert root CV to bytes (little-endian)
    let cv = chunk_cvs[0];
    let mut hash = [0u8; 32];
    for i in 0..8 {
        let bytes = cv[i].to_le_bytes();
        hash[4 * i..4 * i + 4].copy_from_slice(&bytes);
    }
    hash
}

/// Compress a single chunk (up to 1024 bytes = 16 blocks) into a chaining value.
///
/// Maintains a single `Blake3Io` across all blocks of the chunk so the
/// chaining value flows from one block to the next via in-place update — no
/// per-block copies needed. Mirrors `compress_block` in `sha256.rs`.
fn compress_chunk(
    chunk: &[u8],
    counter: u64,
    is_root: bool,
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) -> [u32; 8] {
    let chunk_len = chunk.len();
    let num_blocks = if chunk_len == 0 { 1 } else { (chunk_len + 63) / 64 };

    let mut io = Blake3Io {
        chaining_value: IV,
        counter,
        block_len_and_flags: 0,
    };

    for block_idx in 0..num_blocks {
        let offset = block_idx * 64;
        let remaining = chunk_len.saturating_sub(offset);
        let block_len = remaining.min(64) as u32;

        let mut flags = 0u32;
        if block_idx == 0 {
            flags |= CHUNK_START;
        }
        if block_idx == num_blocks - 1 {
            flags |= CHUNK_END;
            if is_root {
                flags |= ROOT;
            }
        }

        io.block_len_and_flags = Blake3Io::pack_block_len_and_flags(block_len, flags);

        compress_one_block(
            &mut io,
            if offset < chunk_len { &chunk[offset..(offset + block_len as usize).min(chunk_len)] } else { &[] },
            #[cfg(feature = "hints")]
            hints,
        );
    }

    io.chaining_value
}

/// Compress two child chaining values into a parent chaining value.
fn compress_parent(
    left: &[u32; 8],
    right: &[u32; 8],
    is_root: bool,
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) -> [u32; 8] {
    // Parent block = left_cv || right_cv (16 u32 words = 64 bytes).
    let mut block_bytes = [0u8; 64];
    for i in 0..8 {
        block_bytes[4 * i..4 * i + 4].copy_from_slice(&left[i].to_le_bytes());
    }
    for i in 0..8 {
        block_bytes[32 + 4 * i..32 + 4 * i + 4].copy_from_slice(&right[i].to_le_bytes());
    }

    let mut flags = PARENT;
    if is_root {
        flags |= ROOT;
    }

    // Parents start from IV, counter = 0, block_len = 64.
    let mut io = Blake3Io {
        chaining_value: IV,
        counter: 0,
        block_len_and_flags: Blake3Io::pack_block_len_and_flags(64, flags),
    };

    compress_one_block(
        &mut io,
        &block_bytes,
        #[cfg(feature = "hints")]
        hints,
    );

    io.chaining_value
}

/// Issue one Blake3 compression syscall.
///
/// `io` already holds the cv + scalars. `block` is the raw 64-byte (or
/// shorter) block payload. The fast path slice-casts the block bytes directly
/// to `&[u64; 8]`; the slow path copies them into an aligned stack buffer
/// first. After the syscall, `io.chaining_value` holds the new cv.
#[inline]
fn compress_one_block(
    io: &mut Blake3Io,
    block: &[u8],
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) {
    debug_assert!(block.len() <= 64);

    if block.len() == 64 && is_aligned_8(block.as_ptr()) {
        let message_64: &[u64; 8] = unsafe { &*(block.as_ptr() as *const [u64; 8]) };
        let mut params = SyscallBlake3Params { io, message: message_64 };
        syscall_blake3_f(
            &mut params,
            #[cfg(feature = "hints")]
            hints,
        );
        return;
    }

    // Slow path: partial or unaligned block — copy into an aligned buffer.
    let mut padded = [0u8; 64];
    padded[..block.len()].copy_from_slice(block);
    let message_64: &[u64; 8] = unsafe { &*(padded.as_ptr() as *const [u64; 8]) };
    let mut params = SyscallBlake3Params { io, message: message_64 };
    syscall_blake3_f(
        &mut params,
        #[cfg(feature = "hints")]
        hints,
    );
}

/// C-compatible wrapper for full Blake3 hash.
///
/// # Safety
/// - `input` must point to at least `input_len` bytes
/// - `output` must point to a writable buffer of at least 32 bytes
#[cfg_attr(not(feature = "hints"), no_mangle)]
#[cfg_attr(feature = "hints", export_name = "hints_blake3_c")]
pub unsafe extern "C" fn blake3_c(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    #[cfg(feature = "hints")] hints: &mut Vec<u64>,
) {
    let input_slice = core::slice::from_raw_parts(input, input_len);
    let hash = blake3(
        input_slice,
        #[cfg(feature = "hints")]
        hints,
    );
    let output_slice = core::slice::from_raw_parts_mut(output, 32);
    output_slice.copy_from_slice(&hash);
}
