/// Rotation constants for Blake3 G function (32-bit)
const R1: u32 = 16;
const R2: u32 = 12;
const R3: u32 = 8;
const R4: u32 = 7;

/// BLAKE3 round function
///
/// Performs one round of Blake3 mixing on the 16-word state using message words.
/// The caller is responsible for applying the message permutation between rounds.
/// The `_round` parameter is accepted for API compatibility with the syscall interface
/// but is unused — the message should already be permuted by the caller.
pub fn blake3_round(v: &mut [u32; 16], m: &[u32; 16], _round: u32) {
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

/// G mixing function for Blake3 (32-bit version)
#[allow(clippy::too_many_arguments)]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    let mut va = v[a];
    let mut vb = v[b];
    let mut vc = v[c];
    let mut vd = v[d];

    va = va.wrapping_add(vb).wrapping_add(x);
    vd = (vd ^ va).rotate_right(R1);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(R2);

    va = va.wrapping_add(vb).wrapping_add(y);
    vd = (vd ^ va).rotate_right(R3);
    vc = vc.wrapping_add(vd);
    vb = (vb ^ vc).rotate_right(R4);

    v[a] = va;
    v[b] = vb;
    v[c] = vc;
    v[d] = vd;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Blake3 constants (duplicated here for self-contained tests) ──

    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];
    const MSG_PERMUTATION: [usize; 16] =
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    const ROUNDS: u32 = 7;
    const CHUNK_START: u32 = 1;
    const CHUNK_END: u32 = 2;
    const PARENT: u32 = 4;
    const ROOT: u32 = 8;

    // ── Standalone compress / hash built on top of blake3_round ──

    fn compress(
        chaining_value: &[u32; 8],
        block_words: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 8] {
        let mut state: [u32; 16] = [
            chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
            chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
            IV[0], IV[1], IV[2], IV[3],
            counter as u32, (counter >> 32) as u32, block_len, flags,
        ];
        let mut msg = *block_words;
        for round in 0..ROUNDS {
            blake3_round(&mut state, &msg, round);
            if round < ROUNDS - 1 {
                let mut permuted = [0u32; 16];
                for i in 0..16 {
                    permuted[i] = msg[MSG_PERMUTATION[i]];
                }
                msg = permuted;
            }
        }
        let mut output = [0u32; 8];
        for i in 0..8 {
            output[i] = state[i] ^ state[i + 8];
        }
        output
    }

    fn compress_chunk(chunk: &[u8], counter: u64, is_root: bool) -> [u32; 8] {
        let chunk_len = chunk.len();
        let num_blocks = if chunk_len == 0 { 1 } else { (chunk_len + 63) / 64 };
        let mut cv = IV;
        for block_idx in 0..num_blocks {
            let offset = block_idx * 64;
            let remaining = chunk_len.saturating_sub(offset);
            let block_len = remaining.min(64);
            let mut block = [0u8; 64];
            if block_len > 0 {
                block[..block_len].copy_from_slice(&chunk[offset..offset + block_len]);
            }
            let mut block_words = [0u32; 16];
            for i in 0..16 {
                block_words[i] = u32::from_le_bytes([
                    block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3],
                ]);
            }
            let mut flags = 0u32;
            if block_idx == 0 { flags |= CHUNK_START; }
            if block_idx == num_blocks - 1 {
                flags |= CHUNK_END;
                if is_root { flags |= ROOT; }
            }
            cv = compress(&cv, &block_words, counter, block_len as u32, flags);
        }
        cv
    }

    fn compress_parent(left: &[u32; 8], right: &[u32; 8], is_root: bool) -> [u32; 8] {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(left);
        block_words[8..].copy_from_slice(right);
        let mut flags = PARENT;
        if is_root { flags |= ROOT; }
        compress(&IV, &block_words, 0, 64, flags)
    }

    fn blake3_hash(input: &[u8]) -> [u8; 32] {
        let input_len = input.len();
        let mut chunk_cvs: Vec<[u32; 8]> = Vec::new();
        let num_chunks = if input_len == 0 { 1 } else { (input_len + 1023) / 1024 };
        for chunk_idx in 0..num_chunks {
            let chunk_start = chunk_idx * 1024;
            let chunk_end = (chunk_start + 1024).min(input_len);
            let chunk = if chunk_start < input_len {
                &input[chunk_start..chunk_end]
            } else {
                &[] as &[u8]
            };
            let is_root = num_chunks == 1;
            chunk_cvs.push(compress_chunk(chunk, chunk_idx as u64, is_root));
        }
        while chunk_cvs.len() > 1 {
            let mut parent_cvs = Vec::new();
            let mut i = 0;
            while i + 1 < chunk_cvs.len() {
                let is_root = chunk_cvs.len() == 2 && i == 0;
                parent_cvs.push(compress_parent(&chunk_cvs[i], &chunk_cvs[i + 1], is_root));
                i += 2;
            }
            if i < chunk_cvs.len() {
                parent_cvs.push(chunk_cvs[i]);
            }
            chunk_cvs = parent_cvs;
        }
        let cv = chunk_cvs[0];
        let mut hash = [0u8; 32];
        for i in 0..8 {
            let bytes = cv[i].to_le_bytes();
            hash[4 * i..4 * i + 4].copy_from_slice(&bytes);
        }
        hash
    }

    /// Generate the standard BLAKE3 test input: repeating 0, 1, 2, ..., 250, 0, 1, ...
    fn test_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // ── Round-level tests ──

    #[test]
    fn test_blake3_round_zero() {
        let mut state = [0u32; 16];
        let message = [0u32; 16];
        blake3_round(&mut state, &message, 0);
        assert_eq!(state, [0u32; 16]);
    }

    #[test]
    fn test_blake3_round_nonzero() {
        let mut state = [1u32; 16];
        let message = [2u32; 16];
        blake3_round(&mut state, &message, 0);
        assert_ne!(state, [1u32; 16]);
    }

    #[test]
    fn test_g_function_rotation_constants() {
        // Verify the G function produces correct output for a known simple case.
        // Single G call on indices (0,4,8,12) with specific values.
        let mut v = [0u32; 16];
        v[0] = 1; v[4] = 2; v[8] = 3; v[12] = 4;
        g(&mut v, 0, 4, 8, 12, 5, 6);

        // Manually compute expected:
        // First half:
        //   a = 1 + 2 + 5 = 8
        //   d = (4 ^ 8).rotate_right(16) = 12.rotate_right(16) = 0x000C0000
        let a1 = 1u32.wrapping_add(2).wrapping_add(5);
        let d1 = (4u32 ^ a1).rotate_right(16);
        let c1 = 3u32.wrapping_add(d1);
        let b1 = (2u32 ^ c1).rotate_right(12);
        // Second half:
        let a2 = a1.wrapping_add(b1).wrapping_add(6);
        let d2 = (d1 ^ a2).rotate_right(8);
        let c2 = c1.wrapping_add(d2);
        let b2 = (b1 ^ c2).rotate_right(7);

        assert_eq!(v[0], a2);
        assert_eq!(v[4], b2);
        assert_eq!(v[8], c2);
        assert_eq!(v[12], d2);
    }

    // ── Compression function tests ──

    #[test]
    fn test_compress_single_block_empty() {
        // Compressing empty input: block_len=0, flags=CHUNK_START|CHUNK_END|ROOT
        let block_words = [0u32; 16];
        let flags = CHUNK_START | CHUNK_END | ROOT;
        let result = compress(&IV, &block_words, 0, 0, flags);
        // Just check it doesn't panic and produces a deterministic result
        let result2 = compress(&IV, &block_words, 0, 0, flags);
        assert_eq!(result, result2);
        // The result should not be all zeros (IV is non-zero)
        assert_ne!(result, [0u32; 8]);
    }

    #[test]
    fn test_compress_deterministic() {
        let block_words: [u32; 16] = core::array::from_fn(|i| i as u32);
        let r1 = compress(&IV, &block_words, 0, 64, CHUNK_START | CHUNK_END | ROOT);
        let r2 = compress(&IV, &block_words, 0, 64, CHUNK_START | CHUNK_END | ROOT);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_compress_different_flags_differ() {
        let block_words: [u32; 16] = core::array::from_fn(|i| i as u32);
        let r1 = compress(&IV, &block_words, 0, 64, CHUNK_START);
        let r2 = compress(&IV, &block_words, 0, 64, CHUNK_END);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compress_different_counters_differ() {
        let block_words: [u32; 16] = core::array::from_fn(|i| i as u32);
        let flags = CHUNK_START | CHUNK_END | ROOT;
        let r1 = compress(&IV, &block_words, 0, 64, flags);
        let r2 = compress(&IV, &block_words, 1, 64, flags);
        assert_ne!(r1, r2);
    }

    // ── Official BLAKE3 test vectors (from BLAKE3 reference test suite) ──
    // Input pattern: repeating 0, 1, 2, ..., 250, 0, 1, ...
    // We test the "hash" mode only (not keyed_hash or derive_key).
    // Expected values are the first 32 bytes (default output length).

    #[test]
    fn test_official_vector_empty() {
        let input = test_input(0);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_official_vector_1_byte() {
        let input = test_input(1);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );
    }

    #[test]
    fn test_official_vector_2_bytes() {
        let input = test_input(2);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63"
        );
    }

    #[test]
    fn test_official_vector_3_bytes() {
        let input = test_input(3);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f"
        );
    }

    #[test]
    fn test_official_vector_4_bytes() {
        let input = test_input(4);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32"
        );
    }

    #[test]
    fn test_official_vector_5_bytes() {
        let input = test_input(5);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2"
        );
    }

    #[test]
    fn test_official_vector_6_bytes() {
        let input = test_input(6);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844"
        );
    }

    #[test]
    fn test_official_vector_7_bytes() {
        let input = test_input(7);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe"
        );
    }

    #[test]
    fn test_official_vector_8_bytes() {
        let input = test_input(8);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb"
        );
    }

    #[test]
    fn test_official_vector_63_bytes() {
        let input = test_input(63);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"
        );
    }

    #[test]
    fn test_official_vector_64_bytes() {
        // Exactly one full block
        let input = test_input(64);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"
        );
    }

    #[test]
    fn test_official_vector_65_bytes() {
        // Two blocks in one chunk
        let input = test_input(65);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"
        );
    }

    #[test]
    fn test_official_vector_127_bytes() {
        let input = test_input(127);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d"
        );
    }

    #[test]
    fn test_official_vector_128_bytes() {
        // Two full blocks in one chunk
        let input = test_input(128);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef"
        );
    }

    #[test]
    fn test_official_vector_129_bytes() {
        let input = test_input(129);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12"
        );
    }

    #[test]
    fn test_official_vector_1023_bytes() {
        // Just under one full chunk
        let input = test_input(1023);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"
        );
    }

    #[test]
    fn test_official_vector_1024_bytes() {
        // Exactly one full chunk
        let input = test_input(1024);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        );
    }

    #[test]
    fn test_official_vector_1025_bytes() {
        // Two chunks — exercises tree hashing
        let input = test_input(1025);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"
        );
    }

    #[test]
    fn test_official_vector_2048_bytes() {
        // Two full chunks
        let input = test_input(2048);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"
        );
    }

    #[test]
    fn test_official_vector_2049_bytes() {
        // Three chunks — exercises tree hashing with odd count
        let input = test_input(2049);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783a"
                [..64], // first 32 bytes
        );
    }

    #[test]
    fn test_official_vector_3072_bytes() {
        // Three full chunks
        let input = test_input(3072);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"
        );
    }

    #[test]
    fn test_official_vector_3073_bytes() {
        // Four chunks — balanced binary tree
        let input = test_input(3073);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3"
        );
    }

    #[test]
    fn test_official_vector_4096_bytes() {
        // Four full chunks
        let input = test_input(4096);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969"
        );
    }

    #[test]
    fn test_official_vector_4097_bytes() {
        // Five chunks
        let input = test_input(4097);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995"
        );
    }

    #[test]
    fn test_official_vector_5120_bytes() {
        // Five full chunks
        let input = test_input(5120);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833"
        );
    }

    #[test]
    fn test_official_vector_5121_bytes() {
        let input = test_input(5121);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"
        );
    }

    #[test]
    fn test_official_vector_6144_bytes() {
        // Six full chunks
        let input = test_input(6144);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205"
        );
    }

    #[test]
    fn test_official_vector_6145_bytes() {
        let input = test_input(6145);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f"
        );
    }

    #[test]
    fn test_official_vector_7168_bytes() {
        // Seven full chunks
        let input = test_input(7168);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a"
        );
    }

    // ── Reference stack-based algorithm (mirrors the BLAKE3 spec exactly) ──
    // Key difference from naive pairwise: the last chunk is NOT pushed through
    // add_chunk_chaining_value. Instead it's finalized separately, merging with
    // the stack from right to left, with ROOT applied only on the final merge.

    fn blake3_hash_ref(input: &[u8]) -> [u8; 32] {
        let input_len = input.len();
        let num_chunks = if input_len == 0 { 1 } else { (input_len + 1023) / 1024 };

        // Single chunk: compress as root directly
        if num_chunks == 1 {
            let chunk = if input_len > 0 { input } else { &[] as &[u8] };
            let cv = compress_chunk(chunk, 0, true);
            return cv_to_bytes(&cv);
        }

        let mut cv_stack: Vec<[u32; 8]> = Vec::new();

        // Process all chunks except the last through the stack
        for chunk_idx in 0..num_chunks - 1 {
            let chunk_start = chunk_idx * 1024;
            let chunk_end = (chunk_start + 1024).min(input_len);
            let chunk = &input[chunk_start..chunk_end];
            let new_cv = compress_chunk(chunk, chunk_idx as u64, false);

            // add_chunk_chaining_value: merge based on trailing zero bits
            let mut total_chunks = (chunk_idx + 1) as u64;
            let mut cv = new_cv;
            while total_chunks & 1 == 0 {
                let left = cv_stack.pop().unwrap();
                cv = compress_parent(&left, &cv, false);
                total_chunks >>= 1;
            }
            cv_stack.push(cv);
        }

        // Process the last chunk (not through add_chunk_chaining_value)
        let last_start = (num_chunks - 1) * 1024;
        let last_end = input_len.min(last_start + 1024);
        let last_chunk = &input[last_start..last_end];
        let mut right_cv = compress_chunk(last_chunk, (num_chunks - 1) as u64, false);

        // Finalize: merge stack CVs with last chunk's CV from right to left
        while let Some(left_cv) = cv_stack.pop() {
            let is_root = cv_stack.is_empty();
            right_cv = compress_parent(&left_cv, &right_cv, is_root);
        }

        cv_to_bytes(&right_cv)
    }

    fn cv_to_bytes(cv: &[u32; 8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for i in 0..8 {
            hash[4 * i..4 * i + 4].copy_from_slice(&cv[i].to_le_bytes());
        }
        hash
    }

    // ── Cross-check both tree approaches against the blake3 crate ──

    #[test]
    fn test_cross_check_against_blake3_crate() {
        for &len in &[0, 1, 63, 64, 65, 127, 128, 129,
                      1023, 1024, 1025, 2048, 2049,
                      3072, 3073, 4096, 4097, 5120, 5121,
                      6144, 6145, 7168, 8192, 16384] {
            let input = test_input(len);
            let crate_hash: [u8; 32] = blake3::hash(&input).into();

            let ref_hash = blake3_hash_ref(&input);
            assert_eq!(
                ref_hash, crate_hash,
                "blake3_hash_ref mismatch at len={}: got={} expected={}",
                len, hex(&ref_hash), hex(&crate_hash)
            );

            let pairwise_hash = blake3_hash(&input);
            assert_eq!(
                pairwise_hash, crate_hash,
                "blake3_hash (pairwise) mismatch at len={}: got={} expected={}",
                len, hex(&pairwise_hash), hex(&crate_hash)
            );
        }
    }

    #[test]
    fn test_official_vector_8192_bytes() {
        // Eight full chunks — 3-level tree
        let input = test_input(8192);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"
        );
    }

    #[test]
    fn test_official_vector_16384_bytes() {
        // 16 chunks — 4-level tree
        let input = test_input(16384);
        let hash = blake3_hash(&input);
        assert_eq!(
            hex(&hash),
            "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4"
        );
    }

    // ── Message permutation test ──

    #[test]
    fn test_message_permutation() {
        let m: [u32; 16] = core::array::from_fn(|i| i as u32);
        let mut permuted = [0u32; 16];
        for i in 0..16 {
            permuted[i] = m[MSG_PERMUTATION[i]];
        }
        assert_eq!(
            permuted,
            [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
        );
    }

    #[test]
    fn test_compress_empty_block() {
        let block_words = [0u32; 16];
        let flags = CHUNK_START | CHUNK_END | ROOT;
        let result = compress(&IV, &block_words, 0, 0, flags);
        let mut hash = [0u8; 32];
        for i in 0..8 {
            hash[4 * i..4 * i + 4].copy_from_slice(&result[i].to_le_bytes());
        }
        assert_eq!(
            hex(&hash),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    // ── Edge cases ──

    #[test]
    fn test_single_byte_chunks() {
        for len in 0..=8 {
            let input = test_input(len);
            let hash = blake3_hash(&input);
            assert_eq!(hash.len(), 32);
            if len > 0 {
                assert_ne!(hash, [0u8; 32]);
            }
        }
    }

    #[test]
    fn test_chunk_boundary_1024() {
        let hash_1023 = blake3_hash(&test_input(1023));
        let hash_1024 = blake3_hash(&test_input(1024));
        let hash_1025 = blake3_hash(&test_input(1025));
        assert_ne!(hash_1023, hash_1024);
        assert_ne!(hash_1024, hash_1025);
        assert_ne!(hash_1023, hash_1025);
    }

    #[test]
    fn test_parent_compression() {
        let left = IV;
        let right: [u32; 8] = core::array::from_fn(|i| (i + 1) as u32);
        let parent_cv = compress_parent(&left, &right, false);
        let root_cv = compress_parent(&left, &right, true);
        assert_ne!(parent_cv, root_cv);
    }
}
