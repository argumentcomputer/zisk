use crate::zisklib;

use anyhow::Result;

/// Processes an `HINT_BLAKE3` hint.
///
/// Mirrors `sha256_hint` and `keccak256_hint`: the payload is the raw input
/// bytes (variable length), and the handler runs the full `zisklib::blake3`
/// hash internally. Per-block-compression cv values accumulate in the `hints`
/// Vec via the syscall path inside `zisklib::blake3`.
#[inline]
pub fn blake3_hint(data: &[u64], data_len_bytes: usize) -> Result<Vec<u64>> {
    let data_len_words = data_len_bytes.div_ceil(8);

    if data.len() != data_len_words {
        anyhow::bail!(
            "HINT_BLAKE3: expected data length of {} bytes ({} words), got {} words",
            data_len_bytes,
            data_len_words,
            data.len()
        );
    }

    let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data_len_bytes) };

    let mut hints = Vec::new();
    zisklib::blake3(bytes, &mut hints);

    Ok(hints)
}
