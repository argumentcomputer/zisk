use zisk_common::OperationBlake3Data;

/// Input data for one Blake3f compression (v2 API).
///
/// Mirrors `Sha256fInput`'s in-place state pattern. The `cv` field is the
/// chaining value (read on entry, written back on exit). `aux` packs the
/// per-block scalars: `aux[0]` = counter, `aux[1]` = block_len|flags (low 32
/// bits = block_len, high 32 bits = flags). `message` is the 64-byte block.
#[derive(Debug)]
pub struct Blake3fInput {
    pub addr_main: u32,
    pub step_main: u64,
    pub io_addr: u32,
    pub message_addr: u32,
    /// 4 u64s = 8 u32 words of chaining value (read on entry).
    pub cv: [u64; 4],
    /// 2 u64s of per-block scalars: counter, block_len|flags.
    pub aux: [u64; 2],
    /// 8 u64s = 16 u32 words of the 64-byte message block.
    pub message: [u64; 8],
}

/// Bus data layout: 5 (precompiled header) + 2 params + 6 (io: cv+aux) + 8 (message) = 21
pub const OPERATION_BUS_BLAKE3F_DATA_SIZE: usize = 21;

impl Blake3fInput {
    pub fn from(values: &OperationBlake3Data<u64>) -> Self {
        Self {
            addr_main: values[3] as u32,
            step_main: values[4],
            io_addr: values[5] as u32,
            message_addr: values[6] as u32,
            cv: values[7..11].try_into().unwrap(),
            aux: values[11..13].try_into().unwrap(),
            message: values[13..21].try_into().unwrap(),
        }
    }
}
