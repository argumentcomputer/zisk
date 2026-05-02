use precompiles_common::MemBusHelpers;
use precompiles_common::MemProcessor;

use zisk_common::OPERATION_PRECOMPILED_BUS_DATA_SIZE;
use zisk_core::blake3f;

use crate::blake3f_constants::{
    PARAMS, PARAM_CHUNKS_AUX, PARAM_CHUNKS_CV, PARAM_CHUNKS_IO, PARAM_CHUNKS_MESSAGE,
    PARAM_CHUNKS_OUTPUT_CV,
};

/// Generate memory bus inputs for one Blake3f compression (v2 API).
///
/// Memory access map (mirrors sha256f):
///   * 2 indirect parameter reads (io_addr, message_addr)
///   * 4 reads of cv at io_addr+0..32          (chaining_value)
///   * 2 reads of aux at io_addr+32..48        (counter, block_len_and_flags)
///   * 8 reads of message at message_addr+0..64
///   * 4 writes of new cv at io_addr+0..32     (in-place feed-forward output)
///
/// Total: 20 memory operations per compression (down from 26 in v1).
pub fn generate_blake3f_mem_inputs<P: MemProcessor>(
    addr_main: u32,
    step_main: u64,
    data: &[u64],
    only_counters: bool,
    mem_processors: &mut P,
) {
    // Bus data layout: [op, op_type, a, b, step, io_addr, message_addr, cv[0..4], aux[0..2], message[0..8]]
    // Indices:           0    1      2  3   4    5         6              7..11      11..13     13..21

    // Read indirect param pointers (io_addr, message_addr).
    for iparam in 0..PARAMS {
        MemBusHelpers::mem_aligned_read(
            addr_main + iparam as u32 * 8,
            step_main,
            data[OPERATION_PRECOMPILED_BUS_DATA_SIZE + iparam],
            mem_processors,
        );
    }

    let io_addr = data[OPERATION_PRECOMPILED_BUS_DATA_SIZE] as u32;
    let message_addr = data[OPERATION_PRECOMPILED_BUS_DATA_SIZE + 1] as u32;

    let cv_offset = OPERATION_PRECOMPILED_BUS_DATA_SIZE + PARAMS;
    let aux_offset = cv_offset + PARAM_CHUNKS_CV;
    let message_offset = aux_offset + PARAM_CHUNKS_AUX;

    // Read cv (4 u64s) from io_addr+0..32.
    for i in 0..PARAM_CHUNKS_CV {
        MemBusHelpers::mem_aligned_read(
            io_addr + i as u32 * 8,
            step_main,
            data[cv_offset + i],
            mem_processors,
        );
    }

    // Read aux (2 u64s) from io_addr+32..48.
    for i in 0..PARAM_CHUNKS_AUX {
        MemBusHelpers::mem_aligned_read(
            io_addr + (PARAM_CHUNKS_CV + i) as u32 * 8,
            step_main,
            data[aux_offset + i],
            mem_processors,
        );
    }

    // Read message (8 u64s) from message_addr+0..64.
    for i in 0..PARAM_CHUNKS_MESSAGE {
        MemBusHelpers::mem_aligned_read(
            message_addr + i as u32 * 8,
            step_main,
            data[message_offset + i],
            mem_processors,
        );
    }

    // Run the Blake3 compression in software to derive the new cv (the value
    // that will be written back to memory).
    let mut new_cv = [0u64; 4];
    if !only_counters {
        new_cv.copy_from_slice(&data[cv_offset..cv_offset + PARAM_CHUNKS_CV]);
        let message: [u64; 8] = data[message_offset..message_offset + PARAM_CHUNKS_MESSAGE]
            .try_into()
            .unwrap();
        let aux: [u64; 2] =
            data[aux_offset..aux_offset + PARAM_CHUNKS_AUX].try_into().unwrap();
        blake3f(&mut new_cv, &message, &aux);
    }

    // Write back the new cv (4 u64s) to io_addr+0..32.
    for i in 0..PARAM_CHUNKS_OUTPUT_CV {
        MemBusHelpers::mem_aligned_write(
            io_addr + i as u32 * 8,
            step_main,
            new_cv[i],
            mem_processors,
        );
    }

    // Suppress unused-import warnings if PARAM_CHUNKS_IO isn't used directly.
    let _ = PARAM_CHUNKS_IO;
}

/// Skip predicate: return true if all addresses touched by this compression
/// are already known to the memory processor.
pub fn skip_blake3f_mem_inputs<P: MemProcessor>(
    addr_main: u32,
    data: &[u64],
    mem_processors: &mut P,
) -> bool {
    // Indirect params
    for iparam in 0..PARAMS {
        let addr = addr_main + iparam as u32 * 8;
        if !mem_processors.skip_addr(addr) {
            return false;
        }
    }

    let io_addr = data[OPERATION_PRECOMPILED_BUS_DATA_SIZE] as u32;
    let message_addr = data[OPERATION_PRECOMPILED_BUS_DATA_SIZE + 1] as u32;

    // io reads (cv + aux = 6 u64s)
    for i in 0..PARAM_CHUNKS_IO {
        if !mem_processors.skip_addr(io_addr + i as u32 * 8) {
            return false;
        }
    }

    // message reads
    for i in 0..PARAM_CHUNKS_MESSAGE {
        if !mem_processors.skip_addr(message_addr + i as u32 * 8) {
            return false;
        }
    }

    // cv writeback (overlaps with cv reads at io_addr+0..32)
    for i in 0..PARAM_CHUNKS_OUTPUT_CV {
        if !mem_processors.skip_addr(io_addr + i as u32 * 8) {
            return false;
        }
    }

    true
}
