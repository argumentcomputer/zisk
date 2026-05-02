use sha2::compress256;

#[allow(deprecated)]
use sha2::digest::generic_array::{typenum::U64, GenericArray};

use precompiles_helpers::blake2b_round;

#[allow(deprecated)]
pub fn sha256f(state: &mut [u64; 4], input: &[u64; 8]) {
    let state_u32: &mut [u32; 8] = unsafe { &mut *(state.as_mut_ptr() as *mut [u32; 8]) };
    let input_u8: &[GenericArray<u8, U64>; 1] =
        unsafe { &*(input.as_ptr() as *const [GenericArray<u8, U64>; 1]) };
    compress256(state_u32, input_u8);
}

#[allow(deprecated)]
pub fn blake2br(index: u64, state: &mut [u64; 16], input: &[u64; 16]) {
    blake2b_round(state, input, index as u32);
}

pub fn blake3f(cv: &mut [u64; 4], message: &[u64; 8], aux: &[u64; 2]) {
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

    let mut cv_u32 = [0u32; 8];
    for i in 0..4 {
        cv_u32[2 * i] = cv[i] as u32;
        cv_u32[2 * i + 1] = (cv[i] >> 32) as u32;
    }

    let mut block_words = [0u32; 16];
    for i in 0..8 {
        block_words[2 * i] = message[i] as u32;
        block_words[2 * i + 1] = (message[i] >> 32) as u32;
    }

    let counter = aux[0];
    let counter_lo = counter as u32;
    let counter_hi = (counter >> 32) as u32;
    let block_len = aux[1] as u32;
    let flags = (aux[1] >> 32) as u32;

    let mut state: [u32; 16] = [
        cv_u32[0], cv_u32[1], cv_u32[2], cv_u32[3], cv_u32[4], cv_u32[5], cv_u32[6], cv_u32[7],
        IV[0], IV[1], IV[2], IV[3], counter_lo, counter_hi, block_len, flags,
    ];

    let mut msg = block_words;
    for round in 0..7u32 {
        precompiles_helpers::blake3_round(&mut state, &msg, round);
        if round < 6 {
            let mut permuted = [0u32; 16];
            for i in 0..16 {
                permuted[i] = msg[MSG_PERM[i]];
            }
            msg = permuted;
        }
    }

    for i in 0..4 {
        let lo = state[2 * i] ^ state[2 * i + 8];
        let hi = state[2 * i + 1] ^ state[2 * i + 1 + 8];
        cv[i] = (lo as u64) | ((hi as u64) << 32);
    }
}
