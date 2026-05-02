use zisk_common::OPERATION_PRECOMPILED_BUS_DATA_SIZE;

// ═══════════════════════════════════════════════════════════════════════════
// TRACE LAYOUT
// ═══════════════════════════════════════════════════════════════════════════

/// Rows per round (1 row per G-function, 8 G-functions per round)
pub const CLOCKS_PER_ROUND: usize = 8;

/// Number of Blake3 rounds per compression
pub const ROUNDS: usize = 7;

/// Rows for G-function computation
pub const CLOCKS_G: usize = CLOCKS_PER_ROUND * ROUNDS; // 56

/// Output capture rows where last-round outputs land via shift routing
pub const CLOCKS_WRITE: usize = 4;

/// Total rows per compression
pub const CLOCKS: usize = CLOCKS_G + CLOCKS_WRITE; // 60

// ═══════════════════════════════════════════════════════════════════════════
// ROTATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

pub const R1: u32 = 16; // first-half XOR-rotate of d
pub const R2: u32 = 12; // first-half XOR-rotate of b
pub const R3: u32 = 8;  // second-half XOR-rotate of d
pub const R4: u32 = 7;  // second-half XOR-rotate of b

// ═══════════════════════════════════════════════════════════════════════════
// G-FUNCTION INDEX TABLES
// ═══════════════════════════════════════════════════════════════════════════

/// Column mixing: G-function i operates on state[G_INDEX[i]]
/// G0-G3 are column mixing, G4-G7 are diagonal mixing
pub const G_INDEX: [[usize; 4]; 8] = [
    // Column mixing (a, b, c, d indices into 16-word state)
    [0, 4, 8, 12],  // G0
    [1, 5, 9, 13],  // G1
    [2, 6, 10, 14], // G2
    [3, 7, 11, 15], // G3
    // Diagonal mixing
    [0, 5, 10, 15], // G4
    [1, 6, 11, 12], // G5
    [2, 7, 8, 13],  // G6
    [3, 4, 9, 14],  // G7
];

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGE SCHEDULE
// ═══════════════════════════════════════════════════════════════════════════

/// Blake3 message word permutation (applied between rounds)
pub const MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Pre-expanded message schedule for all 7 rounds.
/// MSG_SCHEDULE[round][2*g + word] = index into original 16-word message block.
/// Round 0 is identity. Each subsequent round applies MSG_PERMUTATION.
pub const MSG_SCHEDULE: [[usize; 16]; 7] = {
    let mut schedule = [[0usize; 16]; 7];
    // Round 0: identity
    let mut i = 0;
    while i < 16 {
        schedule[0][i] = i;
        i += 1;
    }
    // Rounds 1-6: iteratively apply permutation
    let mut r = 1;
    while r < 7 {
        let mut j = 0;
        while j < 16 {
            schedule[r][j] = schedule[r - 1][MSG_PERMUTATION[j]];
            j += 1;
        }
        r += 1;
    }
    schedule
};

// ═══════════════════════════════════════════════════════════════════════════
// OUTPUT SHIFT DISTANCES
// ═══════════════════════════════════════════════════════════════════════════
//
// Each G-function's second-half output (a'',b'',c'',d'') must appear as the
// input (va,vb,vc,vd) on the FUTURE row that next reads those state words.
// These shift distances (in rows ahead) repeat every 8 rows (each round).
//
// Derivation: for G-function g at position p within a round, its output for
// state word W goes to the next G-function that reads W. The shift = distance
// between current row and that future row.

/// a_out shift: always 4 (constant for all G-functions)
pub const A_OUT_SHIFT: usize = 4;

/// b_out shift per G-function position within a round
pub const B_OUT_SHIFT: [usize; 8] = [7, 3, 3, 3, 5, 5, 5, 1];

/// c_out shift per G-function position within a round
pub const C_OUT_SHIFT: [usize; 8] = [6, 6, 2, 2, 6, 6, 2, 2];

/// d_out shift per G-function position within a round
pub const D_OUT_SHIFT: [usize; 8] = [5, 5, 5, 1, 7, 3, 3, 3];

// ═══════════════════════════════════════════════════════════════════════════
// MEMORY LAYOUT
// ═══════════════════════════════════════════════════════════════════════════

// Blake3 v2 memory layout — 2 indirect params (io_addr, message_addr)
// matching sha256f's pattern. The io buffer holds cv (4 u64s, RW) followed
// by aux (2 u64s, R): counter and block_len_and_flags.
pub const PARAMS: usize = 2; // io_addr, message_addr
pub const READ_PARAMS: usize = 2; // io (cv + aux) + message
pub const WRITE_PARAMS: usize = 1; // cv writeback (4 u64s into io)
pub const PARAM_CHUNKS_IO: usize = 6; // 4 cv u64s + 2 aux u64s
pub const PARAM_CHUNKS_CV: usize = 4; // 8 u32s packed as 4 u64s
pub const PARAM_CHUNKS_AUX: usize = 2; // counter + block_len_and_flags
pub const PARAM_CHUNKS_MESSAGE: usize = 8; // 16 u32s packed as 8 u64s
pub const PARAM_CHUNKS_OUTPUT_CV: usize = 4; // new cv (in-place writeback)
pub const START_READ_PARAMS: usize = OPERATION_PRECOMPILED_BUS_DATA_SIZE + PARAMS;

/// Blake3 IV constants (same as SHA-256 initial hash values)
pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
