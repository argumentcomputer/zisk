use std::sync::Arc;

use fields::PrimeField64;
use rayon::prelude::*;

use pil_std_lib::Std;
use proofman_common::{AirInstance, FromTrace, ProofmanResult};
use proofman_util::{timer_start_trace, timer_stop_and_log_trace};
use zisk_pil::{Blake3fTrace, Blake3fTraceRow, Blake3fTraceRowOps};

use super::{
    blake3f_constants::{
        CLOCKS, CLOCKS_G, CLOCKS_PER_ROUND, G_INDEX, IV, MSG_PERMUTATION, ROUNDS,
    },
    Blake3fInput,
};

/// Blake3 Compression State Machine.
///
/// Constrains one full Blake3 compression: 7 rounds × 8 G-functions = 56 G-calls,
/// plus 4 write-back rows = 60 rows per compression. Each G-function is a single row
/// with explicit intermediate columns; G-function outputs are routed to future rows
/// via PIL row-shifts (A_SHIFT, B_OUT_SHIFT, C_OUT_SHIFT, D_OUT_SHIFT).
pub struct Blake3fSM<F: PrimeField64> {
    pub std: Arc<Std<F>>,
    pub num_available_blake3fs: usize,
    num_non_usable_rows: usize,
    range_id: usize,
}

impl<F: PrimeField64> Blake3fSM<F> {
    pub fn new(std: Arc<Std<F>>) -> Arc<Self> {
        let num_non_usable_rows = Blake3fTrace::<Blake3fTraceRow<F>>::NUM_ROWS % CLOCKS;
        let num_available_blake3fs = Blake3fTrace::<Blake3fTraceRow<F>>::NUM_ROWS / CLOCKS
            - (num_non_usable_rows != 0) as usize;

        let range_id = std.get_range_id(0, (1 << 16) - 1, None).expect("Failed to get range ID");

        Arc::new(Self { std, num_available_blake3fs, num_non_usable_rows, range_id })
    }

    /// Process a single compression, filling 60 trace rows.
    #[inline(always)]
    pub fn process_input<R: Blake3fTraceRowOps<F>>(
        &self,
        input: &Blake3fInput,
        trace: &mut [R],
    ) -> [u32; 65536] {
        let mut range_checks = [0u32; 65536];

        let step_main = input.step_main;
        let addr_main = input.addr_main;
        let io_addr = input.io_addr;
        let message_addr = input.message_addr;

        // Unpack cv (4 u64s) into 8 u32 chaining_value words.
        let mut cv = [0u32; 8];
        for i in 0..4 {
            cv[2 * i] = input.cv[i] as u32;
            cv[2 * i + 1] = (input.cv[i] >> 32) as u32;
        }

        // Unpack aux (2 u64s) into per-block scalars.
        let counter_lo = input.aux[0] as u32;
        let counter_hi = (input.aux[0] >> 32) as u32;
        let block_len = input.aux[1] as u32;
        let flags = (input.aux[1] >> 32) as u32;

        // Unpack message (8 u64s) into 16 u32 message words.
        let msg_original = unpack_u64_to_u32(&input.message);

        // Build the 16-word initial state. The PIL constrains state[8..12] to
        // equal IV (via fixed columns) and state[12..16] to equal counter_lo,
        // counter_hi, block_len, flags (via the aux mem reads). The state
        // machine fills the witness with these constructed values.
        let mut state: [u32; 16] = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3],
            counter_lo, counter_hi, block_len, flags,
        ];

        // Fill step_addr on the first few rows.
        trace[0].set_step_addr(step_main); // STEP_MAIN
        trace[1].set_step_addr(addr_main as u64); // ADDR_OP
        trace[2].set_step_addr(io_addr as u64); // ADDR_IO
        trace[3].set_step_addr(message_addr as u64); // ADDR_MESSAGE
        trace[4].set_step_addr(io_addr as u64); // ADDR_IND_0
        trace[5].set_step_addr(message_addr as u64); // ADDR_IND_1

        // Activate all rows
        for row in trace.iter_mut().take(CLOCKS) {
            row.set_in_use(true);
        }

        // Fill message words on rows 0-15 (m_limbs holds the original 16
        // message words for the row-shift message-schedule routing).
        for (i, &word) in msg_original.iter().enumerate() {
            let limbs = [word as u16, (word >> 16) as u16];
            trace[i].set_m_limbs(0, limbs[0]);
            trace[i].set_m_limbs(1, limbs[1]);
            range_checks[limbs[0] as usize] += 1;
            range_checks[limbs[1] as usize] += 1;
        }

        // m_limbs is zero on G-function rows 16-55 (only rows 0-15 have message data)
        // Count the zero range checks for those 40 rows × 2 limb columns
        range_checks[0] += ((CLOCKS_G - 16) * 2) as u32;

        // Process 7 rounds × 8 G-functions
        let mut msg = msg_original;
        for round in 0..ROUNDS {
            let row_base = round * CLOCKS_PER_ROUND;

            // 8 G-function calls per round
            for g in 0..CLOCKS_PER_ROUND {
                let row_idx = row_base + g;
                let [ai, bi, ci, di] = G_INDEX[g];

                let (a_in, b_in, c_in, d_in) = (state[ai], state[bi], state[ci], state[di]);
                let mx = msg[2 * g];
                let my = msg[2 * g + 1];

                // Compute first half of G with explicit carries (u64 arithmetic, then split).
                // Carries feed the degree-2 modular-add constraints in the PIL.
                let a_mid_full = (a_in as u64) + (b_in as u64) + (mx as u64);
                let a_mid_carry = (a_mid_full >> 32) as u8; // ∈ {0, 1, 2}
                let a_mid = a_mid_full as u32;
                let d_mid = (d_in ^ a_mid).rotate_right(16);
                let c_mid_full = (c_in as u64) + (d_mid as u64);
                let c_mid_carry = (c_mid_full >> 32) as u8; // ∈ {0, 1}
                let c_mid = c_mid_full as u32;
                let b_mid = (b_in ^ c_mid).rotate_right(12);

                // Compute second half of G with explicit carries.
                let a_out_full = (a_mid as u64) + (b_mid as u64) + (my as u64);
                let a_out_carry = (a_out_full >> 32) as u8; // ∈ {0, 1, 2}
                let a_out = a_out_full as u32;
                let d_out = (d_mid ^ a_out).rotate_right(8);
                let c_out_full = (c_mid as u64) + (d_out as u64);
                let c_out_carry = (c_out_full >> 32) as u8; // ∈ {0, 1}
                let c_out = c_out_full as u32;
                let b_out = (b_mid ^ c_out).rotate_right(7);

                // Fill input columns
                set_va::<R, F>(&mut trace[row_idx], &mut range_checks, a_in);
                set_vb::<R, F>(&mut trace[row_idx], b_in);
                set_vc::<R, F>(&mut trace[row_idx], &mut range_checks, c_in);
                set_vd::<R, F>(&mut trace[row_idx], d_in);

                // Fill intermediate columns
                set_va_mid::<R, F>(&mut trace[row_idx], &mut range_checks, a_mid);
                set_vb_mid::<R, F>(&mut trace[row_idx], b_mid);
                set_vc_mid::<R, F>(&mut trace[row_idx], &mut range_checks, c_mid);
                set_vd_mid::<R, F>(&mut trace[row_idx], d_mid);

                // Carry witnesses for the modular-add constraints
                trace[row_idx].set_va_mid_carry(a_mid_carry);
                trace[row_idx].set_vc_mid_carry(c_mid_carry != 0);
                trace[row_idx].set_va_out_carry(a_out_carry);
                trace[row_idx].set_vc_out_carry(c_out_carry != 0);

                // mx and my are PIL expressions derived from m via row shifts —
                // no witness columns to fill here.

                // Update state for subsequent G-functions
                state[ai] = a_out;
                state[bi] = b_out;
                state[ci] = c_out;
                state[di] = d_out;
            }

            // Apply message permutation for next round (except after last round)
            if round < ROUNDS - 1 {
                let mut permuted = [0u32; 16];
                for i in 0..16 {
                    permuted[i] = msg[MSG_PERMUTATION[i]];
                }
                msg = permuted;
            }
        }

        // Output capture rows (56-59): final state in same layout as initial rows 0-3.
        // The second-half G-function constraints on the last round's diagonal G-functions
        // (rows 52-55) shift their outputs to these rows. The witness must match.
        //   Row 56: va=state[0], vb=state[4], vc=state[8], vd=state[12]
        //   Row 57: va=state[1], vb=state[5], vc=state[9], vd=state[13]
        //   Row 58: va=state[2], vb=state[6], vc=state[10], vd=state[14]
        //   Row 59: va=state[3], vb=state[7], vc=state[11], vd=state[15]
        //
        // On output rows we ALSO repurpose vb_mid / vd_mid (which are
        // unconstrained here because g_active = 0) as the bit decomposition of
        // va and vc respectively. The PIL constrains
        //   pack_bits(vb_mid) === va  and  pack_bits(vd_mid) === vc
        // on output rows, then computes the XOR feed-forward output
        //   h[i] = state[i] ^ state[i+8] = pack(vb_mid XOR vd_mid)
        // for the cv writeback to memory at CLK 56. Reusing existing bit columns
        // avoids adding 64 new columns to every trace row.
        for i in 0..4 {
            let row_idx = CLOCKS_G + i;
            set_va::<R, F>(&mut trace[row_idx], &mut range_checks, state[i]);
            set_vb::<R, F>(&mut trace[row_idx], state[4 + i]);
            set_vc::<R, F>(&mut trace[row_idx], &mut range_checks, state[8 + i]);
            set_vd::<R, F>(&mut trace[row_idx], state[12 + i]);
            // Repurpose vb_mid / vd_mid on output rows as bit decomp of va / vc.
            set_vb_mid::<R, F>(&mut trace[row_idx], state[i]);
            set_vd_mid::<R, F>(&mut trace[row_idx], state[8 + i]);
            // Output rows have zero va_mid, vc_mid, m limbs — count their range checks
            // va_mid_limbs(2) + vc_mid_limbs(2) + m_limbs(2) = 6
            range_checks[0] += 6;
        }

        return range_checks;

        // ── Helper functions ──

        fn unpack_u64_to_u32(data: &[u64; 8]) -> [u32; 16] {
            let mut out = [0u32; 16];
            for (i, &val) in data.iter().enumerate() {
                out[2 * i] = val as u32;
                out[2 * i + 1] = (val >> 32) as u32;
            }
            out
        }

        fn set_va<R: Blake3fTraceRowOps<F>, F: PrimeField64>(
            row: &mut R,
            rc: &mut [u32; 65536],
            val: u32,
        ) {
            let limbs = [val as u16, (val >> 16) as u16];
            row.set_va_limbs(0, limbs[0]);
            row.set_va_limbs(1, limbs[1]);
            rc[limbs[0] as usize] += 1;
            rc[limbs[1] as usize] += 1;
        }

        fn set_vc<R: Blake3fTraceRowOps<F>, F: PrimeField64>(
            row: &mut R,
            rc: &mut [u32; 65536],
            val: u32,
        ) {
            let limbs = [val as u16, (val >> 16) as u16];
            row.set_vc_limbs(0, limbs[0]);
            row.set_vc_limbs(1, limbs[1]);
            rc[limbs[0] as usize] += 1;
            rc[limbs[1] as usize] += 1;
        }

        fn set_vb<R: Blake3fTraceRowOps<F>, F: PrimeField64>(row: &mut R, val: u32) {
            for j in 0..32 {
                row.set_vb(j, ((val >> j) & 1) != 0);
            }
        }

        fn set_vd<R: Blake3fTraceRowOps<F>, F: PrimeField64>(row: &mut R, val: u32) {
            for j in 0..32 {
                row.set_vd(j, ((val >> j) & 1) != 0);
            }
        }

        fn set_va_mid<R: Blake3fTraceRowOps<F>, F: PrimeField64>(
            row: &mut R,
            rc: &mut [u32; 65536],
            val: u32,
        ) {
            let limbs = [val as u16, (val >> 16) as u16];
            row.set_va_mid_limbs(0, limbs[0]);
            row.set_va_mid_limbs(1, limbs[1]);
            rc[limbs[0] as usize] += 1;
            rc[limbs[1] as usize] += 1;
        }

        fn set_vc_mid<R: Blake3fTraceRowOps<F>, F: PrimeField64>(
            row: &mut R,
            rc: &mut [u32; 65536],
            val: u32,
        ) {
            let limbs = [val as u16, (val >> 16) as u16];
            row.set_vc_mid_limbs(0, limbs[0]);
            row.set_vc_mid_limbs(1, limbs[1]);
            rc[limbs[0] as usize] += 1;
            rc[limbs[1] as usize] += 1;
        }

        fn set_vb_mid<R: Blake3fTraceRowOps<F>, F: PrimeField64>(row: &mut R, val: u32) {
            for j in 0..32 {
                row.set_vb_mid(j, ((val >> j) & 1) != 0);
            }
        }

        fn set_vd_mid<R: Blake3fTraceRowOps<F>, F: PrimeField64>(row: &mut R, val: u32) {
            for j in 0..32 {
                row.set_vd_mid(j, ((val >> j) & 1) != 0);
            }
        }
    }

    /// Computes the witness for a batch of compression inputs.
    pub fn compute_witness<R: Blake3fTraceRowOps<F>>(
        &self,
        inputs: &[Vec<Blake3fInput>],
        trace_buffer: Vec<F>,
    ) -> ProofmanResult<AirInstance<F>> {
        let mut trace = Blake3fTrace::<R>::new_from_vec_zeroes(trace_buffer)?;
        let num_rows = trace.num_rows();
        let num_available = self.num_available_blake3fs;

        let num_inputs = inputs.iter().map(|v| v.len()).sum::<usize>();
        let all_ops_used = num_inputs == num_available;
        let num_rows_filled = num_inputs * CLOCKS;

        if num_inputs > num_available {
            panic!(
                "Exceeded available Blake3f compressions: requested {}, but only {} available.",
                num_inputs, num_available
            );
        }

        tracing::debug!(
            "··· Creating Blake3f instance [{} compressions, {} / {} rows filled {:.2}%]",
            num_inputs,
            num_rows_filled,
            num_rows,
            num_rows_filled as f64 / num_rows as f64 * 100.0
        );

        timer_start_trace!(BLAKE3F_TRACE);

        // Split trace into CLOCKS-sized chunks for parallel processing
        let mut trace_rows = trace.buffer.as_mut_slice();
        let mut par_traces = Vec::new();
        let mut inputs_indexes = Vec::new();
        for (i, chunk_inputs) in inputs.iter().enumerate() {
            for (j, _) in chunk_inputs.iter().enumerate() {
                let (head, tail) = trace_rows.split_at_mut(CLOCKS);
                par_traces.push(head);
                inputs_indexes.push((i, j));
                trace_rows = tail;
            }
        }

        // Fill trace in parallel
        let range_checks_vec: Vec<[u32; 65536]> = par_traces
            .into_par_iter()
            .enumerate()
            .map(|(index, trace)| {
                let input_index = inputs_indexes[index];
                let input = &inputs[input_index.0][input_index.1];
                self.process_input::<R>(input, trace)
            })
            .collect();

        // Aggregate range checks
        let mut range_checks = vec![0; 65536];
        for rc in range_checks_vec {
            for i in 0..65536 {
                range_checks[i] += rc[i];
            }
        }

        timer_stop_and_log_trace!(BLAKE3F_TRACE);

        // Padding: zero rows. Blake3 has no per-row latched columns (no round_idx
        // analog to Blake2's CLK_0 / round_idx_sel constraint), so default-zero
        // padding satisfies the constraints.
        let padding_row = R::default();
        let _ = all_ops_used; // currently no latching needed
        trace.buffer[num_rows_filled..num_rows]
            .par_iter_mut()
            .for_each(|slot| *slot = padding_row);

        // Count zero range checks for unused rows.
        // 10 range-checked limb columns per row:
        //   va_limbs(2) + vc_limbs(2) + va_mid_limbs(2) + vc_mid_limbs(2) + m_limbs(2) = 10
        // (mx and my are PIL expressions derived from m, not separate witness columns)
        let num_unused_rows = (num_available - num_inputs
            + (self.num_non_usable_rows != 0) as usize)
            * CLOCKS
            + self.num_non_usable_rows;
        let count_zeros = num_unused_rows * 10;
        range_checks[0] += count_zeros as u32;

        self.std.range_checks(self.range_id, range_checks);

        Ok(AirInstance::new_from_trace(FromTrace::new(&mut trace)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fields::Goldilocks;
    use zisk_pil::Blake3fTraceRow;

    use crate::blake3f_constants::MSG_SCHEDULE;

    type F = Goldilocks;
    type Row = Blake3fTraceRow<F>;

    // ── Helpers to read trace row values ──

    fn get_va(row: &Row) -> u32 {
        row.get_va_limbs(0) as u32 | ((row.get_va_limbs(1) as u32) << 16)
    }
    fn get_vc(row: &Row) -> u32 {
        row.get_vc_limbs(0) as u32 | ((row.get_vc_limbs(1) as u32) << 16)
    }
    fn get_vb_packed(row: &Row) -> u32 {
        (0..32).fold(0u32, |acc, j| acc | if row.get_vb(j) { 1 << j } else { 0 })
    }
    fn get_vd_packed(row: &Row) -> u32 {
        (0..32).fold(0u32, |acc, j| acc | if row.get_vd(j) { 1 << j } else { 0 })
    }
    fn get_va_mid(row: &Row) -> u32 {
        row.get_va_mid_limbs(0) as u32 | ((row.get_va_mid_limbs(1) as u32) << 16)
    }
    fn get_vc_mid(row: &Row) -> u32 {
        row.get_vc_mid_limbs(0) as u32 | ((row.get_vc_mid_limbs(1) as u32) << 16)
    }
    fn get_vb_mid_packed(row: &Row) -> u32 {
        (0..32).fold(0u32, |acc, j| acc | if row.get_vb_mid(j) { 1 << j } else { 0 })
    }
    fn get_vd_mid_packed(row: &Row) -> u32 {
        (0..32).fold(0u32, |acc, j| acc | if row.get_vd_mid(j) { 1 << j } else { 0 })
    }
    fn get_va_mid_carry(row: &Row) -> u8 {
        row.get_va_mid_carry()
    }
    fn get_va_out_carry(row: &Row) -> u8 {
        row.get_va_out_carry()
    }
    fn get_vc_mid_carry(row: &Row) -> u8 {
        if row.get_vc_mid_carry() {
            1
        } else {
            0
        }
    }
    fn get_vc_out_carry(row: &Row) -> u8 {
        if row.get_vc_out_carry() {
            1
        } else {
            0
        }
    }
    /// Read the original message word from m_limbs columns at the given row.
    fn get_m(row: &Row) -> u32 {
        row.get_m_limbs(0) as u32 | ((row.get_m_limbs(1) as u32) << 16)
    }
    /// Get mx for a G-function row by reading m from the correct source row
    fn get_mx_from_trace(trace: &[Row], row: usize) -> u32 {
        let round = row / CLOCKS_PER_ROUND;
        let g = row % CLOCKS_PER_ROUND;
        let idx = MSG_SCHEDULE[round][2 * g];
        get_m(&trace[idx])
    }
    fn get_my_from_trace(trace: &[Row], row: usize) -> u32 {
        let round = row / CLOCKS_PER_ROUND;
        let g = row % CLOCKS_PER_ROUND;
        let idx = MSG_SCHEDULE[round][2 * g + 1];
        get_m(&trace[idx])
    }

    fn pack_u64(lo: u32, hi: u32) -> u64 {
        lo as u64 | ((hi as u64) << 32)
    }

    /// Reference G-function (returns output AND intermediate values)
    fn g_ref(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        mx: u32,
        my: u32,
    ) -> ((u32, u32, u32, u32), (u32, u32, u32, u32)) {
        let a1 = a.wrapping_add(b).wrapping_add(mx);
        let d1 = (d ^ a1).rotate_right(16);
        let c1 = c.wrapping_add(d1);
        let b1 = (b ^ c1).rotate_right(12);
        let a2 = a1.wrapping_add(b1).wrapping_add(my);
        let d2 = (d1 ^ a2).rotate_right(8);
        let c2 = c1.wrapping_add(d2);
        let b2 = (b1 ^ c2).rotate_right(7);
        ((a2, b2, c2, d2), (a1, b1, c1, d1))
    }

    /// Build a trace from a known input, returning the trace and final state.
    fn build_test_trace(state_u64: &[u64; 8], input_u64: &[u64; 8]) -> (Vec<Row>, [u32; 16]) {
        let mut trace = vec![Row::default(); CLOCKS];
        let state_u32 = {
            let mut s = [0u32; 16];
            for (i, &v) in state_u64.iter().enumerate() {
                s[2 * i] = v as u32;
                s[2 * i + 1] = (v >> 32) as u32;
            }
            s
        };
        let msg_original = {
            let mut m = [0u32; 16];
            for (i, &v) in input_u64.iter().enumerate() {
                m[2 * i] = v as u32;
                m[2 * i + 1] = (v >> 32) as u32;
            }
            m
        };

        for row in trace.iter_mut().take(CLOCKS) {
            row.set_in_use(true);
        }
        for (i, &word) in msg_original.iter().enumerate() {
            let limbs = [word as u16, (word >> 16) as u16];
            trace[i].set_m_limbs(0, limbs[0]);
            trace[i].set_m_limbs(1, limbs[1]);
        }
        let mut state = state_u32;
        let mut msg = msg_original;
        for round in 0..ROUNDS {
            let row_base = round * CLOCKS_PER_ROUND;
            for g in 0..CLOCKS_PER_ROUND {
                let row_idx = row_base + g;
                let [ai, bi, ci, di] = G_INDEX[g];
                let (a_in, b_in, c_in, d_in) = (state[ai], state[bi], state[ci], state[di]);
                let mx = msg[2 * g];
                let my = msg[2 * g + 1];
                // Same u64-then-split pattern as process_input so carries match the PIL.
                let a_mid_full = (a_in as u64) + (b_in as u64) + (mx as u64);
                let a_mid_carry = (a_mid_full >> 32) as u8;
                let a_mid = a_mid_full as u32;
                let d_mid = (d_in ^ a_mid).rotate_right(16);
                let c_mid_full = (c_in as u64) + (d_mid as u64);
                let c_mid_carry = (c_mid_full >> 32) as u8;
                let c_mid = c_mid_full as u32;
                let b_mid = (b_in ^ c_mid).rotate_right(12);
                let a_out_full = (a_mid as u64) + (b_mid as u64) + (my as u64);
                let a_out_carry = (a_out_full >> 32) as u8;
                let a_out = a_out_full as u32;
                let d_out = (d_mid ^ a_out).rotate_right(8);
                let c_out_full = (c_mid as u64) + (d_out as u64);
                let c_out_carry = (c_out_full >> 32) as u8;
                let c_out = c_out_full as u32;
                let b_out = (b_mid ^ c_out).rotate_right(7);

                trace[row_idx].set_va_limbs(0, a_in as u16);
                trace[row_idx].set_va_limbs(1, (a_in >> 16) as u16);
                for j in 0..32 {
                    trace[row_idx].set_vb(j, ((b_in >> j) & 1) != 0);
                }
                trace[row_idx].set_vc_limbs(0, c_in as u16);
                trace[row_idx].set_vc_limbs(1, (c_in >> 16) as u16);
                for j in 0..32 {
                    trace[row_idx].set_vd(j, ((d_in >> j) & 1) != 0);
                }
                trace[row_idx].set_va_mid_limbs(0, a_mid as u16);
                trace[row_idx].set_va_mid_limbs(1, (a_mid >> 16) as u16);
                for j in 0..32 {
                    trace[row_idx].set_vb_mid(j, ((b_mid >> j) & 1) != 0);
                }
                trace[row_idx].set_vc_mid_limbs(0, c_mid as u16);
                trace[row_idx].set_vc_mid_limbs(1, (c_mid >> 16) as u16);
                for j in 0..32 {
                    trace[row_idx].set_vd_mid(j, ((d_mid >> j) & 1) != 0);
                }
                trace[row_idx].set_va_mid_carry(a_mid_carry);
                trace[row_idx].set_vc_mid_carry(c_mid_carry != 0);
                trace[row_idx].set_va_out_carry(a_out_carry);
                trace[row_idx].set_vc_out_carry(c_out_carry != 0);

                state[ai] = a_out;
                state[bi] = b_out;
                state[ci] = c_out;
                state[di] = d_out;
            }
            if round < ROUNDS - 1 {
                let mut permuted = [0u32; 16];
                for i in 0..16 {
                    permuted[i] = msg[MSG_PERMUTATION[i]];
                }
                msg = permuted;
            }
        }
        for i in 0..4 {
            let row_idx = CLOCKS_G + i;
            trace[row_idx].set_va_limbs(0, state[i] as u16);
            trace[row_idx].set_va_limbs(1, (state[i] >> 16) as u16);
            for j in 0..32 {
                trace[row_idx].set_vb(j, ((state[4 + i] >> j) & 1) != 0);
            }
            trace[row_idx].set_vc_limbs(0, state[8 + i] as u16);
            trace[row_idx].set_vc_limbs(1, (state[8 + i] >> 16) as u16);
            for j in 0..32 {
                trace[row_idx].set_vd(j, ((state[12 + i] >> j) & 1) != 0);
            }
        }

        (trace, state)
    }

    fn test_state() -> [u64; 8] {
        [
            0x00000002_00000001,
            0x00000004_00000003,
            0x00000006_00000005,
            0x00000008_00000007,
            0x6A09E667_BB67AE85,
            0xA54FF53A_3C6EF372,
            0x00000000_510E527F,
            0x00000001_00000040,
        ]
    }

    fn test_input() -> [u64; 8] {
        [
            0x00000102_00000101,
            0x00000104_00000103,
            0x00000106_00000105,
            0x00000108_00000107,
            0x0000010a_00000109,
            0x0000010c_0000010b,
            0x0000010e_0000010d,
            0x00000110_0000010f,
        ]
    }

    /// Test: G-function first-half intermediate values are correct.
    #[test]
    fn test_g_function_intermediates() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());

        let a_in = get_va(&trace[0]);
        let b_in = get_vb_packed(&trace[0]);
        let c_in = get_vc(&trace[0]);
        let d_in = get_vd_packed(&trace[0]);
        let mx = get_mx_from_trace(&trace, 0);
        let my = get_my_from_trace(&trace, 0);

        let (_, (a_mid, b_mid, c_mid, d_mid)) = g_ref(a_in, b_in, c_in, d_in, mx, my);

        assert_eq!(get_va_mid(&trace[0]), a_mid, "G0 a_mid");
        assert_eq!(get_vb_mid_packed(&trace[0]), b_mid, "G0 b_mid");
        assert_eq!(get_vc_mid(&trace[0]), c_mid, "G0 c_mid");
        assert_eq!(get_vd_mid_packed(&trace[0]), d_mid, "G0 d_mid");
    }

    /// Test: state routing -- G-function outputs appear at the correct future rows.
    #[test]
    fn test_state_routing_round0() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());

        // G0 (row 0) outputs should appear as G4 (row 4) inputs
        let a_in_0 = get_va(&trace[0]);
        let b_in_0 = get_vb_packed(&trace[0]);
        let mx_0 = get_mx_from_trace(&trace, 0);
        let my_0 = get_my_from_trace(&trace, 0);
        // G0's a_out should be G4's a_in (shift 4)
        let ((a_out, _, _, _), _) =
            g_ref(a_in_0, b_in_0, get_vc(&trace[0]), get_vd_packed(&trace[0]), mx_0, my_0);
        assert_eq!(get_va(&trace[4]), a_out, "G0.a_out -> G4.a_in");

        // G1's a_out should be G5's a_in (shift 4)
        let a_in_1 = get_va(&trace[1]);
        let b_in_1 = get_vb_packed(&trace[1]);
        let mx_1 = get_mx_from_trace(&trace, 1);
        let my_1 = get_my_from_trace(&trace, 1);
        let ((a_out_1, _, _, _), _) =
            g_ref(a_in_1, b_in_1, get_vc(&trace[1]), get_vd_packed(&trace[1]), mx_1, my_1);
        assert_eq!(get_va(&trace[5]), a_out_1, "G1.a_out -> G5.a_in");
    }

    /// Test: output rows hold the correct final state.
    #[test]
    fn test_output_rows() {
        let (trace, final_state) = build_test_trace(&test_state(), &test_input());

        for i in 0..4 {
            let row = CLOCKS_G + i;
            assert_eq!(get_va(&trace[row]), final_state[i], "output row {row}: va = state[{i}]");
            assert_eq!(
                get_vb_packed(&trace[row]),
                final_state[4 + i],
                "output row {row}: vb = state[{}]",
                4 + i
            );
            assert_eq!(
                get_vc(&trace[row]),
                final_state[8 + i],
                "output row {row}: vc = state[{}]",
                8 + i
            );
            assert_eq!(
                get_vd_packed(&trace[row]),
                final_state[12 + i],
                "output row {row}: vd = state[{}]",
                12 + i
            );
        }
    }

    /// Test: memory value packing -- verify that the column layout on
    /// rows 0-3 and 56-59 produces correct u64 state words.
    #[test]
    fn test_mem_value_packing() {
        let state = test_state();
        let input = test_input();
        let (trace, final_state) = build_test_trace(&state, &input);

        // ── Initial state reads (rows 0-3) ──
        // Port 0, CLK 0: state_u64[0] = (va@0, va@1) = (state[0], state[1])
        assert_eq!(pack_u64(get_va(&trace[0]), get_va(&trace[1])), state[0], "read state[0]");
        assert_eq!(pack_u64(get_va(&trace[2]), get_va(&trace[3])), state[1], "read state[1]");
        assert_eq!(
            pack_u64(get_vb_packed(&trace[0]), get_vb_packed(&trace[1])),
            state[2],
            "read state[2]"
        );
        assert_eq!(
            pack_u64(get_vb_packed(&trace[2]), get_vb_packed(&trace[3])),
            state[3],
            "read state[3]"
        );
        assert_eq!(pack_u64(get_vc(&trace[0]), get_vc(&trace[1])), state[4], "read state[4]");
        assert_eq!(pack_u64(get_vc(&trace[2]), get_vc(&trace[3])), state[5], "read state[5]");
        assert_eq!(
            pack_u64(get_vd_packed(&trace[0]), get_vd_packed(&trace[1])),
            state[6],
            "read state[6]"
        );
        assert_eq!(
            pack_u64(get_vd_packed(&trace[2]), get_vd_packed(&trace[3])),
            state[7],
            "read state[7]"
        );

        // ── Final state writes (rows 56-59, same layout) ──
        let fs = |i: usize| -> u64 {
            final_state[2 * i] as u64 | ((final_state[2 * i + 1] as u64) << 32)
        };
        assert_eq!(pack_u64(get_va(&trace[56]), get_va(&trace[57])), fs(0), "write state[0]");
        assert_eq!(pack_u64(get_va(&trace[58]), get_va(&trace[59])), fs(1), "write state[1]");
        assert_eq!(
            pack_u64(get_vb_packed(&trace[56]), get_vb_packed(&trace[57])),
            fs(2),
            "write state[2]"
        );
        assert_eq!(
            pack_u64(get_vb_packed(&trace[58]), get_vb_packed(&trace[59])),
            fs(3),
            "write state[3]"
        );
        assert_eq!(pack_u64(get_vc(&trace[56]), get_vc(&trace[57])), fs(4), "write state[4]");
        assert_eq!(pack_u64(get_vc(&trace[58]), get_vc(&trace[59])), fs(5), "write state[5]");
        assert_eq!(
            pack_u64(get_vd_packed(&trace[56]), get_vd_packed(&trace[57])),
            fs(6),
            "write state[6]"
        );
        assert_eq!(
            pack_u64(get_vd_packed(&trace[58]), get_vd_packed(&trace[59])),
            fs(7),
            "write state[7]"
        );
    }

    /// Test: full compression matches the reference implementation.
    #[test]
    fn test_full_compression_vs_reference() {
        let state = test_state();
        let input = test_input();
        let (_, final_state) = build_test_trace(&state, &input);

        let mut ref_state = {
            let mut s = [0u32; 16];
            for (i, &v) in state.iter().enumerate() {
                s[2 * i] = v as u32;
                s[2 * i + 1] = (v >> 32) as u32;
            }
            s
        };
        let msg_original = {
            let mut m = [0u32; 16];
            for (i, &v) in input.iter().enumerate() {
                m[2 * i] = v as u32;
                m[2 * i + 1] = (v >> 32) as u32;
            }
            m
        };

        let mut msg = msg_original;
        for round in 0..7u32 {
            precompiles_helpers::blake3_round(&mut ref_state, &msg, round);
            if round < 6 {
                let mut permuted = [0u32; 16];
                for i in 0..16 {
                    permuted[i] = msg[MSG_PERMUTATION[i]];
                }
                msg = permuted;
            }
        }

        for i in 0..16 {
            assert_eq!(
                final_state[i], ref_state[i],
                "state[{i}] mismatch: trace={:#010x} ref={:#010x}",
                final_state[i], ref_state[i]
            );
        }
    }

    /// Test: message schedule -- verify mx/my values match MSG_SCHEDULE.
    #[test]
    fn test_message_schedule() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());

        let msg_original = {
            let input = test_input();
            let mut m = [0u32; 16];
            for (i, &v) in input.iter().enumerate() {
                m[2 * i] = v as u32;
                m[2 * i + 1] = (v >> 32) as u32;
            }
            m
        };

        // Pre-expand message schedule
        let mut schedule = [[0usize; 16]; 7];
        for i in 0..16 {
            schedule[0][i] = i;
        }
        for r in 1..7 {
            for i in 0..16 {
                schedule[r][i] = schedule[r - 1][MSG_PERMUTATION[i]];
            }
        }

        // Verify mx and my on each G-function row match the expected message words
        for round in 0..ROUNDS {
            let mut msg = msg_original;
            // Apply permutation to get this round's message order
            for _ in 0..round {
                let mut permuted = [0u32; 16];
                for i in 0..16 {
                    permuted[i] = msg[MSG_PERMUTATION[i]];
                }
                msg = permuted;
            }
            for g in 0..CLOCKS_PER_ROUND {
                let row = round * CLOCKS_PER_ROUND + g;
                let expected_mx = msg[2 * g];
                let expected_my = msg[2 * g + 1];
                assert_eq!(
                    get_mx_from_trace(&trace, row),
                    expected_mx,
                    "round {round} G{g} (row {row}): mx"
                );
                assert_eq!(
                    get_my_from_trace(&trace, row),
                    expected_my,
                    "round {round} G{g} (row {row}): my"
                );
            }
        }
    }

    /// Test: add3_check constraint -- verify the degree-3 polynomial is satisfied.
    #[test]
    fn test_add3_check_constraint() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());
        let p2_32: u64 = 1 << 32;

        // Check first-half add3: va_mid = va + vb_packed + mx (mod 2^32)
        for row in 0..CLOCKS_G {
            let va_mid = get_va_mid(&trace[row]) as u64;
            let va = get_va(&trace[row]) as u64;
            let vb = get_vb_packed(&trace[row]) as u64;
            let mx = get_mx_from_trace(&trace, row) as u64;
            let sum = va_mid.wrapping_sub(va).wrapping_sub(vb).wrapping_sub(mx);
            // sum mod p should be 0, -2^32, or -2*2^32 (i.e., sum mod 2^32 == 0)
            assert_eq!(sum % p2_32, 0, "row {row}: add3 first-half failed");
        }
    }

    /// Test: every add3/add2 carry witness on G-function rows satisfies the
    /// integer-level invariant the PIL encodes:
    ///   va_mid + va_mid_carry * 2^32 == va + vb_packed + mx       (first-half)
    ///   vc_mid + vc_mid_carry * 2^32 == vc + vd_mid_packed         (first-half)
    ///   va_out_shift + va_out_carry * 2^32 == va_mid + vb_mid_packed + my
    ///   vc_out_shift + vc_out_carry * 2^32 == vc_mid + vd_out_shift (second-half)
    /// and carries are in the expected small range.
    #[test]
    fn test_carry_invariants() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());
        let p2_32: u64 = 1 << 32;

        // First-half carries: one pair (va_mid, vc_mid) per G-function row 0..56.
        for row in 0..CLOCKS_G {
            let va = get_va(&trace[row]) as u64;
            let vb = get_vb_packed(&trace[row]) as u64;
            let mx = get_mx_from_trace(&trace, row) as u64;
            let va_mid = get_va_mid(&trace[row]) as u64;
            let va_mid_carry = get_va_mid_carry(&trace[row]) as u64;

            assert!(va_mid_carry <= 2, "row {row}: va_mid_carry={va_mid_carry} out of range");
            assert_eq!(
                va_mid + va_mid_carry * p2_32,
                va + vb + mx,
                "row {row}: va_mid first-half carry invariant violated",
            );

            let vc = get_vc(&trace[row]) as u64;
            let vd_mid = get_vd_mid_packed(&trace[row]) as u64;
            let vc_mid = get_vc_mid(&trace[row]) as u64;
            let vc_mid_carry = get_vc_mid_carry(&trace[row]) as u64;

            assert!(vc_mid_carry <= 1, "row {row}: vc_mid_carry={vc_mid_carry} out of range");
            assert_eq!(
                vc_mid + vc_mid_carry * p2_32,
                vc + vd_mid,
                "row {row}: vc_mid first-half carry invariant violated",
            );
        }

        // Second-half carries: validate the same invariant, but the outputs
        // (va_out, vc_out) live on FUTURE rows per the A_SHIFT / C_SHIFT table.
        // Matches PIL lines 264, 278-281.
        const A_SHIFT: usize = 4;
        const C_SHIFT: [usize; 8] = [6, 6, 2, 2, 6, 6, 2, 2];
        const D_SHIFT: [usize; 8] = [5, 5, 5, 1, 7, 3, 3, 3];

        for row in 0..CLOCKS_G {
            let g = row % CLOCKS_PER_ROUND;
            let a_out_row = (row + A_SHIFT) % CLOCKS;
            let c_out_row = (row + C_SHIFT[g]) % CLOCKS;

            let va_mid = get_va_mid(&trace[row]) as u64;
            let vb_mid = get_vb_mid_packed(&trace[row]) as u64;
            let my = get_my_from_trace(&trace, row) as u64;
            let va_out = get_va(&trace[a_out_row]) as u64;
            let va_out_carry = get_va_out_carry(&trace[row]) as u64;

            assert!(va_out_carry <= 2, "row {row}: va_out_carry={va_out_carry} out of range");
            assert_eq!(
                va_out + va_out_carry * p2_32,
                va_mid + vb_mid + my,
                "row {row}: va_out second-half carry invariant violated",
            );

            let vc_mid = get_vc_mid(&trace[row]) as u64;
            // vd_out lives on the row at D_SHIFT[g] ahead; for the add, the
            // PIL pulls it via vd_out_packed which is the XOR-rotate output
            // stored in vd_mid at the CURRENT row (from rotl_xor_check line 294).
            // The second-half add checks: vc_out = vc_mid + vd_out, where
            // vd_out is on the shifted row. But the carry witness captured
            // here (vc_out_carry) corresponds to this row's add result.
            // The resulting vc_out sits at row + C_SHIFT[g].
            let vd_out_row = (row + D_SHIFT[g]) % CLOCKS;
            let vd_out = get_vd_packed(&trace[vd_out_row]) as u64;
            let vc_out = get_vc(&trace[c_out_row]) as u64;
            let vc_out_carry = get_vc_out_carry(&trace[row]) as u64;

            assert!(vc_out_carry <= 1, "row {row}: vc_out_carry={vc_out_carry} out of range");
            assert_eq!(
                vc_out + vc_out_carry * p2_32,
                vc_mid + vd_out,
                "row {row}: vc_out second-half carry invariant violated",
            );
        }
    }

    /// Test: carry witnesses on padding-eligible rows (non-G rows 56..59) are
    /// zero (trace defaults). This matches the PIL's expectation that carries
    /// only come from gated add checks on G-function rows.
    #[test]
    fn test_carries_zero_on_output_rows() {
        let (trace, _) = build_test_trace(&test_state(), &test_input());
        for i in 0..4 {
            let row = CLOCKS_G + i;
            assert_eq!(get_va_mid_carry(&trace[row]), 0, "row {row}: va_mid_carry nonzero");
            assert_eq!(get_va_out_carry(&trace[row]), 0, "row {row}: va_out_carry nonzero");
            assert_eq!(get_vc_mid_carry(&trace[row]), 0, "row {row}: vc_mid_carry nonzero");
            assert_eq!(get_vc_out_carry(&trace[row]), 0, "row {row}: vc_out_carry nonzero");
        }
    }
}
