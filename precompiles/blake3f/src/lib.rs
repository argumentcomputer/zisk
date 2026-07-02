mod blake3f;
mod blake3f_constants;
mod blake3f_input;
mod blake3f_mem_inputs;

pub use blake3f::*;
pub use blake3f_constants::*;
pub use blake3f_input::*;

zisk_common::zisk_precompile! {
    name = Blake3f,
    op_type = Blake3,
    trace = Blake3fTrace,
    num_available = {
        let n = ::zisk_pil::Blake3fTrace::<::zisk_pil::Blake3fTraceRow<F>>::NUM_ROWS;
        n / CLOCKS - (n % CLOCKS != 0) as usize
    },
    ops = [
        (OperationBlake3Data, Blake3fInput),
    ],
}
