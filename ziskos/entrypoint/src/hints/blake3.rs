// Empty stub for the Blake3 hash hint (HINT_BLAKE3 = 0x0A00).
// Matches the upstream pattern for ops with efficient precompiles
// (hint_sha256, hint_keccak256, hint_blake2b_compress): the symbol exists so
// guest code can `extern "C"` it without link errors, but emission happens
// automatically via syscall_blake3_f, which pushes the resulting cv to
// the hints Vec when running natively with --cfg zisk_hints + feature=hints.
// Real macro-generated emitters live in bn254.rs / bls12_381.rs / etc., for
// ops without precompile circuits.
#[no_mangle]
pub unsafe extern "C" fn hint_blake3(_input_ptr: *const u8, _input_len: usize) {}
