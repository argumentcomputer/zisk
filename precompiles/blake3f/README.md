# Blake3f Compression Precompile for Zisk

Compression-level precompile that accelerates Blake3 hashing in the Zisk zkVM.
Replaces the round-level `blake3r` precompile with a single-syscall design
that performs all 7 rounds, message permutation, and state routing internally.

Blake3 uses 32-bit words. The precompile constrains one full compression
(56 G-function calls = 56 rows, plus 4 output capture rows = 60 rows total)
per trace block. Each G-function is a single row with explicit intermediate
columns. The final output XOR feed-forward (`h[i] = state[i] ^ state[i+8]`)
is performed inside the AIR on the output capture rows by repurposing
`vb_mid`/`vd_mid` as bit decompositions of `va`/`vc`.

## Architecture

```
Layer              | What it does
-------------------+----------------------------------------------
PIL constraints    | blake3f.pil -- 60-row trace per compression,
                   | 1 row per G-function, shift-routed outputs,
                   | lookup-based message verification
Rust state machine | precompiles/blake3f/src/ -- witness generation,
                   | planner, bus device, instance management
Rust helper        | core/src/helpers.rs -- blake3f() full compression
C helper           | lib-c/c/src/blake3/ -- blake3_compress() for
                   | the ASM emulator
ASM emulator       | emulator-asm/src/emu.c -- _opcode_blake3()
Syscall layer      | ziskos/entrypoint/src/syscalls/blake3f.rs
Zisklib            | ziskos/entrypoint/src/zisklib/lib/blake3.rs --
                   | full hash: compress (syscall), chunk, tree
```

## Key Design Decisions

- **1 row per G-function** (not 3 as in blake3r): needs ~150 witness columns
  instead of ~77, but fits 3x more compressions per instance, reducing the
  `instances x columns` product by 36%.
- **N = 2^18**: matches `Sha256f` and `Blake2br`. One instance holds 4,369
  compressions; proofman spawns multiple instances for larger workloads.
- **Max constraint degree 3** via explicit carry-bit witnesses for modular
  add (`va_mid_carry`, `va_out_carry`, `vc_mid_carry`, `vc_out_carry`). The
  `add3_check` / `add2_check` helpers are degree-2 after `g_active` gating;
  the max degree (3) comes from `rotl_xor_check`. This matches `Sha256f`'s
  carry-based encoding and shrinks the stage-Q extension from 4*N to 3*N.
- **Shift-routed outputs**: second-half G-function outputs are stored on future
  rows via CLK_G-selected variable shifts, avoiding separate output columns.
- **In-place cv writeback with XOR feed-forward in the AIR**: the precompile
  writes only the updated chaining value (4 u64s = 8 u32s) back to memory.
  `vb_mid` / `vd_mid` (unused on the 4 output capture rows) are repurposed as
  the bit decomposition of `va` / `vc`, letting the AIR express
  `h[i] = state[i] ^ state[i+8]` bitwise without extra columns.

## Testing

### Unit tests

```bash
# Blake3 round function + official test vectors
cargo test -p precompiles-helpers --lib blake3

# Blake3f state machine (G-function, routing, memory packing)
cargo test -p precomp-blake3f

# Full workspace
cargo test --workspace
```

### Integration tests

From a separate `zk-benchmarks` repo:

```bash
cargo run --release -p blake3-host --bin execute
cargo run --release -p blake3-host --bin verify-constraints
cargo run --release -p blake3-host --bin prove
```

## Guest Usage

```rust
#![no_main]
ziskos::entrypoint!(main);

use ziskos::zisklib::blake3;

fn main() {
    let input = b"hello world";
    let hash: [u8; 32] = blake3(input);
}
```

## Regenerating PIL and Proving Key

Required after modifying `blake3f.pil` or any PIL file. The flow is split
across two scripts so the expensive proving-key step doesn't run on every
iteration:

| Script | What it does | Time |
|---|---|---|
| `tools/regen-blake3f.sh` | Compile PIL → regen helpers → rebuild → tests | ~15-25 min |
| `tools/regen-blake3f-pk.sh` | Generate proving key + verify setup | ~1 hour+ |

Day-to-day after editing PIL or witness code, run `regen-blake3f.sh`. When
you actually need to prove (or after a major PIL change), run both. Both
scripts tee their output to a log file at the repo root
(`regen-blake3f.log`, `regen-blake3f-pk.log`) so you can re-inspect the run
after the fact.

```bash
# From zisk repo root:
tools/regen-blake3f.sh                   # rebuild + tests (no PK)
tools/regen-blake3f.sh && tools/regen-blake3f-pk.sh   # full regen
```

The manual steps below mirror what the scripts do — useful if you need to
run individual steps or debug a script failure.

### Order of operations

1. Compile PIL (produces `.pilout`)
2. Regenerate PIL helpers (produces Rust trace structs from `.pilout`)
3. Rebuild Zisk (compiles the new Rust trace structs)
4. Copy binaries to `~/.zisk/bin`
5. Regenerate proving key (needed for both `verify-constraints` and `prove`;
   only `execute` works without it)

### Prerequisites

The PIL toolchain repos must sit alongside the zisk repo (siblings — every
subsequent command references `../pil2-*`). If they're not already there:

```bash
# From the parent directory of the zisk repo:
git clone https://github.com/0xPolygonHermez/pil2-compiler.git
git clone https://github.com/0xPolygonHermez/pil2-proofman.git
git clone https://github.com/0xPolygonHermez/pil2-proofman-js.git
(cd pil2-compiler && npm i)
(cd pil2-proofman-js && npm i)
```

Match the upstream installation flow described in
`book/getting_started/installation.md`. `pil2-proofman` is a Rust workspace
(no `npm i` needed).

### 1. Generate fixed data

```bash
# From zisk repo root:
cargo run --release --bin arith_frops_fixed_gen
cargo run --release --bin binary_basic_frops_fixed_gen
cargo run --release --bin binary_extension_frops_fixed_gen
```

### 2. Compile PIL

```bash
# From zisk repo root:
node --max-old-space-size=16384 ../pil2-compiler/src/pil.js pil/zisk.pil \
  -I pil,../pil2-proofman/pil2-components/lib/std/pil,state-machines,precompiles \
  -o pil/zisk.pilout -u tmp/fixed -O fixed-to-file
```

### 3. Regenerate PIL helpers

```bash
cd ../pil2-proofman
cargo run --release --bin proofman-cli -- pil-helpers \
  --pilout ../zisk/pil/zisk.pilout --path ../zisk/pil/src -o
cd ../zisk
```

### 4. Rebuild Zisk and install

```bash
# From zisk repo root:
touch pil/src/pil_helpers/traces.rs
cargo build --release
```

The build auto-detects CUDA via `ziskbuild/build.rs` (sets `ZISK_COMPUTE_MODE=gpu|cpu`
based on whether `/usr/local/cuda`, `$CUDA_HOME`, or `nvcc` on `$PATH` is
present). Verify the resulting binary's `--version` ends in `[gpu]` if a GPU
build is desired. To force a CPU build on a host with CUDA, pass
`--features cpu-only`.

Then copy binaries to `~/.zisk/bin`:

```bash
mkdir -p $HOME/.zisk/bin
cp target/release/cargo-zisk target/release/ziskemu target/release/riscv2zisk \
   target/release/zisk-coordinator target/release/zisk-worker \
   target/release/libziskclib.a $HOME/.zisk/bin

mkdir -p $HOME/.zisk/zisk/emulator-asm
cp -r ./emulator-asm/src $HOME/.zisk/zisk/emulator-asm
cp ./emulator-asm/Makefile $HOME/.zisk/zisk/emulator-asm
cp -r ./lib-c $HOME/.zisk/zisk
```

### 5. Generate proving key (~1 hour+)

Required for both `verify-constraints` and `prove`. The proving key contains
constraint definitions and expression binaries that verify-constraints needs to
evaluate. Only `execute` works without it.

```bash
# From zisk repo root:
node --max-old-space-size=16384 --stack-size=8192 \
  ../pil2-proofman-js/src/main_setup.js \
  -a ./pil/zisk.pilout -b build \
  -t ../pil2-proofman/pil2-components/lib/std/pil \
  -u tmp/fixed -r -s ./state-machines/starkstructs.json

cp -R build/provingKey $HOME/.zisk/
cargo-zisk check-setup -a
```
