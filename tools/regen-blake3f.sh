#!/usr/bin/env bash
#
# Regenerate Zisk pilout + PIL helpers + release build, then run pre-flight tests.
# Use after editing any PIL file (e.g., blake3f.pil).
#
# Order of operations mirrors precompiles/blake3f/README.md:
#   1. (optional) Generate fixed data for arith / binary tables
#   2. Compile PIL -> zisk.pilout
#   3. Regenerate pil_helpers/traces.rs from pilout
#   4. Rebuild zisk (release) + install binaries to ~/.zisk/bin
#   5. Pre-flight checks (cargo tests + blake3-host execute)
#
# Proving-key regeneration is intentionally split out — it takes ~1 hour+
# and shouldn't run on every iteration. After this script completes, run
# `tools/regen-blake3f-pk.sh` to (re)generate the proving key.
#
# Usage:
#   tools/regen-blake3f.sh              # full run (skips step 1 if tmp/fixed exists)
#   tools/regen-blake3f.sh --with-fixed # force regenerate fixed data
#   tools/regen-blake3f.sh --cpu-only   # build with --features cpu-only (force CPU)
#   tools/regen-blake3f.sh --skip-tests # skip pre-flight tests at step 5
#
# Assumes:
#   - Run from the zisk repo root
#   - ../pil2-compiler, ../pil2-proofman, ../pil2-proofman-js exist and are npm-installed
#   - Default build auto-detects CUDA via ziskbuild/build.rs (sets ZISK_COMPUTE_MODE).
#     Pass --cpu-only to force CPU build via --features cpu-only.
#   - ~/zk-benchmarks/zisk exists for the blake3-host execute check (optional)

set -euo pipefail

# ── Parse args ────────────────────────────────────────────────────────────
FORCE_FIXED=0
CPU_ONLY=0
SKIP_TESTS=0
for arg in "$@"; do
    case "$arg" in
        --with-fixed)   FORCE_FIXED=1 ;;
        --cpu-only)     CPU_ONLY=1 ;;
        --skip-tests)   SKIP_TESTS=1 ;;
        -h|--help)
            sed -n '3,21p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

# ── Logging ───────────────────────────────────────────────────────────────
# All output goes to both terminal and a log file (overwritten on each run).
LOG_FILE="regen-blake3f.log"
echo "Logging to: $LOG_FILE"
exec > >(tee "$LOG_FILE") 2>&1

# ── Sanity ────────────────────────────────────────────────────────────────
if [[ ! -f pil/zisk.pil ]]; then
    echo "ERROR: pil/zisk.pil not found. Run from the zisk repo root." >&2
    exit 1
fi

for repo in ../pil2-compiler ../pil2-proofman ../pil2-proofman-js; do
    if [[ ! -d "$repo" ]]; then
        echo "ERROR: $repo not found. See precompiles/blake3f/README.md prerequisites." >&2
        exit 1
    fi
done

# ── Helpers ───────────────────────────────────────────────────────────────
SECONDS_START=$SECONDS
step_begin() {
    echo
    echo "════════════════════════════════════════════════════════════════════════"
    echo "▶  $1"
    echo "════════════════════════════════════════════════════════════════════════"
    STEP_START=$SECONDS
}
step_end() {
    local dur=$((SECONDS - STEP_START))
    printf "✓  done (%dm %ds)\n" $((dur / 60)) $((dur % 60))
}

# v0.17 auto-detects CUDA at build time (ziskbuild/build.rs sets
# ZISK_COMPUTE_MODE=gpu|cpu). The only feature flag is --features cpu-only
# to force a CPU build.
BUILD_FEATURES=""
if [[ $CPU_ONLY -eq 1 ]]; then
    BUILD_FEATURES="--features cpu-only"
fi

# ── Step 1 ────────────────────────────────────────────────────────────────
if [[ $FORCE_FIXED -eq 1 ]] || [[ ! -d tmp/fixed ]] || [[ -z "$(ls -A tmp/fixed 2>/dev/null)" ]]; then
    step_begin "Step 1/5: Generate fixed data (arith + binary tables)"
    cargo run --release --bin arith_frops_fixed_gen
    cargo run --release --bin binary_basic_frops_fixed_gen
    cargo run --release --bin binary_extension_frops_fixed_gen
    step_end
else
    echo "▶  Step 1/5: Skipped (tmp/fixed already populated; use --with-fixed to force)"
fi

# ── Step 2 ────────────────────────────────────────────────────────────────
step_begin "Step 2/5: Compile PIL → pil/zisk.pilout"
node --max-old-space-size=16384 ../pil2-compiler/src/pil.js pil/zisk.pil \
    -I pil,../pil2-proofman/pil2-components/lib/std/pil,state-machines,precompiles \
    -o pil/zisk.pilout -u tmp/fixed -O fixed-to-file
step_end

# ── Step 3 ────────────────────────────────────────────────────────────────
step_begin "Step 3/5: Regenerate pil_helpers/traces.rs from pilout"
(
    cd ../pil2-proofman
    cargo run --release --bin proofman-cli -- pil-helpers \
        --pilout ../zisk/pil/zisk.pilout --path ../zisk/pil/src -o
)
# Force cargo to see the regenerated file
touch pil/src/pil_helpers/traces.rs
step_end

# ── Step 4 ────────────────────────────────────────────────────────────────
step_begin "Step 4/5: Rebuild zisk (release${BUILD_FEATURES:+ }${BUILD_FEATURES}) + install binaries"
# shellcheck disable=SC2086
cargo build --release $BUILD_FEATURES

mkdir -p "$HOME/.zisk/bin"
cp target/release/cargo-zisk \
   target/release/ziskemu \
   target/release/riscv2zisk \
   target/release/zisk-coordinator \
   target/release/zisk-worker \
   target/release/libziskclib.a \
   "$HOME/.zisk/bin/"

mkdir -p "$HOME/.zisk/zisk/emulator-asm"
cp -r ./emulator-asm/src "$HOME/.zisk/zisk/emulator-asm/"
cp ./emulator-asm/Makefile "$HOME/.zisk/zisk/emulator-asm/"
cp -r ./lib-c "$HOME/.zisk/zisk/"
step_end

# ── Step 5 (pre-flight checks) ────────────────────────────────────────────
# Run as the last gate so any constraint/witness bug surfaces here, before
# you commit to the ~45-min proving-key generation in regen-blake3f-pk.sh.
if [[ $SKIP_TESTS -eq 0 ]]; then
    step_begin "Step 5/5: Pre-flight checks (tests + execute)"

    echo "  ── cargo test -p precompiles-helpers --lib blake3 ──"
    cargo test --release -p precompiles-helpers --lib blake3

    echo
    echo "  ── cargo test -p precomp-blake3f ──"
    cargo test --release -p precomp-blake3f

    echo
    echo "  ── cargo test --workspace (regression guard) ──"
    cargo test --release --workspace

    # Integration check: run the blake3-host execute binary if the benchmarks
    # repo is present. `execute` doesn't need a proving key, so it's safe here.
    if [[ -d "$HOME/zk-benchmarks/zisk/blake3" ]]; then
        echo
        echo "  ── cargo-zisk execute on blake3-host (integration) ──"
        (
            cd "$HOME/zk-benchmarks/zisk"
            cargo run --release -p blake3-host --bin execute
        )
    else
        echo
        echo "  ── blake3-host execute: skipped (~/zk-benchmarks/zisk/blake3 not found) ──"
    fi
    step_end
else
    echo
    echo "▶  Step 5/5: Skipped (--skip-tests) — recommended to run before regen-blake3f-pk.sh"
fi

# ── Done ──────────────────────────────────────────────────────────────────
total=$((SECONDS - SECONDS_START))
echo
echo "════════════════════════════════════════════════════════════════════════"
printf "✓  Rebuild complete in %dm %ds\n" $((total / 60)) $((total % 60))
echo "════════════════════════════════════════════════════════════════════════"
echo
echo "Next steps:"
echo "  tools/regen-blake3f-pk.sh         # generate proving key (~1 hour+)"
echo
echo "Or, if you only want to execute (no proving):"
echo "  cd ~/zk-benchmarks/zisk"
echo "  cargo run --release -p blake3-host --bin execute"
