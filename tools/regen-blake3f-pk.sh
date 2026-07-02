#!/usr/bin/env bash
#
# Regenerate the Zisk proving key from an already-built pilout.
# This step is split out from `regen-blake3f.sh` because it is the heavy step
# and shouldn't run on every rebuild iteration. Measured ~25 min on 32 cores
# with jobs=8 (the v1.0.0-alpha Rust setup; the old node main_setup.js flow
# took 1 hour+).
#
# Order of operations:
#   1. Generate proving key (~25 min) + install to ~/.zisk/provingKey
#   2. Verify setup (cargo-zisk check-setup -a)
#
# Prerequisites (run `tools/regen-blake3f.sh` first):
#   - pil/zisk.pilout exists (from PIL compilation)
#   - tmp/fixed/ populated (from FROPS fixed-data generation)
#   - cargo-zisk-dev on PATH or installed at ~/.zisk/bin (from rebuild + install)
#
# Usage:
#   tools/regen-blake3f-pk.sh           # generate PK + verify
#   tools/regen-blake3f-pk.sh --no-verify  # skip the cargo-zisk check-setup step
#
# Assumes:
#   - Run from the zisk repo root
#   - ../pil2-proofman exists at the v1.0.0-alpha tag (bundles circom + the
#     Rust pil2-stark-setup that replaced pil2-proofman-js's main_setup.js)

set -euo pipefail

# ── Parse args ────────────────────────────────────────────────────────────
NO_VERIFY=0
for arg in "$@"; do
    case "$arg" in
        --no-verify)    NO_VERIFY=1 ;;
        -h|--help)
            sed -n '3,20p' "$0"
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
LOG_FILE="regen-blake3f-pk.log"
echo "Logging to: $LOG_FILE"
exec > >(tee "$LOG_FILE") 2>&1

# ── Sanity ────────────────────────────────────────────────────────────────
if [[ ! -f pil/zisk.pil ]]; then
    echo "ERROR: pil/zisk.pil not found. Run from the zisk repo root." >&2
    exit 1
fi

if [[ ! -f pil/zisk.pilout ]]; then
    echo "ERROR: pil/zisk.pilout not found. Run tools/regen-blake3f.sh first." >&2
    exit 1
fi

if [[ ! -d tmp/fixed ]] || [[ -z "$(ls -A tmp/fixed 2>/dev/null)" ]]; then
    echo "ERROR: tmp/fixed/ is empty. Run tools/regen-blake3f.sh first." >&2
    exit 1
fi

if [[ ! -d ../pil2-proofman ]]; then
    echo "ERROR: ../pil2-proofman not found. See precompiles/blake3f/README.md prerequisites." >&2
    exit 1
fi

if [[ $NO_VERIFY -eq 0 ]] && ! command -v cargo-zisk-dev >/dev/null 2>&1; then
    echo "WARNING: cargo-zisk-dev not on PATH. Step 2 (check-setup) will fail." >&2
    echo "         Run tools/regen-blake3f.sh first or pass --no-verify." >&2
fi

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

# ── Step 1 ────────────────────────────────────────────────────────────────
step_begin "Step 1/2: Generate proving key (~25 min on 32 cores)"
# v1.0.0-alpha: proving-key setup is the Rust pil2-stark-setup, wrapped by
# cargo-zisk-dev. Writes $HOME/.zisk/provingKey directly (no build/ copy step).
# RECURSIVE_JOBS / SETUP_JOBS parallelize the setup; size to available RAM
# (each recursive slot runs one circom compile + pil2com at ~1-4 GB peak).
cargo-zisk-dev proofman-setup setup \
    --airout ./pil/zisk.pilout \
    --build-dir "$HOME/.zisk" \
    --fixed-dir tmp/fixed \
    --stark-structs ./state-machines/starkstructs.json \
    --recursive \
    --setup-jobs "${SETUP_JOBS:-8}" \
    --recursive-jobs "${RECURSIVE_JOBS:-8}"
step_end

# ── Step 2 ────────────────────────────────────────────────────────────────
if [[ $NO_VERIFY -eq 0 ]]; then
    step_begin "Step 2/2: Verify setup (cargo-zisk-dev check-setup -a)"
    cargo-zisk-dev check-setup -a
    step_end
else
    echo
    echo "▶  Step 2/2: Skipped (--no-verify)"
fi

# ── Done ──────────────────────────────────────────────────────────────────
total=$((SECONDS - SECONDS_START))
echo
echo "════════════════════════════════════════════════════════════════════════"
printf "✓  Proving key regenerated in %dm %ds\n" $((total / 60)) $((total % 60))
echo "════════════════════════════════════════════════════════════════════════"
echo
echo "Next steps:"
echo "  cd ~/zk-benchmarks/zisk"
echo "  cargo run --release -p blake3-host --bin verify-constraints"
echo "  cargo run --release -p blake3-host --bin prove"
