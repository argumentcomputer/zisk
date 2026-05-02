#!/usr/bin/env bash
#
# Regenerate the Zisk proving key from an already-built pilout.
# This step is split out from `regen-blake3f.sh` because it takes ~1 hour+
# and shouldn't run on every rebuild iteration.
#
# Order of operations:
#   1. Generate proving key (~1 hour+) + install to ~/.zisk/provingKey
#   2. Verify setup (cargo-zisk check-setup -a)
#
# Prerequisites (run `tools/regen-blake3f.sh` first):
#   - pil/zisk.pilout exists (from PIL compilation)
#   - tmp/fixed/ populated (from FROPS fixed-data generation)
#   - cargo-zisk on PATH or installed at ~/.zisk/bin (from rebuild + install)
#
# Usage:
#   tools/regen-blake3f-pk.sh           # generate PK + verify
#   tools/regen-blake3f-pk.sh --no-verify  # skip the cargo-zisk check-setup step
#
# Assumes:
#   - Run from the zisk repo root
#   - ../pil2-proofman, ../pil2-proofman-js exist and are npm-installed

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

for repo in ../pil2-proofman ../pil2-proofman-js; do
    if [[ ! -d "$repo" ]]; then
        echo "ERROR: $repo not found. See precompiles/blake3f/README.md prerequisites." >&2
        exit 1
    fi
done

if [[ $NO_VERIFY -eq 0 ]] && ! command -v cargo-zisk >/dev/null 2>&1; then
    echo "WARNING: cargo-zisk not on PATH. Step 2 (check-setup) will fail." >&2
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
step_begin "Step 1/2: Generate proving key (~1 hour+, patience)"
node --max-old-space-size=16384 --stack-size=8192 \
    ../pil2-proofman-js/src/main_setup.js \
    -a ./pil/zisk.pilout -b build \
    -t ../pil2-proofman/pil2-components/lib/std/pil \
    -u tmp/fixed -r -s ./state-machines/starkstructs.json

cp -R build/provingKey "$HOME/.zisk/"
step_end

# ── Step 2 ────────────────────────────────────────────────────────────────
if [[ $NO_VERIFY -eq 0 ]]; then
    step_begin "Step 2/2: Verify setup (cargo-zisk check-setup -a)"
    cargo-zisk check-setup -a
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
