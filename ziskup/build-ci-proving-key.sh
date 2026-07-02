#!/usr/bin/env bash
#
# Build and upload the CPU "no-consttree" proving-key tarball that the ix repo's
# RISC-V bench CI restores in order to run `zisk-host --execute`
# (ix: .github/workflows/riscv-bench.yml, the `zisk-execute` job).
#
# Why this exists
# ---------------
# This `blake3-precompile` branch has a different circuit than upstream zisk
# (it adds the Blake3f AIR), so the key published on upstream's `zisk-setup`
# bucket does not match — `ziskup` with `--nokey` is used in CI and the
# fork-matching key is restored from our own bucket instead.
#
# Like Zisk's own released `zisk-provingkey-*.tar.gz`, the artifact OMITS the
# regenerable const-tree files (`*.consttree`, ~36 GB at v1.0.0-alpha) and the
# GPU variants (`*_gpu` const/consttree files, ~40 GB, generated lazily by the
# first GPU prove and unused on the CPU-only runner). What ships is the ~13 GB
# core (a few GB gzipped). CI regenerates the const-trees after download with
# `cargo-zisk-dev check-setup --proving-key <dir> -a` (v1.0.0-alpha moved
# check-setup to the cargo-zisk-dev binary; exactly how `ziskup` itself
# populates them).
#
# Prerequisites
# -------------
#   * A fully-populated $ZISK_HOME/provingKey — i.e. `ziskup` installed the key
#     for THIS branch's circuit and the const-trees were generated.
#   * `pigz` (multithreaded gzip) and `tar`.
#   * `aws` CLI configured with write access to the bucket below (the bucket is
#     public-read; only uploads need credentials).
#   * Run from a checkout of this branch so the rev tag matches the circuit.
#
# After uploading, update the hardcoded object name in the ix workflow
# (`riscv-bench.yml`, the `curl ... .s3.amazonaws.com/...` line) to the file
# this script prints, so CI fetches the key matching the current circuit rev.

set -euo pipefail

ZISK_HOME="${ZISK_HOME:-$HOME/.zisk}"
BUCKET="s3://argument-zisk-setup"
REV="$(git rev-parse --short=8 HEAD)"
OUT="zisk-provingkey-blake3-${REV}-cpu.tar.gz"

if [[ ! -d "$ZISK_HOME/provingKey" ]]; then
  echo "error: $ZISK_HOME/provingKey not found — install it with ziskup first" >&2
  exit 1
fi

echo "Packaging $ZISK_HOME/provingKey -> $OUT (excluding const-trees and GPU variants)"
tar -C "$ZISK_HOME" --exclude='*.consttree' --exclude='*_gpu' -I pigz -cf "$OUT" provingKey

echo "Uploading $OUT -> $BUCKET/$OUT"
aws s3 cp "$OUT" "$BUCKET/$OUT"

echo "Done. Point the ix CI curl at:"
echo "  https://argument-zisk-setup.s3.amazonaws.com/$OUT"
