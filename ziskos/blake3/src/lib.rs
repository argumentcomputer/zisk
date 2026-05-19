//! Drop-in replacement for the upstream `blake3` crate (v1.8.4 public API
//! subset) that routes hashing through `ziskos::zisklib::blake3` — the
//! Blake3f precompile on the Zisk zkVM target, software fallback otherwise.
//!
//! # Usage
//!
//! Consumers add a single `[patch.crates-io]` entry to their workspace:
//!
//! ```toml
//! [patch.crates-io]
//! blake3 = { git = "https://github.com/argumentcomputer/zisk.git", \
//!            branch = "blake3-precompile-v0.17" }
//! ```
//!
//! No source changes are needed — every `blake3::Hasher::new()`,
//! `blake3::hash(..)`, and `blake3::Hash` use is satisfied by this crate.
//!
//! # Exposed surface
//!
//! - [`Hash`] — 32-byte digest. Byte-for-byte compatible with upstream:
//!   `as_bytes`, `to_hex` (returns `ArrayString<64>`), `from_slice`,
//!   `From<[u8; 32]>`, `Eq`/`Ord`/`std::hash::Hash`/`Copy`/`Clone`/`Debug`.
//! - [`Hasher`] — streaming hasher. `new`, `update` (chainable), `finalize`.
//!   Buffers all input internally and calls the precompile once at
//!   `finalize` time. Equivalent to streaming Blake3 because the algorithm
//!   is defined over the concatenation of inputs.
//! - [`hash`] — one-shot top-level hash.
//!
//! # Not implemented
//!
//! Keyed / derive modes, `OutputReader` / `finalize_xof`, `update_rayon`,
//! `update_mmap`, `update_reader`. None are used by the typical zkVM guest
//! pipeline (kernel typecheckers, hash trees, etc.). Add as needed.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use arrayvec::ArrayString;
use core::array::TryFromSliceError;
use core::convert::TryFrom;
use core::fmt;

pub const OUT_LEN: usize = 32;

/// A 32-byte Blake3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; OUT_LEN]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, TryFromSliceError> {
        <[u8; OUT_LEN]>::try_from(bytes).map(Self)
    }

    pub fn to_hex(&self) -> ArrayString<{ 2 * OUT_LEN }> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = ArrayString::<{ 2 * OUT_LEN }>::new();
        for &b in &self.0 {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }
}

impl From<[u8; OUT_LEN]> for Hash {
    fn from(bytes: [u8; OUT_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; OUT_LEN] {
    fn from(h: Hash) -> Self {
        h.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex().as_str())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_hex().as_str())
    }
}

/// Streaming Blake3 hasher. `update` appends into an internal buffer;
/// `finalize` calls the precompile (or its software fallback) once.
#[derive(Clone, Default)]
pub struct Hasher {
    buf: Vec<u8>,
}

impl Hasher {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(input);
        self
    }

    pub fn finalize(&self) -> Hash {
        Hash(ziskos::zisklib::blake3(&self.buf))
    }
}

/// One-shot Blake3 of `input`.
pub fn hash(input: &[u8]) -> Hash {
    Hash(ziskos::zisklib::blake3(input))
}
