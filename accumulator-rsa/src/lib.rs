#![deny(
// warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
//! Implementation of a dynamic universal RSA accumulator
#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate common;

pub(crate) const MIN_SIZE_PRIME: usize = 1024;
pub(crate) const FACTOR_SIZE: usize = MIN_SIZE_PRIME / 8;
pub(crate) const MIN_BYTES: usize = FACTOR_SIZE * 6 + 4;
pub(crate) const MEMBER_SIZE: usize = 32;
pub(crate) const MEMBER_SIZE_BITS: usize = 256;

/// Provides an accumulator secret factors
pub mod key;
/// Provides methods for hashing to prime
pub mod hash;
/// Provides methods for creating and updating accumulators
pub mod accumulator;
/// Provides witness methods
pub mod witness;
/// Proofs of set membership
pub mod memproof;

use common::bigint::BigInteger;

/// BigUint to fixed array
pub(crate) fn b2fa(b: &BigInteger, expected_size: usize) -> Vec<u8> {
    let mut t = vec![0u8; expected_size];
    let bt = b.to_bytes();
    assert!(expected_size >= bt.len(), format!("expected = {}, found = {}", expected_size, bt.len()));
    t[(expected_size - bt.len())..].clone_from_slice(bt.as_slice());
    t
}
