#![deny(
// warnings,
missing_docs,
unsafe_code,
unused_import_braces,
unused_lifetimes,
unused_qualifications,
)]
#![cfg_attr(feature = "nightly", feature(doc_cfg))]
//! Implementation of a universal RSA accumulator
//!
//!
#[macro_use]
extern crate arrayref;

pub(crate) const MIN_SIZE_PRIME: usize = 1024;
pub(crate) const FACTOR_SIZE: usize = MIN_SIZE_PRIME / 8;
pub(crate) const MIN_BYTES: usize = FACTOR_SIZE * 6 + 4;
pub(crate) const MEMBER_SIZE: usize = 32;

use openssl::bn::*;

#[macro_use]
mod macros;
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

/// BigUint to fixed array
pub(crate) fn b2fa(b: &BigNum, expected_size: usize) -> Vec<u8> {
    let mut t = vec![0u8; expected_size];
    let bt = b.to_vec();
    assert!(expected_size >= bt.len(), format!("expected = {}, found = {}", expected_size, bt.len()));
    t[(expected_size - bt.len())..].clone_from_slice(bt.as_slice());
    t
}

#[inline]
pub(crate) fn clone_bignum(b: &BigNum) -> BigNum {
    BigNum::from_slice(b.to_vec().as_slice()).unwrap()
}

// Uses Bezout coefficient's to compute an (xy)-th root of a group element
// `g` from an x-th root of `g` and a y-th root of `g`
// pub(crate) fn shamir_trick(base1: &BigNum, exp1: &BigNum, base2: &BigNum, exp2: &BigNum, modulus: &BigNum) -> Option<BigNum> {
//
//     let res = exp1.extended_gcd(exp2);
//
//     if res.gcd == BigUint::from(1u64) {
//         let t1 = base1.modpow(&res.y, modulus);
//         let t2 = base2.modpow(&res.x, modulus);
//         Some((t1 * t2) % modulus)
//     } else {
//         None
//     }
// }

