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
extern  crate arrayref;

use num_bigint::BigUint;
use num_integer::Integer;

#[macro_use]
mod macros;
/// Provides methods for hashing to prime
pub mod hash;
/// Provides methods for creating and updating accumulators
pub mod accumulator;

pub(crate) fn shamir_trick(base1: &BigUint, exp1: &BigUint, base2: &BigUint, exp2: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let res = exp1.extended_gcd(exp2);

    if res.gcd == BigUint::from(1u64) {
        let t1 = base1.modpow(&res.y, modulus);
        let t2 = base2.modpow(&res.x, modulus);
        Some((t1 * t2) % modulus)
    } else {
        None
    }
}

