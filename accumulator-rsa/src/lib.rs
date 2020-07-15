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
pub extern crate common;

pub(crate) const MIN_SIZE_PRIME: usize = 1024;
pub(crate) const FACTOR_SIZE: usize = MIN_SIZE_PRIME / 8;
pub(crate) const MIN_BYTES: usize = FACTOR_SIZE * 6 + 4;
pub(crate) const MEMBER_SIZE: usize = 32;
pub(crate) const MEMBER_SIZE_BITS: usize = 256;

/// Provides methods for creating and updating accumulators
pub mod accumulator;
/// Provides methods for hashing to prime
pub mod hash;
/// Provides an accumulator secret factors
pub mod key;
/// Proofs of set membership
pub mod memproof;
/// Proofs of set non-membership
pub mod nonmemproof;
/// Provides non-membership witness methods
pub mod nonwitness;
/// Provides witness methods
pub mod memwitness;

use crate::{accumulator::Accumulator, hash::hash_to_prime};
use blake2::{digest::Digest, Blake2b};
use common::{
    bigint::BigInteger,
    error::{AccumulatorError, AccumulatorErrorKind},
};
use std::convert::TryFrom;

/// Convenience module to include when using
pub mod prelude {
    pub use crate::{
        accumulator::Accumulator,
        common::{
            bigint::{BigInteger, GcdResult},
            error::*,
        },
        key::AccumulatorSecretKey,
        memproof::MembershipProof,
        memwitness::MembershipWitness,
        nonmemproof::NonMembershipProof,
        nonwitness::NonMembershipWitness,
    };
}

/// BigUint to fixed array
pub(crate) fn b2fa(b: &BigInteger, expected_size: usize) -> Vec<u8> {
    let mut t = vec![0u8; expected_size];
    let bt = b.to_bytes();
    assert!(
        expected_size >= bt.len(),
        format!("expected = {}, found = {}", expected_size, bt.len())
    );
    t[(expected_size - bt.len())..].clone_from_slice(bt.as_slice());
    t
}

/// Represents a Proof of Knowledge of Exponents 2 from section 3.2 in
/// <https://eprint.iacr.org/2018/1188.pdf>
/// Not meant to be used directly
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Poke2Proof {
    u: BigInteger,
    z: BigInteger,
    q: BigInteger,
    r: BigInteger,
}

impl Poke2Proof {
    /// The size of this proof serialized
    pub const SIZE_BYTES: usize = 6 * FACTOR_SIZE + MEMBER_SIZE;

    /// Create a new proof of knowledge of exponents
    pub fn new<B: AsRef<[u8]>>(
        x_in: &BigInteger,
        u: &BigInteger,
        a: &BigInteger,
        accumulator: &Accumulator,
        nonce: B,
    ) -> Self {
        let f = common::Field::new(&accumulator.modulus);
        let nonce = nonce.as_ref();
        let g = f.exp(&accumulator.generator, &BigInteger::from(nonce.to_vec()));
        let z = f.exp(&g, x_in);

        let mut data = g.to_bytes();
        data.append(&mut accumulator.modulus.to_bytes());
        data.append(&mut a.to_bytes());
        data.append(&mut u.to_bytes());
        data.append(&mut z.to_bytes());
        data.extend_from_slice(nonce.as_ref());

        // l = H2P( g || m || v || u || z || n1 )
        let l = hash_to_prime(data.as_slice());

        data.append(&mut l.to_bytes());
        // Fiat-Shamir
        // x = H(g || m || v || u || z || n1 || l)
        let x = BigInteger::try_from(Blake2b::digest(data.as_slice()).as_slice()).unwrap();
        // q = x / l
        // r = x % l
        let (whole, r) = BigInteger::div_rem(&x_in, &l);

        // u ^ q
        let q1 = f.exp(&u, &whole);
        // g ^ {q * alpha}
        let q2 = f.exp(&g, &(&x * &whole));
        // Q = u ^ q * g ^ {q * alpha}
        let q = f.mul(&q1, &q2);
        Self {
            u: u.clone(),
            q,
            r,
            z,
        }
    }

    /// Use another value as the accumulator value to verify
    pub fn verify_with<B: AsRef<[u8]>>(
        &self,
        value: &BigInteger,
        accumulator: &Accumulator,
        nonce: B,
    ) -> bool {
        let mut acc = accumulator.clone();
        acc.value = value.clone();
        self.verify(&acc, nonce)
    }

    /// Verify a proof of knowledge of exponents
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        let nonce = nonce.as_ref();
        let f = common::Field::new(&accumulator.modulus);
        let g = f.exp(&accumulator.generator, &BigInteger::from(nonce.to_vec()));
        let mut data = g.to_bytes();
        data.append(&mut accumulator.modulus.to_bytes());
        data.append(&mut accumulator.value.to_bytes());
        data.append(&mut self.u.to_bytes());
        data.append(&mut self.z.to_bytes());
        data.extend_from_slice(nonce.as_ref());

        // l = H2P(g || m || v || u || z || n1)
        let l = hash_to_prime(data.as_slice());
        data.append(&mut l.to_bytes());

        // Fiat-Shamir
        // x = H(g || m || v || u || z || n1 || l)
        let x = BigInteger::try_from(Blake2b::digest(data.as_slice()).as_slice()).unwrap();


        // Q ^ l
        let p1 = f.exp(&self.q, &l);
        // u ^ r
        let p2 = f.exp(&self.u, &self.r);
        // x * r
        // g ^ {x * r}
        let p3 = f.exp(&g, &(&x * &self.r));

        // Q^l * u^r * g^{x * r}
        let left = f.mul(&p1, &f.mul(&p2, &p3));

        // v * z^x
        let right = f.mul(&accumulator.value, &f.exp(&self.z, &x));

        left == right
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.u, 2 * FACTOR_SIZE);
        output.append(&mut b2fa(&self.z, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.q, 2 * FACTOR_SIZE));
        output.append(&mut b2fa(&self.r, MEMBER_SIZE));
        output
    }
}

impl TryFrom<&[u8]> for Poke2Proof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != Self::SIZE_BYTES {
            return Err(AccumulatorErrorKind::SerializationError.into());
        }
        let u = BigInteger::try_from(&data[..(2 * FACTOR_SIZE)])?;
        let z = BigInteger::try_from(&data[(2 * FACTOR_SIZE)..(4 * FACTOR_SIZE)])?;
        let q = BigInteger::try_from(&data[(4 * FACTOR_SIZE)..(6 * FACTOR_SIZE)])?;
        let r = BigInteger::try_from(&data[(6 * FACTOR_SIZE)..])?;
        Ok(Self { u, z, q, r })
    }
}

serdes_impl!(Poke2Proof);
