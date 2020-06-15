use crate::{accumulator::Accumulator, key::AccumulatorSecretKey, clone_bignum};
use openssl::bn::*;
use rayon::prelude::*;

/// A witness that can be used for membership proofs
#[derive(Debug, Eq, PartialEq)]
pub struct MembershipWitness {
    pub(crate) w: BigNum,
    pub(crate) x: BigNum
}

impl MembershipWitness {
    /// Return a new membership witness
    pub fn new(accumulator: &Accumulator, x: &BigNum) -> Self {
        let exp = accumulator.members.par_iter()
            .map(|b| clone_bignum(b))
            .filter(|b| b != x)
            .reduce(|| BigNum::from_u32(1).unwrap(),
                    |a, b| {
                        let mut ctx = BigNumContext::new().unwrap();
                        let mut t = BigNum::new().unwrap();
                        BigNumRef::checked_mul(&mut t, &a, &b, &mut ctx).unwrap();
                        t
                    });
        let mut w = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_exp(&mut w, &accumulator.generator, &exp, &accumulator.modulus, &mut ctx).unwrap();
        MembershipWitness {
            w, x: clone_bignum(x)
        }
    }

    /// Return a new membership witness. This is more efficient that `new` due to
    /// the ability to reduce by the totient
    pub fn with_secret_key(accumulator: &Accumulator, secret_key: &AccumulatorSecretKey, x: &BigNum) -> Self {
        let totient = secret_key.totient();
        let exp = accumulator.members.par_iter()
            .map(|b| clone_bignum(b))
            .filter(|b| b != x)
            .reduce(|| BigNum::from_u32(1).unwrap(),
                    |a, b| {
                        let mut ctx = BigNumContext::new().unwrap();
                        let mut t = BigNum::new().unwrap();
                        BigNumRef::mod_mul(&mut t, &a, &b, &totient, &mut ctx).unwrap();
                        t
                    });
        let mut w = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        BigNumRef::mod_exp(&mut w, &accumulator.generator, &exp, &accumulator.modulus, &mut ctx).unwrap();
        MembershipWitness {
            w, x: clone_bignum(x)
        }
    }
}

