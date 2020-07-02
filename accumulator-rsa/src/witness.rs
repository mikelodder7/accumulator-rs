use crate::{
    accumulator::Accumulator,
    hash::hash_to_prime,
    key::AccumulatorSecretKey,
};
use common::{
    bigint::BigInteger,
    error::{AccumulatorErrorKind, AccumulatorError},
};
use rayon::prelude::*;

/// A witness that can be used for membership proofs
#[derive(Debug, Eq, PartialEq)]
pub struct MembershipWitness {
    pub(crate) u: BigInteger,
    pub(crate) x: BigInteger,
}

impl MembershipWitness {
    /// Return a new membership witness
    pub fn new<B: AsRef<[u8]>>(accumulator: &Accumulator, x: B) -> Result<Self, AccumulatorError> {
        let x = hash_to_prime(x.as_ref());
        Self::new_prime(accumulator, &x)
    }

    /// Return a new membership witness with a value that is already prime
    pub fn new_prime(accumulator: &Accumulator, x: &BigInteger) -> Result<Self, AccumulatorError> {
        if !accumulator.members.contains(&x) {
            return Err(AccumulatorError::from_msg(AccumulatorErrorKind::InvalidMemberSupplied, "value is not in the accumulator"));
        }
        let exp = accumulator.members.par_iter()
            .cloned()
            .filter(|b| b != x)
            .product();
        let u = (&accumulator.generator).mod_exp(&exp, &accumulator.modulus);
        Ok(MembershipWitness {
            u, x: x.clone()
        })
    }

    /// Return a new membership witness. This is more efficient that `new` due to
    /// the ability to reduce by the totient
    pub fn with_secret_key<B: AsRef<[u8]>>(accumulator: &Accumulator, secret_key: &AccumulatorSecretKey, x: B) -> Self {
        let x = hash_to_prime(x.as_ref());
        Self::with_prime_and_secret_key(accumulator, secret_key, &x)
    }

    /// Return a new membership witness with a value already prime.
    /// This is more efficient that `new` due to
    /// the ability to reduce by the totient
    pub fn with_prime_and_secret_key(accumulator: &Accumulator, secret_key: &AccumulatorSecretKey, x: &BigInteger) -> Self {
        if !accumulator.members.contains(&x) {
            return MembershipWitness {
                u: accumulator.value.clone(), x: x.clone()
            };
        }
        let totient = secret_key.totient();
        let f = common::Field::new(&totient);
        let exp = accumulator.members.par_iter()
            .cloned()
            .filter(|b| b != x)
            .reduce(|| BigInteger::from(1u32), |a, b| f.mul(&a, &b));
        let u = (&accumulator.generator).mod_exp(&exp, &accumulator.modulus);
        MembershipWitness {
            u, x: x.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_to_prime;

    #[test]
    fn witnesses() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![3u64.to_be_bytes(), 7u64.to_be_bytes(), 11u64.to_be_bytes(), 13u64.to_be_bytes()];
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = MembershipWitness::new(&acc, &members[0]).unwrap();
        let x = hash_to_prime(&members[0]);
        assert_eq!(witness.x, x);

        acc.remove_assign(&key, &members[0]).unwrap();

        assert_eq!(acc.value, witness.u);
    }
}