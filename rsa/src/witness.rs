use crate::{
    accumulator::Accumulator,
    error::{AccumulatorErrorKind, AccumulatorError},
    hash::hash_to_prime,
    key::AccumulatorSecretKey,
    clone_bignum
};
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
    pub fn new<B: AsRef<[u8]>>(accumulator: &Accumulator, x: B) -> Result<Self, AccumulatorError> {
        let x = hash_to_prime(x.as_ref());
        if !accumulator.members.contains(&x) {
            return Err(AccumulatorError::from_msg(AccumulatorErrorKind::InvalidMemberSupplied, ""));
        }
        let exp = accumulator.members.par_iter()
            .map(|b| clone_bignum(b))
            .filter(|b| b != &x)
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
        Ok(MembershipWitness {
            w, x
        })
    }

    /// Return a new membership witness. This is more efficient that `new` due to
    /// the ability to reduce by the totient
    pub fn with_secret_key<B: AsRef<[u8]>>(accumulator: &Accumulator, secret_key: &AccumulatorSecretKey, x: B) -> Self {
        let x = hash_to_prime(x.as_ref());
        if !accumulator.members.contains(&x) {
            return MembershipWitness {
                w: clone_bignum(&accumulator.value), x
            };
        }
        let totient = secret_key.totient();
        let exp = accumulator.members.par_iter()
            .map(|b| clone_bignum(b))
            .filter(|b| b != &x)
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
            w, x
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

        acc.remove_mut(&key, &members[0]).unwrap();

        assert_eq!(acc.value, witness.w);
    }
}