use crate::{
    accumulator::Accumulator, b2fa, common::error::*, hash::hash_to_prime,
    witness::MembershipWitness, FACTOR_SIZE, MEMBER_SIZE,
};
use blake2::{Blake2b, Digest};
use common::bigint::BigInteger;
use std::convert::TryFrom;

/// A proof of knowledge of exponents membership proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MembershipProof {
    u: BigInteger,
    z: BigInteger,
    q: BigInteger,
    r: BigInteger,
}

impl MembershipProof {
    /// Create a new PoKE2 proof
    pub fn new<B: AsRef<[u8]>>(
        witness: &MembershipWitness,
        accumulator: &Accumulator,
        nonce: B,
    ) -> Self {
        let f = common::Field::new(&accumulator.modulus);
        let z = f.exp(&accumulator.generator, &witness.x);

        let mut data = accumulator.generator.to_bytes();
        data.append(&mut accumulator.modulus.to_bytes());
        data.append(&mut accumulator.value.to_bytes());
        data.append(&mut witness.u.to_bytes());
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
        let (whole, r) = BigInteger::div_rem(&witness.x, &l);

        // u ^ q
        let q1 = f.exp(&witness.u, &whole);
        // g ^ {q * alpha}
        let q2 = f.exp(&accumulator.generator, &(&x * &whole));
        // Q = u ^ q * g ^ {q * alpha}
        let q = f.mul(&q1, &q2);
        MembershipProof {
            u: witness.u.clone(),
            z,
            q,
            r,
        }
    }

    /// Verify a set membership proof
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        let mut data = accumulator.generator.to_bytes();
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

        let f = common::Field::new(&accumulator.modulus);

        // Q ^ l
        let p1 = f.exp(&self.q, &l);
        // u ^ r
        let p2 = f.exp(&self.u, &self.r);
        // x * r
        // g ^ {x * r}
        let p3 = f.exp(&accumulator.generator, &(&x * &self.r));

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

impl TryFrom<&[u8]> for MembershipProof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != FACTOR_SIZE * 3 + MEMBER_SIZE {
            return Err(AccumulatorErrorKind::SerializationError.into());
        }
        let u = BigInteger::try_from(&data[..(2 * FACTOR_SIZE)])?;
        let z = BigInteger::try_from(&data[(2 * FACTOR_SIZE)..(4 * FACTOR_SIZE)])?;
        let q = BigInteger::try_from(&data[(4 * FACTOR_SIZE)..(6 * FACTOR_SIZE)])?;
        let r = BigInteger::try_from(&data[(6 * FACTOR_SIZE)..])?;
        Ok(Self { u, z, q, r })
    }
}

serdes_impl!(MembershipProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey;
    use crate::MEMBER_SIZE_BITS;
    use rayon::prelude::*;

    #[test]
    fn proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            3u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = MembershipWitness::new(&acc, &members[0]).unwrap();
        let nonce = b"proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_assign(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
        assert_eq!(proof.to_bytes().len(), 6 * FACTOR_SIZE + MEMBER_SIZE);
    }

    #[test]
    fn big_proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<BigInteger> = (0..1_000)
            .collect::<Vec<_>>()
            .par_iter()
            .map(|_| BigInteger::generate_prime(MEMBER_SIZE_BITS))
            .collect();
        let mut acc = Accumulator::with_prime_members(&key, &members).unwrap();
        let witness = MembershipWitness::new_prime(&acc, &members[0]).unwrap();
        let nonce = b"big_proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_prime_assign(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
    }
}
