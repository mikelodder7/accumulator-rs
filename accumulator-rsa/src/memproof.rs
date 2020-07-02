use crate::{
    accumulator::Accumulator,
    hash::hash_to_prime,
    witness::MembershipWitness,
};
use blake2::{Blake2b, Digest};
use common::bigint::BigInteger;
use std::convert::TryFrom;

/// A proof of knowledge of exponents membership proof
#[derive(Debug , Eq, PartialEq)]
pub struct MembershipProof {
    u: BigInteger,
    z: BigInteger,
    q: BigInteger,
    r: BigInteger
}

impl MembershipProof {
    /// Create a new PoKE2 proof
    pub fn new<B: AsRef<[u8]>>(witness: &MembershipWitness, accumulator: &Accumulator, nonce: B) -> Self {
        let f = common::Field::new(&accumulator.modulus);
        let z = f.exp(&accumulator.generator,&witness.x);

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
        let q1 = f.exp(&witness.u,&whole);
        // g ^ {q * alpha}
        let q2 = f.exp(&accumulator.generator, &(&x * &whole));
        // Q = u ^ q * g ^ {q * alpha}
        let q = f.mul(&q1,&q2);
        MembershipProof {
            u: witness.u.clone(),
            z,
            q,
            r
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
        let p3 = f.exp(&accumulator.generator,&(&x * &self.r));

        // Q^l * u^r * g^{x * r}
        let left = f.mul(&p1, &f.mul(&p2,&p3));

        // v * z^x
        let right = f.mul(&accumulator.value,&f.exp(&self.z,&x));

        left == right
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey;

    #[test]
    fn proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![3u64.to_be_bytes(), 7u64.to_be_bytes(), 11u64.to_be_bytes(), 13u64.to_be_bytes()];
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = MembershipWitness::new(&acc, &members[0]).unwrap();
        let nonce = b"proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_mut(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
    }

    #[test]
    fn big_proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = (0..100_000u64).collect::<Vec<u64>>().iter().map(|i| i.to_be_bytes()).collect();
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = MembershipWitness::new(&acc, &members[0]).unwrap();
        let nonce = b"big_proof_test";

        let proof = MembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc.remove_mut(&key, &members[0]).unwrap();

        assert!(!proof.verify(&acc, nonce));
    }
}