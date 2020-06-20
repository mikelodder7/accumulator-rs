use crate::{
    clone_bignum,
    accumulator::Accumulator,
    hash::hash_to_prime,
    witness::MembershipWitness,
};
use blake2::{Blake2b, Digest};
use openssl::bn::*;

/// A proof of knowledge of exponents membership proof
#[derive(Debug , Eq, PartialEq)]
pub struct MembershipProof {
    witness: BigNum,
    z: BigNum,
    q: BigNum,
    r: BigNum
}

impl MembershipProof {
    /// Create a new PoKE2 proof
    pub fn new<B: AsRef<[u8]>>(witness: &MembershipWitness, accumulator: &Accumulator, nonce: B) -> Self {
        let mut ctx = BigNumContext::new().unwrap();
        let mut z = BigNum::new().unwrap();
        // z = g^x
        BigNumRef::mod_exp(&mut z, &accumulator.generator, &witness.x, &accumulator.modulus, &mut ctx).unwrap();

        let mut data = accumulator.generator.to_vec();
        data.append(&mut accumulator.modulus.to_vec());
        data.append(&mut accumulator.value.to_vec());
        data.append(&mut witness.w.to_vec());
        data.append(&mut z.to_vec());
        data.extend_from_slice(nonce.as_ref());

        // l = H2P( g || m || v || u || z || n1 )
        let l = hash_to_prime(data.as_slice());

        data.append(&mut l.to_vec());

        // Fiat-Shamir
        // x = H(g || m || v || u || z || n1 || l)
        let x = BigNum::from_slice(Blake2b::digest(data.as_slice()).as_slice()).unwrap();
        let mut whole = BigNum::new().unwrap();
        let mut r= BigNum::new().unwrap();

        // q = x / l
        BigNumRef::checked_div(&mut whole, &witness.x, &l, &mut ctx).unwrap();
        // r = x % l
        BigNumRef::checked_rem(&mut r, &witness.x, &l, &mut ctx).unwrap();

        let mut q1 = BigNum::new().unwrap();
        let mut q2 = BigNum::new().unwrap();
        let mut q = BigNum::new().unwrap();

        let mut t = BigNum::new().unwrap();
        // q * alpha
        BigNumRef::checked_mul(&mut t, &x, &whole, &mut ctx).unwrap();

        // u ^ q
        BigNumRef::mod_exp(&mut q1, &witness.w, &q, &accumulator.modulus, &mut ctx).unwrap();
        // g ^ {q * alpha}
        BigNumRef::mod_exp(&mut q2, &accumulator.generator, &t, &accumulator.modulus, &mut ctx).unwrap();
        // Q = u ^ q * g ^ {q * alpha}
        BigNumRef::mod_mul(&mut q, &q1, &q2, &accumulator.modulus, &mut ctx).unwrap();
        MembershipProof {
            witness: clone_bignum(&witness.w),
            z,
            q,
            r
        }
    }

    /// Verify a set membership proof
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        let mut data = accumulator.generator.to_vec();
        data.append(&mut accumulator.modulus.to_vec());
        data.append(&mut accumulator.value.to_vec());
        data.append(&mut self.witness.to_vec());
        data.append(&mut self.z.to_vec());
        data.extend_from_slice(nonce.as_ref());

        // l = H2P(g || m || v || u || z || n1)
        let l = hash_to_prime(data.as_slice());
        data.append(&mut l.to_vec());

        // Fiat-Shamir
        // x = H(g || m || v || u || z || n1 || l)
        let x = BigNum::from_slice(Blake2b::digest(data.as_slice()).as_slice()).unwrap();

        let mut p1 = BigNum::new().unwrap();
        let mut p2 = BigNum::new().unwrap();
        let mut p3 = BigNum::new().unwrap();
        let mut p4 = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();

        // Q ^ l
        BigNumRef::mod_exp(&mut p1, &self.q, &l, &accumulator.modulus, &mut ctx).unwrap();
        // u ^ r
        BigNumRef::mod_exp(&mut p2, &self.witness, &self.r, &accumulator.modulus, &mut ctx).unwrap();
        // x * r
        BigNumRef::checked_mul(&mut p4, &x, &self.r, &mut ctx).unwrap();
        // g ^ {x * r}
        BigNumRef::mod_exp(&mut p3, &accumulator.generator, &p4, &accumulator.modulus, &mut ctx).unwrap();

        let mut left = BigNum::new().unwrap();
        // Q^l * u^r * g^{x * r}
        BigNumRef::mod_mul(&mut p4, &p1, &p2, &accumulator.modulus, &mut ctx).unwrap();
        BigNumRef::mod_mul(&mut left, &p3, &p4, &accumulator.modulus, &mut ctx).unwrap();

        // v * z^x
        let mut right = BigNum::new().unwrap();
        BigNumRef::mod_exp(&mut p4, &self.z, &x, &accumulator.modulus, &mut ctx).unwrap();
        BigNumRef::mod_mul(&mut right, &p4, &accumulator.value, &accumulator.modulus, &mut ctx).unwrap();

        left == right
    }
}