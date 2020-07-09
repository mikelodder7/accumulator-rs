use crate::{
    accumulator::Accumulator, b2fa, nonwitness::NonMembershipWitness, Poke2Proof, FACTOR_SIZE,
};
use common::{bigint::BigInteger, error::*, Field};
use std::convert::TryFrom;

/// A proof of knowledge of exponents non-membership proof
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NonMembershipProof {
    v: BigInteger,
    proof_v: Poke2Proof,
    proof_g: Poke2Proof,
}

impl NonMembershipProof {
    /// Create a new PoKE2 proof
    pub fn new<B: AsRef<[u8]>>(
        witness: &NonMembershipWitness,
        accumulator: &Accumulator,
        nonce: B,
    ) -> Self {
        let f = Field::new(&accumulator.modulus);
        let v = f.exp(&accumulator.value, &witness.a);
        let v_inv = f.inv(&v);
        let gv_inv = f.mul(&accumulator.generator, &v_inv);
        let nonce = nonce.as_ref();
        let proof_v = Poke2Proof::new(&witness.a, &accumulator.value, &v, &accumulator, nonce);
        let proof_g = Poke2Proof::new(&witness.x, &witness.b, &gv_inv, &accumulator, nonce);
        Self {
            v,
            proof_v,
            proof_g,
        }
    }

    /// Verify a set membership proof
    pub fn verify<B: AsRef<[u8]>>(&self, accumulator: &Accumulator, nonce: B) -> bool {
        let nonce = nonce.as_ref();
        let f = Field::new(&accumulator.modulus);
        let v_inv = f.inv(&self.v);
        let gv_inv = f.mul(&accumulator.generator, &v_inv);
        // Copy the latest value of the accumulator so the proof will fail if
        // the accumulator value has changed since the proof was created
        let proof_v = Poke2Proof {
            u: accumulator.value.clone(),
            r: self.proof_v.r.clone(),
            q: self.proof_v.q.clone(),
            z: self.proof_v.z.clone(),
        };
        let v_res = proof_v.verify_with(&self.v, &accumulator, nonce);
        let g_res = self.proof_g.verify_with(&gv_inv, &accumulator, nonce);
        g_res && v_res
        // self.proof_g.verify(&accumulator, nonce) &&
        //     self.proof_v.verify(&accumulator, nonce)
    }

    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.v, 2 * FACTOR_SIZE);
        // TODO: proof_v.u is the same as the current accumulator, no need to store that
        // possible optimization later?
        output.append(&mut self.proof_v.to_bytes());
        output.append(&mut self.proof_g.to_bytes());
        output
    }
}

impl TryFrom<&[u8]> for NonMembershipProof {
    type Error = AccumulatorError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() != Poke2Proof::SIZE_BYTES * 2 + 2 * FACTOR_SIZE {
            return Err(AccumulatorErrorKind::SerializationError.into());
        }
        let offset = 2 * FACTOR_SIZE;
        let v = BigInteger::try_from(&data[..offset])?;
        let end = offset + Poke2Proof::SIZE_BYTES;
        let proof_v = Poke2Proof::try_from(&data[offset..end])?;
        let proof_g = Poke2Proof::try_from(&data[end..])?;
        Ok(Self {
            v,
            proof_v,
            proof_g,
        })
    }
}

serdes_impl!(NonMembershipProof);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey;

    #[test]
    fn proof_test() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            3u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let member = 17u64.to_be_bytes();
        let mut acc = Accumulator::with_members(&key, &members);
        let witness = NonMembershipWitness::new(&acc, &member).unwrap();
        let nonce = b"proof_test";

        let proof = NonMembershipProof::new(&witness, &acc, nonce);
        assert!(proof.verify(&acc, nonce));
        acc += 17u64;

        assert!(!proof.verify(&acc, nonce));
        assert_eq!(
            proof.to_bytes().len(),
            2 * Poke2Proof::SIZE_BYTES + 2 * FACTOR_SIZE
        );
    }
}
