use crate::{
    accumulator::Accumulator,
    hash_to_prime,
    b2fa,
    FACTOR_SIZE,
    MEMBER_SIZE
};
use common::{
    bigint::BigInteger,
    error::*,
};
use rayon::prelude::*;

/// A witness that can be used for non-membership proofs
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NonMembershipWitness {
    pub(crate) a: BigInteger,
    pub(crate) b: BigInteger,
    pub(crate) x: BigInteger,
}

impl NonMembershipWitness {
    /// Return a new non-membership witness
    pub fn new<B: AsRef<[u8]>>(accumulator: &Accumulator, x: B) -> Result<Self, AccumulatorError> {
        let x = hash_to_prime(x.as_ref());
        Self::new_prime(accumulator, &x)
    }

    /// Return a new non-membership witness with a value that is already prime
    pub fn new_prime(accumulator: &Accumulator, x: &BigInteger) -> Result<Self, AccumulatorError> {
        if accumulator.members.contains(&x) {
            return Err(AccumulatorError::from_msg(
                AccumulatorErrorKind::InvalidMemberSupplied,
                "value is in the accumulator",
            ));
        }
        let s: BigInteger = accumulator
            .members
            .par_iter()
            .product();
        let gcd_res = s.bezouts_coefficients(x);

        Ok(Self {
            a: gcd_res.a,
            b: (&accumulator.generator).mod_exp(&gcd_res.b, &accumulator.modulus),
            x: x.clone(),
        })
    }

    // /// Create a new witness to match `new_acc` from `old_acc` using this witness
    // /// by applying the methods found in 4.2 in
    // /// <https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf>
    // pub fn update(&self, old_acc: &Accumulator, new_acc: &Accumulator) -> Result<Self, AccumulatorError> {
    //     let mut w = self.clone();
    //     w.update_assign(old_acc, new_acc)?;
    //     Ok(w)
    // }
    //
    // /// Update this witness to match `new_acc` from `old_acc`
    // /// by applying the methods found in 4.2 in
    // /// <https://www.cs.purdue.edu/homes/ninghui/papers/accumulator_acns07.pdf>
    // pub fn update_assign(&mut self, old_acc: &Accumulator, new_acc: &Accumulator) -> Result<(), AccumulatorError> {
    //     if !new_acc.members.contains(&self.x) {
    //         return Err(AccumulatorErrorKind::InvalidMemberSupplied.into());
    //     }
    //     if !old_acc.members.contains(&self.x) {
    //         return Err(AccumulatorErrorKind::InvalidMemberSupplied.into());
    //     }
    //
    //     let additions: Vec<&BigInteger> = new_acc.members.difference(&old_acc.members).collect();
    //     let deletions: Vec<&BigInteger> = old_acc.members.difference(&new_acc.members).collect();
    //     let x: BigInteger = new_acc.members.par_iter().product();
    //     let x_hat = deletions.into_par_iter().product();
    //     let x_a = additions.into_par_iter().product();
    //
    //     let gcd_res = x.bezouts_coefficients(&x_hat);
    //     assert_eq!(gcd_res.value, BigInteger::from(1u32));
    //     let f = Field::new(&new_acc.modulus);
    //
    //     self.u = f.mul(
    //         &f.exp(&f.exp(&self.u, &x_a), &gcd_res.b),
    //         &f.exp(&new_acc.value, &gcd_res.a),
    //     );
    //     Ok(())
    // }
    //
    /// Serialize this to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = b2fa(&self.a, FACTOR_SIZE * 2);
        output.append(&mut b2fa(&self.b, FACTOR_SIZE * 2));
        output.append(&mut b2fa(&self.x, MEMBER_SIZE));
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::AccumulatorSecretKey;

    #[test]
    fn witnesses() {
        let key = AccumulatorSecretKey::default();
        let members: Vec<[u8; 8]> = vec![
            3u64.to_be_bytes(),
            7u64.to_be_bytes(),
            11u64.to_be_bytes(),
            13u64.to_be_bytes(),
        ];
        let member = 17u64.to_be_bytes();
        let acc = Accumulator::with_members(&key, &members);
        let witness = NonMembershipWitness::new(&acc, &member).unwrap();
        let x = hash_to_prime(&member);
        assert_eq!(witness.x, x);
        assert_eq!(witness.a, BigInteger::from("15795998627841229596746791978738735879500608346691682615375569238309284887513"));
        assert_eq!(witness.b, BigInteger::from("6388326997732524861157518981293465348126497224448224262899188532204238407926532196045325248196972846806947720340521784938389014005663302337262427886146089488840725520453702779222204754092861965365585545163578729266631568761125702734412168237307421720677183700888938471137124110944346634396607732586727642165029849092492022242344835576192376600778666980586195770904801446657862109479980888723780837336205065718097700798928910065564613160557112440577753800406030377186114098712828892503060592905025686768606679731772102776289644694522991421550919174447634643520414913404966680048474966211610900737010091996857902429565"));

        assert_eq!(witness.to_bytes().len(), 4 * FACTOR_SIZE + MEMBER_SIZE);
    }
}