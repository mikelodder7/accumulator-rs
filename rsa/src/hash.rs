use blake2::{Blake2b, Digest};
use openssl::bn::*;

/// Hashes `input` to a prime.
/// See Section 7 in
/// <https://eprint.iacr.org/2018/1188.pdf>
pub(crate) fn hash_to_prime<B: AsRef<[u8]>>(input: B) -> BigNum {
    let mut input = input.as_ref().to_vec();
    let mut i = 1usize;
    let offset = input.len();
    input.extend_from_slice(&i.to_be_bytes()[..]);
    let end = input.len();
    let mut ctx = BigNumContext::new().unwrap();

    let mut num;

    loop {
        let mut hash = Blake2b::digest(input.as_slice());
        // Force it to be odd
        hash[63] |= 1;
        // Only need 256 bits just borrow the bottom 32 bytes
        // There should be plenty of primes below 2^256
        // and we want this to be reasonably fast
        num = BigNum::from_slice(&hash[32..]).unwrap();
        if num.is_prime(15, &mut ctx).unwrap() {
            break;
        }
        i += 1;
        let i_bytes = i.to_be_bytes();
        input[offset..end].clone_from_slice(&i_bytes[..]);
    }
    num
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;
    use gmp::mpz::{Mpz, ProbabPrimeResult};

    #[test]
    fn test_hash() {
        let t = hash_to_prime(b"This is a test to find a prime");
        let n = Mpz::from(t.to_vec().as_slice());
        assert!(n.probab_prime(15) != ProbabPrimeResult::NotPrime);
        let mut bytes = vec![0u8; 32];
        for _ in 0..10 {
            thread_rng().fill_bytes(bytes.as_mut_slice());
            let t = hash_to_prime(&bytes);
            let n = Mpz::from(t.to_vec().as_slice());
            assert!(n.probab_prime(15) != ProbabPrimeResult::NotPrime);
        }
    }
}