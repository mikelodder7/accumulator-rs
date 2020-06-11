use crate::hash::hash_to_prime;
#[cfg(not(test))]
use glass_pumpkin::safe_prime::new as gen_safe_prime;
use num_bigint::BigUint;
use rayon::prelude::*;
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Error as DError, Visitor}};
use std::{
    convert::TryFrom,
    fmt::Formatter,
    ops::Add,
    collections::BTreeSet,
};

const MIN_SIZE_PRIME: usize = 1024;
const FACTOR_SIZE: usize = MIN_SIZE_PRIME / 8;
const MIN_BYTES: usize = FACTOR_SIZE * 5 + 4;
const MEMBER_SIZE: usize = 32;

/// Represents the safe primes used in the modulus for the accumulator
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccumulatorSecretKey {
    /// Must be a safe prime with MIN_SIZE_PRIME bits
    p: BigUint,
    /// Must be a safe prime with MIN_SIZE_PRIME bits
    q: BigUint,
}

/// A universal RSA accumulator
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Accumulator {
    /// The initial value of the accumulator and the generator
    /// to be used for generating proofs
    generator: BigUint,
    /// The current set of members in the accumulator
    members: BTreeSet<BigUint>,
    /// The RSA modulus
    modulus: BigUint,
    /// The current accumulator value with all `members`
    value: BigUint,
}

impl Accumulator {
    /// Create a new accumulator
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize a new accumulator prefilled with entries
    pub fn with_members<M: AsRef<[B]>, B: AsRef<[u8]>>(m: M) -> Self {
        let m: Vec<&[u8]> = m.as_ref().iter().map(|b| b.as_ref()).collect();
        let members: BTreeSet<BigUint> = m.par_iter().map(|b| hash_to_prime(b)).collect();
        let primes = gen_primes();
        let totient = (&primes[1] - 1u64) * (&primes[2] - 1u64);

        // From section 3.2 in https://cs.brown.edu/people/alysyans/papers/camlys02.pdf
        // For Update of the accumulator value:
        // n = p * q
        // \varphi = (p - 1)(q -1)
        // To batch add values to the exponent, compute
        // \pi_add = (x_1 * ... * x_n) \mod (\varphi)
        // v ^ {\pi_add} mod n
        let modulus = &primes[1] * &primes[2];
        let exp = members.clone().into_par_iter().reduce(|| BigUint::from(1u64), |v, m| (v * m) % &totient);
        let value = primes[0].modpow(&exp, &modulus);
        Self {
            generator: primes[0].clone(),
            members,
            modulus,
            value
        }
    }

    /// Add a value to the accumulator, the value will be hashed to a prime number first
    pub fn insert<B: AsRef<[u8]>>(&self, value: B) -> Self {

        let p = hash_to_prime(value.as_ref());
        if self.members.contains(&p) {
            return self.clone();
        }
        let mut members = self.members.clone();
        members.insert(p.clone());
        let value = self.value.modpow(&p, &self.modulus);
        Self {
            generator: self.generator.clone(),
            members,
            modulus: self.modulus.clone(),
            value,
        }
    }

    /// Add a value an update this accumulator
    pub fn insert_mut<B: AsRef<[u8]>>(&mut self, value: B) {
        let p = hash_to_prime(value.as_ref());
        if self.members.contains(&p) {
            return;
        }
        self.members.insert(p.clone());
        self.value = self.value.modpow(&p, &self.modulus);
    }

    /// Convert accumulator to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FACTOR_SIZE * 5 + 4 + MEMBER_SIZE * self.members.len());

        out.append(b2fa(&self.generator, FACTOR_SIZE).as_mut());
        out.append(b2fa(&self.value, FACTOR_SIZE * 2).as_mut());
        out.append(b2fa(&self.modulus, FACTOR_SIZE * 2).as_mut());

        let m_len = self.members.len() as u32;
        out.extend_from_slice(m_len.to_be_bytes().as_ref());

        for b in &self.members {
            out.append(b2fa(b, MEMBER_SIZE).as_mut());
        }

        out
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        let primes = gen_primes();
        Self {
            generator: primes[0].clone(),
            members: BTreeSet::new(),
            modulus: primes[1].clone() * primes[2].clone(),
            value: primes[0].clone()
        }
    }
}

impl TryFrom<Vec<u8>> for Accumulator {
    type Error = String;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(data.as_slice())
    }
}

impl TryFrom<&[u8]> for Accumulator {
    type Error = String;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < MIN_BYTES {
            return Err(format!("Expected size {}, found {}", MIN_BYTES, data.len()));
        }

        let mut offset = 0;
        let mut end = FACTOR_SIZE;

        let generator = BigUint::from_bytes_be(&data[offset..end]);

        offset = end;
        end = offset + 2 * FACTOR_SIZE;

        let value = BigUint::from_bytes_be(&data[offset..end]);

        offset = end;
        end = offset + 2 * FACTOR_SIZE;

        let modulus = BigUint::from_bytes_be(&data[offset..end]);

        offset = end;
        end = offset + 4;

        let member_count = u32::from_be_bytes(*array_ref![data, offset, 4]) as usize;
        let mut members = BTreeSet::new();

        offset = end;
        end = offset + MEMBER_SIZE;
        for _ in 0..member_count {
            let m = BigUint::from_bytes_be(&data[offset..end]);
            members.insert(m);
            offset = end;
            end = offset + MEMBER_SIZE;
        }
        Ok(Self {
            generator,
            members,
            modulus,
            value
        })
    }
}

serdes_impl!(Accumulator);

macro_rules! add_impl {
    ($ty:ty,$c:expr) => {
        impl Add<$ty> for Accumulator {
            type Output = Self;

            fn add(self, rhs: $ty) -> Self::Output {
                self.insert($c(rhs))
            }
        }
    };
}

macro_rules! add_ref_impl {
    ($ty:ty, $c:expr) => {
        add_impl!($ty, $c);

        impl<'a> Add<$ty> for &'a Accumulator {
            type Output = Accumulator;

            fn add(self, rhs: $ty) -> Self::Output {
                self.insert($c(rhs))
            }
        }
    };
}

macro_rules! add_two_ref_impl {
    ($ty:ty, $c:expr) => {
        impl Add<&$ty> for Accumulator {
            type Output = Self;

            fn add(self, rhs: &$ty) -> Self::Output {
                self.insert($c(rhs))
            }
        }

        impl<'a, 'b> Add<&'b $ty> for &'a Accumulator {
            type Output = Accumulator;

            fn add(self, rhs: &'b $ty) -> Self::Output {
                self.insert($c(rhs))
            }
        }
    };
}

add_two_ref_impl!([u8], |rhs| rhs);
add_ref_impl!(BigUint, |rhs: BigUint| rhs.to_bytes_be());
add_ref_impl!(u64, |rhs: u64| rhs.to_be_bytes());
add_ref_impl!(u32, |rhs: u32| rhs.to_be_bytes());
add_ref_impl!(i64, |rhs: i64| rhs.to_be_bytes());
add_ref_impl!(i32, |rhs: i32| rhs.to_be_bytes());

impl Add<&str> for Accumulator {
    type Output = Self;

    fn add(self, rhs: &str) -> Self::Output {
        self.insert(rhs.as_bytes())
    }
}

impl<'a, 'b> Add<&'b str> for &'a Accumulator {
    type Output = Accumulator;

    fn add(self, rhs: &'b str) -> Self::Output {
        self.insert(rhs.as_bytes())
    }
}

/// BigUint to fixed array
fn b2fa(b: &BigUint, expected_size: usize) -> Vec<u8> {
    let mut t = vec![0u8; expected_size];
    let bt = b.to_bytes_be();
    assert!(expected_size >= bt.len(), format!("expected = {}, found = {}", expected_size, bt.len()));
    t[(expected_size - bt.len())..].clone_from_slice(bt.as_slice());
    t
}

#[cfg(not(test))]
fn gen_primes() -> Vec<BigUint> {
    (0..3).collect::<Vec<usize>>().par_iter().map(|_| {
        gen_safe_prime(MIN_SIZE_PRIME).unwrap()
    }).collect()
}

#[cfg(test)]
fn gen_primes() -> Vec<BigUint> {
    use num_traits::Num;
    // Taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
    // because Accumulator::default() takes a long time
    vec![
        (BigUint::from_str_radix("76510636706393288402973018952427795147470564193069829622069209003733997084159144803363853656280756946149118081932181243022097881139700081470010118851209205854189955701724297010704364322171383509487901918283958716896143288755442068220698957513740353994270435468688023965338050723270523965709917111415635591723", 10).unwrap()),
        (BigUint::from_str_radix("66295144163396665403376179086308918015255210762161712943347745256800426733181435998953954369657699924569095498869393378860769817738689910466139513014839505675023358799693196331874626976637176000078613744447569887988972970496824235261568439949705345174465781244618912962800788579976795988724553365066910412859", 10).unwrap() << 1) + 1u64,
        (BigUint::from_str_radix("37313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029", 10).unwrap() << 2) + 3u64
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_test() {
        let acc = Accumulator::default();
        let bytes = acc.to_bytes();
        assert_eq!(bytes.len(), MIN_BYTES);
        let res = Accumulator::try_from(bytes);
        assert!(res.is_ok());
        let acc2 = res.unwrap();
        assert_eq!(acc, acc2);
    }

    #[test]
    fn default_test() {
        let acc = Accumulator::default();
        assert_eq!(acc.generator, acc.value);
    }

    #[test]
    fn with_members_test() {
        let members: Vec<[u8; 8]> = vec![3u64.to_be_bytes(), 7u64.to_be_bytes(), 11u64.to_be_bytes(), 13u64.to_be_bytes()];
        let mut acc = Accumulator::default();
        for m in &members {
            acc.insert_mut(m);
        }
        let acc1 = Accumulator::with_members(members.as_slice());
        assert_eq!(acc.value, acc1.value);
    }

    #[test]
    fn add_biguint_test() {
        let biguint = BigUint::from(345_617_283_975_612_837_561_827_365u128);
        let acc = Accumulator::new();
        let acc1 = &acc + biguint;
        assert_ne!(acc1.value, acc.value);
    }

    #[test]
    fn add_string_test() {
        let acc = Accumulator::new();
        let acc1 = &acc + "a test to see if my value is in the accumulator";
        assert_ne!(acc1.value, acc.value);
    }

    #[test]
    fn add_u64_test() {
        let acc = Accumulator::new();
        let acc1 = &acc + 12_345_678_987_654u64;
        assert_ne!(acc1.value, acc.value);
    }

    #[test]
    fn add_u32_test() {
        let acc = Accumulator::new();
        let acc1 = &acc + 123_456_789u32;
        assert_ne!(acc1.value, acc.value);
    }

    #[test]
    fn add_i64_test() {
        let acc = Accumulator::new();
        let acc1 = &acc + 12_345_678_987_654i64;
        assert_ne!(acc1.value, acc.value);
    }

    #[test]
    fn add_i32_test() {
        let acc = Accumulator::new();
        let acc1 = &acc + 123_456_789i32;
        assert_ne!(acc1.value, acc.value);
    }
}