/// Use Big Integer implementation backed by OpenSSL BigNum
#[cfg(feature = "openssl")]
pub mod ossl;
/// Use Big Integer implementation backed by GMP Mpz
#[cfg(feature = "rust-gmp")]
pub mod mpz;
/// Use Big Integer implementation backed by rust's num-bigint
#[cfg(feature = "bigint-rust")]
pub mod rust;

#[cfg(feature = "openssl")]
pub use ossl::OsslBigInt as BigInteger;

