# accumulator-rs
Cryptographic Accumulators in Rust

A cryptographic accumulator allows for testing set membership without revealing which set member was tested. This avoids the need to check every member to see if a value exists and compress into a small value. Provers use a witness that a specific value is or is not in the set and generate a zero-knowledge proof.

There are three constructions for accumulators as referenced [Zero-Knowledge Proofs for Set Membership](https://eprint.iacr.org/2019/1255.pdf)

1. RSA-Based: Requires groups of unknown order and can be slow to create but offers reasonable performance for witness updates and proof generation and verification. Each element must be prime number and the modulus must be large enough to be secure (≥ 2048-bits). Elements do not have to be know in advance and can be added on-the-fly. Setup parameters include generating prime numbers for the modulus.
1. Elliptic-Curve Pairing-Based: Accumulators proofs are smaller and faster to compute that RSA-Based. Setup parameters are large and sets are number of elements allowed is fixed after creation.
1. Merkle Tree-Based: Setup parameters tend to be short and the accumulator size depends on the depth of the tree and the representation of the leaves.

This project aims to implement each one and compare their sizes, performance, and complexity.

# Author

Michael Lodder

# License

Licensed under either of
 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
