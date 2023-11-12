# ecdaa-rs

[![Rust](https://github.com/akakou/ecdaa-rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/akakou/ecdaa-rs/actions/workflows/rust.yml)

This is an ECDAA library written in rust language.   
ECDAA is a privacy-friendly signature scheme that is used for device attestation widely. 

If you needs information about ECDAA, please follow the websites:

- Auther's blog
  - https://dev.to/akakou/daa-direct-anonymous-attestation-17i7

- FIDO ECDAA specfitication
  - https://fidoalliance.org/specs/common-specs/fido-ecdaa-algorithm-v2.1-ps-20220523.html

- Original article of DAA
  - https://eprint.iacr.org/2004/205.pdf

This library uses the [forked amcl](https://github.com/akakou-fork/fp256bn-amcl/tree/serde) library for cryptographic computation.


## Note

This library is just for research, not real world.  

If you want to use this library for practical usages,   
**YOU NEED TO CHECK ITS CODES AND USE IT AT OWN RISK**.
