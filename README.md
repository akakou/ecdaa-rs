# ecdaa-rs

[![Rust](https://github.com/akakou/ecdaa-rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/akakou/ecdaa-rs/actions/workflows/rust.yml)

This is an ECDAA library written in rust language. 
ECDAA is a privacy-friendly signature scheme that is used for device attestation widely. 

If you needs information about ECDAA, please follow the websites:

What is ECDAA (Auther's blog)
- https://dev.to/akakou/daa-direct-anonymous-attestation-17i7

FIDO ECDAA
- https://fidoalliance.org/specs/common-specs/fido-ecdaa-algorithm-v2.1-ps-20220523.html

The original article of DAA
- https://eprint.iacr.org/2004/205.pdf

This library uses the [mcl](https://github.com/herumi/mcl) library for cryptographic computation.

Note: This library does not support fully unlinkable mode and forces the basename, but it may be updated shortly.

## Dependecies

This library requires a `clang` compiler to build. 

If you use Ubuntu, you can install it with the command ;
> apt install clang

## Note

This library expects that it is used for research, not the real world.  

Nevertheless, if you want to use this library for practical usages,   
**YOU NEED TO CHECK ITS CODES AND USE IT AT OWN RISK**.
