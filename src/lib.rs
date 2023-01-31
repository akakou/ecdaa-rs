// #![no_std]
extern crate alloc;

type EcdaaError = Result<(), String>;

pub mod cred;
pub mod issuer;
pub mod req_for_join;
pub mod schnorr;
pub mod signature;
pub mod utils;

#[cfg(test)]
mod tests;
