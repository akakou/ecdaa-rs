extern crate alloc;
extern crate serde;

type EcdaaError = Result<(), u32>;

pub use fp256bn_amcl;
pub mod cred;
pub mod issuer;
pub mod join;
pub mod schnorr;
pub mod signature;
mod utils;

#[cfg(test)]
mod tests;
