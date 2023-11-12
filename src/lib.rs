extern crate alloc;
extern crate serde;

#[derive(Debug)]
pub enum EcdaaError {
    InvalidSchnorrProof,
    InvalidPublicKey,
    InvalidCredential1,
    InvalidCredential2,
    KNotInSignature,
    HashingFailed,
}

pub use fp256bn_amcl;
pub mod cred;
pub mod issuer;
pub mod join;
pub mod schnorr;
pub mod signature;
mod utils;

#[cfg(test)]
mod tests;
