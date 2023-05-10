// use alloc::string::String;
// use mcl_rust::CurveType;
extern crate alloc;

type EcdaaError = Result<(), u32>;

// pub unsafe fn initalize_mcl() {
//     mcl_rust::init(CurveType::BN254);
// }

// pub mod cred;
pub mod issuer;
// pub mod join;
pub mod schnorr;
// pub mod signature;
mod utils;

#[cfg(test)]
mod tests;
