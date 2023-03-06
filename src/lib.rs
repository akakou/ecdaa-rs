#![no_std]

use alloc::string::String;
use mcl_rust::CurveType;
extern crate alloc;

static mut MCL_INITIALIZED: bool = false;

type EcdaaError = Result<(), String>;

pub fn initalize_mcl() {
    unsafe {
        if !MCL_INITIALIZED {
            mcl_rust::init(CurveType::BN254);
            MCL_INITIALIZED = true;
        }
    }
}

pub mod cred;
pub mod issuer;
pub mod join;
pub mod schnorr;
pub mod signature;
mod utils;

#[cfg(test)]
mod tests;
