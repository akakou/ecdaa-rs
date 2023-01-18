use alloc::vec;
use mcl_rust::{Fr, CurveType, get_curve_order};
use rand::RngCore;

static mut mcl_initialized : bool = false;

pub fn mcl_initalize() {
    unsafe {
        if !mcl_initialized {
            mcl_rust::init(CurveType::BN254);
            mcl_initialized = true;
        }
    }
}

