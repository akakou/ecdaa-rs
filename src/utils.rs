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

pub fn rand_fr(rng: &mut impl RngCore) -> Fr {
    mcl_initalize();

    let mut x = Fr::zero();

    let mut d = vec![0; 32];
    rng.fill_bytes(&mut d);
    x.set_little_endian_mod(&d);
    
    x
}
