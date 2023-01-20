use alloc::vec;
use mcl_rust::{get_curve_order, CurveType, Fp, Fp2, Fr, G2};

static mut mcl_initialized: bool = false;

pub fn initalize_mcl() {
    unsafe {
        if !mcl_initialized {
            mcl_rust::init(CurveType::BN254);
            mcl_initialized = true;
        }
    }
}

pub fn rand_fr() -> Fr {
    let mut fr = unsafe { Fr::uninit() };
    fr.set_by_csprng();

    fr
}

pub fn g2() -> G2 {
    let mut g2 = G2::zero();
    g2.set_hash_of(&[1]);
    return g2;
}
