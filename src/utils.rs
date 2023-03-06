use mcl_rust::{CurveType, Fr, G1, G2};

pub fn rand_fr() -> Fr {
    let mut fr = unsafe { Fr::uninit() };
    fr.set_by_csprng();

    fr
}

pub fn g1() -> G1 {
    let mut g1 = G1::zero();
    g1.set_hash_of(&[1]);
    g1
}

pub fn g2() -> G2 {
    let mut g2 = G2::zero();
    g2.set_hash_of(&[1]);
    g2
}
