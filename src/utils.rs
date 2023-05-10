use alloc::vec::{self, Vec};
use fp256bn_amcl::fp256bn;
use fp256bn_amcl::fp256bn::big::{BIG, NLEN};
use fp256bn_amcl::fp256bn::ecp::ECP;
use fp256bn_amcl::fp256bn::ecp2::ECP2;
use fp256bn_amcl::fp256bn::rom::CURVE_ORDER;

pub fn p() -> BIG {
    let v_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            CURVE_ORDER.to_vec().as_ptr() as *const u8,
            &CURVE_ORDER.to_vec().len() * core::mem::size_of::<i64>(),
        )
    };

    fp256bn::big::BIG::frombytes(v_bytes)
}

pub fn g1() -> ECP {
    ECP::generator()
}

pub fn g2() -> ECP2 {
    ECP2::generator()
}

pub fn export_ecp(ecp: &ECP) -> Vec<u8> {
    let mut result = [0; 33];
    ecp.tobytes(&mut result, true);
    return result.to_vec();
}

pub fn export_ecp2(ecp2: &ECP2) -> Vec<u8> {
    let mut result = [0; 65];
    ecp2.tobytes(&mut result, true);
    return result.to_vec();
}

// pub fn rand_fr(rng: &RAND) -> BIG {
//     let mut rng = big::thread_rng();

//     let mut fr = unsafe { Fr::uninit() };
//     fr.set_by_csprng();

//     fr
// }

// pub fn g1() -> G1 {
//     let mut g1 = G1::zero();
//     g1.set_hash_of(&[1]);
//     g1
// }

// pub fn g2() -> G2 {
//     let mut g2 = G2::zero();
//     g2.set_hash_of(&[1]);
//     g2
// }
