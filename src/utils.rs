use alloc::vec::Vec;
use fp256bn_amcl::fp256bn::big::BIG;
use fp256bn_amcl::fp256bn::ecp::ECP;
use fp256bn_amcl::fp256bn::ecp2::ECP2;
use fp256bn_amcl::fp256bn::rom::{CURVE_COF_I, CURVE_ORDER};
use fp256bn_amcl::sha3::{HASH256, SHA3};

use crate::EcdaaError;

pub fn p() -> BIG {
    BIG::new_ints(&CURVE_ORDER)
}

// pub fn g1() -> ECP {
//     ECP::generator()
// }

pub fn g2() -> ECP2 {
    ECP2::generator()
}

pub fn export_big(big: &BIG) -> Vec<u8> {
    let mut result = [0; 32];
    big.tobytes(&mut result);
    return result.to_vec();
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

pub fn hash_to_ecp(base: &[u8]) -> Result<(ECP, u8), EcdaaError> {
    let mut buf = base.to_vec();

    for i in 0..232 {
        let i: u8 = i;
        buf.push(i);

        let mut sha = SHA3::new(HASH256);
        sha.process_array(&buf);
        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c = BIG::frombytes(&digest.to_vec());

        let ecp = ECP::new_big(&c);
        ecp.mul(&BIG::new_int(CURVE_COF_I));

        if !ecp.is_infinity() {
            return Ok((ecp, i));
        }

        buf.pop();
    }

    Err(EcdaaError::HashingFailed)
}
