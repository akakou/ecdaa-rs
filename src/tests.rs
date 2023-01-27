// use mcl_rust::G2;

use crate::issuer::*;
use crate::join::*;
use crate::utils::*;

#[test]
fn test_gen_issuer() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);

    match ipk.is_valid() {
        Ok(_) => {}
        Err(e) => {
            panic!("{}", e)
        }
    }
}

#[test]
fn test_req_join() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);

    let m = gen_seed_for_join();
    let req = ReqForJoin::random(&m, &ipk);

    match req.is_valid(&m) {
        Ok(_) => {}
        Err(e) => {
            panic!("{}", e)
        }
    }
}
