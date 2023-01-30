// use mcl_rust::G2;

use crate::issuer::*;
use crate::join::*;
use crate::utils::*;

#[test]
fn test_gen_issuer() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);

    ipk.is_valid().unwrap();
}

#[test]
fn test_req_join() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);

    let m = gen_seed_for_join();
    let req = ReqForJoin::random(&m, &ipk);

    req.is_valid(&m).unwrap();
}

#[test]
fn test_cred() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);

    let m = gen_seed_for_join();
    let req = ReqForJoin::random(&m, &ipk);

    let cred = Credential::with_no_encryption(&req, &m, &isk);
    cred.is_valid(&ipk).unwrap();
}
