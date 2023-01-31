use crate::{cred::*, issuer::*, req_for_join::*, req_for_join::*, signature::*, utils::*};

#[test]
fn test_ok() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::random(&isk);
    ipk.is_valid().unwrap();

    let m = gen_seed_for_join();
    let (req, sk) = ReqForJoin::random(&m, &ipk);
    req.is_valid(&m).unwrap();

    let cred = Credential::with_no_encryption(&req, &m, &isk);
    cred.is_valid(&ipk).unwrap();

    let signature = Signature::random(&m, &sk, &cred, &ipk);
    signature.is_valid(&m).unwrap()
}
