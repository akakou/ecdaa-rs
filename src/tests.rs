use crate::{cred::*, issuer::*, req_for_join::*, signature::*, utils::*};

#[test]
fn test_ok() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::generate(&isk);
    ipk.valid().unwrap();

    let m = gen_seed_for_join();
    let (req, sk) = ReqForJoin::generate(&m);
    req.valid(&m).unwrap();

    let cred = Credential::with_no_encryption(&req, &m, &isk);
    cred.valid(&ipk).unwrap();

    let signature = Signature::generate(&m, &sk, &cred);
    signature.valid(&m, &ipk).unwrap()
}
