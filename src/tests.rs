use crate::{cred::*, initalize_mcl, issuer::*, join::*, signature::*};

#[test]
fn test_ok() {
    initalize_mcl();

    let isk = ISK::random();
    let ipk = IPK::generate(&isk);
    ipk.valid().unwrap();

    let m = gen_seed_for_join().serialize();
    let (req, sk) = ReqForJoin::generate(&m);
    req.valid(&m).unwrap();

    let cred = Credential::with_no_encryption(&req, &m, &isk);
    cred.valid(&ipk).unwrap();

    let signature = Signature::generate(&m, &m, &sk, &cred);
    signature.valid(&m, &m, &ipk).unwrap()
}
