use fp256bn_amcl::rand::RAND;

use crate::{
    cred::{Credential, RandomizedCredential},
    issuer::{IPK, ISK},
    join::ReqForJoin,
    signature::Signature,
};

#[test]
fn test_ok() {
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND::new();

    rng.clean();
    for i in 0..100 {
        raw[i] = i as u8
    }

    rng.seed(100, &raw);

    let isk = ISK::random(&mut rng);
    let ipk = IPK::random(&isk, &mut rng);

    ipk.valid().expect("ipk");

    let m = vec![0, 2, 3];
    let basename = vec![0, 2, 3, 4];
    let req = ReqForJoin::random(&m, &mut rng).unwrap();

    req.0.valid(&m).expect("req");

    let sk = req.1;

    let cred = Credential::with_no_encryption(&req.0, &m, &isk).unwrap();
    cred.valid(&ipk).expect("cred");

    let rand_cred = RandomizedCredential::randomize(&cred, &mut rng);
    rand_cred.valid(&ipk).expect("rand cred");

    let signature = Signature::sign(&m, &basename, &sk, &cred, true, &mut rng).unwrap();

    match signature.verify(&m, &basename, &ipk, true) {
        Err(e) => panic!("error: {}", e),
        _ => (),
    }

    match signature.verify(&basename, &basename, &ipk, true) {
        Err(e) => {}
        _ => panic!("error: should fail"),
    }

    match signature.verify(&basename, &basename, &ipk, true) {
        Err(e) => {}
        _ => panic!("error: should fail"),
    }
}
