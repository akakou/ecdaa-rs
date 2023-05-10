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

    ipk.valid().unwrap();

    let m = vec![0, 2, 3];
    let req = ReqForJoin::random(&m, &mut rng).unwrap();

    req.0.valid(&m).unwrap();

    let sk = req.1;

    let cred = Credential::with_no_encryption(&req.0, &m, &isk).unwrap();
    cred.valid(&ipk).unwrap();

    let rand_cred = RandomizedCredential::randomize(&cred, &mut rng);
    rand_cred.valid(&ipk).unwrap();

    let signature = Signature::sign(&m, &m, &sk, &cred, &mut rng);
    signature.verify(&m, &m, &ipk).unwrap()
}
