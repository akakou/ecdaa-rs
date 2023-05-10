use fp256bn_amcl::rand::RAND;

use crate::issuer::{IPK, ISK};

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
}
