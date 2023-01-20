// use mcl_rust::G2;

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
