use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP, pair},
    rand::RAND,
};
use serde::{Deserialize, Serialize};

use crate::{
    issuer::{IPK, ISK},
    join::ReqForJoin,
    utils::{g2, hash_to_ecp, p},
    EcdaaError,
};

#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct Credential {
    pub a: ECP,
    pub b: ECP,
    pub c: ECP,
    pub d: ECP,
}

impl Credential {
    pub fn new(a: ECP, b: ECP, c: ECP, d: ECP) -> Self {
        Self { a, b, c, d }
    }

    pub fn with_no_encryption(req: &ReqForJoin, m: &[u8], isk: &ISK) -> Result<Self, EcdaaError> {
        // 1/y
        let mut inv_y = isk.y.clone();
        inv_y.invmodp(&p());

        // b = H(m)
        let b = hash_to_ecp(m)?.0;

        // a = B^{1/y}
        let a = b.mul(&inv_y);

        // c = (A Q)^x
        let mut tmp = a.clone();
        tmp.add(&req.q);

        let c = tmp.mul(&isk.x);

        // d = Q
        let d = req.q.clone();

        Ok(Self::new(a, b, c, d))
    }

    pub fn valid(&self, ipk: &IPK) -> Result<(), EcdaaError> {
        let mut tmp = self.a.clone();
        tmp.add(&self.d);

        let param1 = pair::ate(&ipk.y, &self.a);
        let param1 = pair::fexp(&param1);

        let param2 = pair::ate(&g2(), &self.b);
        let param2 = pair::fexp(&param2);

        if !param1.equals(&param2) {
            return Err(EcdaaError::InvalidCredential1);
        }

        let param3 = pair::ate(&g2(), &self.c);
        let param3 = pair::fexp(&param3);

        let param4 = pair::ate(&ipk.x, &tmp);
        let param4 = pair::fexp(&param4);

        if !param3.equals(&param4) {
            return Err(EcdaaError::InvalidCredential2);
        }

        Ok(())
    }
}

pub fn randomize_cred(cred: &Credential, rng: &mut RAND) -> Credential {
    let l = BIG::random(rng);

    let a = cred.a.mul(&l);
    let b = cred.b.mul(&l);
    let c = cred.c.mul(&l);
    let d = cred.d.mul(&l);

    Credential { a, b, c, d }
}
