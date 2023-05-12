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

fn valid_cred(a: &ECP, b: &ECP, c: &ECP, d: &ECP, ipk: &IPK) -> EcdaaError {
    let mut tmp = a.clone();
    tmp.add(&d);

    let param1 = pair::ate(&ipk.y, a);
    let param2 = pair::ate(&g2(), b);
    let param3 = pair::ate(&g2(), c);
    let param4 = pair::ate(&ipk.y, &tmp);

    if param1.equals(&param2) {
        return Err(3);
    }

    if param3.equals(&param4) {
        return Err(4);
    }

    Ok(())
}

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

    pub fn with_no_encryption(req: &ReqForJoin, m: &[u8], isk: &ISK) -> Result<Self, u32> {
        // 1/y
        let mut inv_y = isk.y.clone();
        inv_y.invmodp(&p());

        // b = H(m)
        let b = hash_to_ecp(m)?.1;

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

    pub fn valid(&self, ipk: &IPK) -> EcdaaError {
        valid_cred(&self.a, &self.b, &self.c, &self.d, ipk)
    }
}


#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct RandomizedCredential {
    pub r: ECP,
    pub s: ECP,
    pub t: ECP,
    pub w: ECP,
}

impl RandomizedCredential {
    pub fn randomize(cred: &Credential, rng: &mut RAND) -> Self {
        let l = BIG::random(rng);

        let r = cred.a.mul(&l);
        let s = cred.b.mul(&l);
        let t = cred.c.mul(&l);
        let w = cred.d.mul(&l);

        Self { r, s, t, w }
    }

    pub fn valid(&self, ipk: &IPK) -> EcdaaError {
        valid_cred(&self.r, &self.s, &self.t, &self.w, ipk)
    }
}
