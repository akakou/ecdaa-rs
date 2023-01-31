use mcl_rust::{pairing, Fr, G1, GT};

use crate::{
    issuer::{IPK, ISK},
    req_for_join::ReqForJoin,
    utils::{g2, rand_fr},
};

pub struct Credential {
    pub a: G1,
    pub b: G1,
    pub c: G1,
    pub d: G1,
}

pub struct RandomizedCredential {
    pub r: G1,
    pub s: G1,
    pub t: G1,
    pub w: G1,
}

impl Credential {
    pub fn new(a: G1, b: G1, c: G1, d: G1) -> Self {
        Self { a, b, c, d }
    }

    pub fn with_no_encryption(req: &ReqForJoin, m: &Fr, isk: &ISK) -> Self {
        let mut a = unsafe { G1::uninit() };
        let mut b = unsafe { G1::uninit() };
        let mut c = unsafe { G1::uninit() };

        // 1/y
        let mut inv_y = Fr::zero();
        Fr::inv(&mut inv_y, &isk.y);

        // b = H(m)
        b.set_hash_of(&m.serialize());

        // a = B^{1/y}
        G1::mul(&mut a, &b, &inv_y);

        // c = (A Q)^x
        let tmp = &a + &req.q;
        G1::mul(&mut c, &tmp, &isk.x);

        // d = Q
        let d = req.q.clone();

        Self::new(a, b, c, d)
    }

    pub fn randomize(&self) -> RandomizedCredential {
        let l = rand_fr();

        let mut r = G1::zero();
        let mut s = G1::zero();
        let mut t = G1::zero();
        let mut w = G1::zero();

        G1::mul(&mut r, &self.a, &l);
        G1::mul(&mut s, &self.b, &l);
        G1::mul(&mut t, &self.c, &l);
        G1::mul(&mut w, &self.d, &l);

        RandomizedCredential { r, s, t, w }
    }

    pub fn is_valid(&self, ipk: &IPK) -> Result<(), String> {
        let mut param1 = GT::zero();
        let mut param2 = GT::zero();
        let mut param3 = GT::zero();
        let mut param4 = GT::zero();

        let tmp = &self.a + &self.d;

        pairing(&mut param1, &self.a, &ipk.y);
        pairing(&mut param2, &self.b, &g2());
        pairing(&mut param3, &self.c, &g2());
        pairing(&mut param4, &tmp, &ipk.x);

        if param1 != param2 {
            return Err("e(A,Y) != e(B,g2)".to_string());
        }

        if param3 != param4 {
            return Err("e(C, g2) != e(A D, X)".to_string());
        }

        Ok(())
    }
}
