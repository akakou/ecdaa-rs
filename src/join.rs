use mcl_rust::{pairing, Fr, G1, G2, GT};
use rand::{random, Error};

use crate::{
    issuer::{IPK, ISK},
    utils::{g2, rand_fr},
};

pub struct SchnorrProof {
    pub q: G1,
    pub c1: Fr,
    pub s1: Fr,
    pub n: Fr,
}

impl SchnorrProof {
    pub fn random(m: &Fr, sk: &Fr, b: &G1, q: &G1) -> Self {
        let mut u1 = unsafe { G1::uninit() };

        // U1 = B^r1
        let r1 = rand_fr();
        G1::mul(&mut u1, b, &r1);

        // c2 = H(U1 || P1 || Q || m)
        let mut c2 = Fr::zero();
        let mut buf = vec![];

        buf.append(&mut u1.serialize());
        buf.append(&mut g2().serialize());

        if !q.is_zero() {
            buf.append(&mut q.serialize());
        }

        buf.append(&mut m.serialize());
        c2.set_hash_of(&buf);

        // c1 = H(n | c2)
        let mut c1 = Fr::zero();
        let mut buf = vec![];

        let n = rand_fr();
        buf.append(&mut n.serialize());
        buf.append(&mut c2.serialize());
        c1.set_hash_of(&buf);

        let s1 = &r1 + &(&c1 * &sk);

        Self {
            s1,
            c1,
            n,
            q: q.clone(),
        }
    }

    pub fn is_valid(&self, m: &Fr, b: &G1) -> Result<(), String> {
        let mut u1 = unsafe { G1::uninit() };
        let mut tmp = unsafe { G1::uninit() };

        // U1 = b^s1 * Q^-c1
        G1::mul(&mut u1, &b, &self.s1);
        G1::mul(&mut tmp, &self.q, &self.c1);

        let u1 = &u1 - &tmp;

        // c2 = H(u1 | g2 | q | m)
        let mut buf = vec![];
        buf.append(&mut u1.serialize());
        buf.append(&mut g2().serialize());
        buf.append(&mut self.q.serialize());
        buf.append(&mut m.serialize());

        let mut c2 = Fr::zero();
        c2.set_hash_of(&buf);

        // c1 = H(n | c2)
        let mut buf = vec![];
        buf.append(&mut self.n.serialize());
        buf.append(&mut c2.serialize());

        let mut c1 = Fr::zero();
        c1.set_hash_of(&buf);

        if c1 == self.c1 {
            Ok(())
        } else {
            Err("req for join is not valid".to_string())
        }
    }
}

pub fn gen_seed_for_join() -> Fr {
    rand_fr()
}

pub struct ReqForJoin {
    pub q: G1,
    pub proof: SchnorrProof,
}

impl ReqForJoin {
    pub fn random(m: &Fr, ipk: &IPK) -> Self {
        let mut b = unsafe { G1::uninit() };
        let mut q = unsafe { G1::uninit() };
        let mut u1 = unsafe { G1::uninit() };

        // B = H(m)
        b.set_hash_of(&m.serialize());

        // key pair (sk, q)
        let sk = rand_fr();

        // Q = B^sk
        G1::mul(&mut q, &b, &sk);

        let proof = SchnorrProof::random(m, &sk, &b, &q);

        Self { q, proof }
    }

    pub fn is_valid(&self, m: &Fr) -> Result<(), String> {
        // B = H(m)
        let mut b = unsafe { G1::uninit() };
        b.set_hash_of(&m.serialize());

        self.proof.is_valid(m, &b)
    }
}

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
