use mcl_rust::{Fr, G1};

use crate::utils::{rand_fr, g2};

pub struct SchnorrProof {
    pub q: G1,
    pub c1: Fr,
    pub s: Fr,
    pub n: Fr,
}

impl SchnorrProof {
    pub fn random(m: &Fr, sk: &Fr, b: &G1, q: &G1) -> Self {
        let r = rand_fr();

        // U = B^r
        let mut u = unsafe { G1::uninit() };

        G1::mul(&mut u, b, &r);

        // c2 = H(U1 || P1 || Q || m)
        let mut c2 = Fr::zero();
        let mut buf = vec![];

        buf.append(&mut u.serialize());
        buf.append(&mut g2().serialize());
        buf.append(&mut m.serialize());
        c2.set_hash_of(&buf);

        // c1 = H(n | c2)
        let mut c1 = Fr::zero();
        let mut buf = vec![];

        let n = rand_fr();
        buf.append(&mut n.serialize());
        buf.append(&mut c2.serialize());
        c1.set_hash_of(&buf);

        let s = &r + &(&c1 * sk);

        Self {
            s,
            c1,
            n,
            q: q.clone(),
        }
    }

    pub fn is_valid(&self, m: &Fr, b: &G1, q: &G1) -> Result<(), String> {
        let mut u1 = unsafe { G1::uninit() };
        let mut tmp = unsafe { G1::uninit() };

        // U1 = b^s * Q^-c1
        G1::mul(&mut u1, &b, &self.s);
        G1::mul(&mut tmp, &self.q, &self.c1);

        let u1 = &u1 - &tmp;

        // c2 = H(u1 | g2 | q | m)
        let mut buf = vec![];
        buf.append(&mut u1.serialize());
        buf.append(&mut g2().serialize());
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
            Err("schnorr proof is not valid".to_string())
        }
    }
}
