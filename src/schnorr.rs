use alloc::{string::ToString, vec};
use mcl_rust::{Fr, G1};

use crate::{utils::rand_fr, EcdaaError};

pub struct SchnorrProof {
    pub c: Fr,
    pub s: Fr,
    pub n: Fr,
    pub k: G1,
}

impl SchnorrProof {
    pub fn generate(msg: &[u8], basename: &[u8], sk: &Fr, b: &G1, q: &G1) -> Self {
        let r = rand_fr();

        // let mut b = G1::zero();
        // b.set_hash_of(basename);

        // E = B^r
        let mut e = G1::zero();
        G1::mul(&mut e, b, &r);

        // L = B^r
        let mut l = G1::zero();
        G1::mul(&mut l, b, &r);

        // K = B^sk
        let mut k = G1::zero();
        G1::mul(&mut k, b, sk);

        // c2 = H(E, L, B, K, [S, W, basename, message])
        let mut buf = vec![];
        buf.append(&mut e.serialize());
        buf.append(&mut l.serialize());
        buf.append(&mut b.serialize());
        buf.append(&mut k.serialize());
        buf.append(&mut basename.to_vec());
        buf.append(&mut msg.to_vec());

        let mut c2 = Fr::zero();
        c2.set_hash_of(&buf);

        // c1 = H(n | c2)
        let mut c = Fr::zero();
        let mut buf = vec![];

        let n = rand_fr();
        buf.append(&mut n.serialize());
        buf.append(&mut c2.serialize());
        c.set_hash_of(&buf);

        // s = r + c . sk
        let s = &r + &(&c * sk);

        Self { s, c, n, k }
    }

    pub fn valid(&self, msg: &[u8], basename: &[u8], b: &G1, q: &G1) -> EcdaaError {
        let mut e = G1::zero();
        let mut l = G1::zero();
        let mut tmp = G1::zero();

        // E = B^s . Q^-c
        // ----------------
        // B^s . Q^-c
        //     = B^(r + c . sk) . Q^-c
        //     = B^(r + c . sk) . Q^-(c)
        //     = B^(r + c . sk) . B^-(c . sk)
        //     = B^r
        //     = E
        G1::mul(&mut e, b, &self.s);
        G1::mul(&mut tmp, q, &self.c);

        e = &e - &tmp;

        // L = B^s - K^c
        // ----------
        // B^s - K^c
        //     = B^(r + c . sk) - B^(c . sk)
        //     = B^r
        //     = L
        G1::mul(&mut l, b, &self.s);
        G1::mul(&mut tmp, &self.k, &self.c);

        l = &l - &tmp;

        // c2 =  H(E, L, B, K, [S, W, basename, message])
        let mut buf = vec![];
        buf.append(&mut e.serialize());
        buf.append(&mut l.serialize());
        buf.append(&mut b.serialize());
        buf.append(&mut self.k.serialize());
        buf.append(&mut basename.to_vec());
        buf.append(&mut msg.to_vec());

        let mut c2 = Fr::zero();
        c2.set_hash_of(&buf);

        // c1 = H(n | c2)
        let mut buf = vec![];
        buf.append(&mut self.n.serialize());
        buf.append(&mut c2.serialize());

        let mut c = Fr::zero();
        c.set_hash_of(&buf);

        if c == self.c {
            Ok(())
        } else {
            Err("schnorr proof is not valid".to_string())
        }
    }
}
