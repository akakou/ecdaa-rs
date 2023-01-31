use mcl_rust::{Fr, G1};

use crate::{issuer::IPK, schnorr::SchnorrProof, utils::rand_fr};

pub fn gen_seed_for_join() -> Fr {
    rand_fr()
}

pub struct ReqForJoin {
    pub q: G1,
    pub proof: SchnorrProof,
}

impl ReqForJoin {
    pub fn random(m: &Fr, ipk: &IPK) -> (Self, Fr) {
        let mut b = unsafe { G1::uninit() };
        let mut q = unsafe { G1::uninit() };

        // B = H(m)
        b.set_hash_of(&m.serialize());

        // key pair (sk, q)
        let sk = rand_fr();

        // Q = B^sk
        G1::mul(&mut q, &b, &sk);

        let proof = SchnorrProof::random(m, &sk, &b, &q);

        let req = Self { q, proof };

        (req, sk)
    }

    pub fn is_valid(&self, m: &Fr) -> Result<(), String> {
        // B = H(m)
        let mut b = unsafe { G1::uninit() };
        b.set_hash_of(&m.serialize());

        self.proof.is_valid(m, &b, &self.q)
    }
}
