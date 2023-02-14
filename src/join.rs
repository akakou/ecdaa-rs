use mcl_rust::{Fr, G1};

use crate::{schnorr::SchnorrProof, utils::rand_fr, EcdaaError};

pub fn gen_seed_for_join() -> Fr {
    rand_fr()
}

pub struct ReqForJoin {
    pub q: G1,
    pub proof: SchnorrProof,
}

impl ReqForJoin {
    pub fn generate(m: &[u8]) -> (Self, Fr) {
        let mut b = G1::zero();
        let mut q = G1::zero();

        // B = H(m)
        b.set_hash_of(m);

        // key pair (sk, q)
        let sk = rand_fr();

        // Q = B^sk
        G1::mul(&mut q, &b, &sk);

        let proof = SchnorrProof::generate(m, m, &sk, &b, &q);
        let req = Self { q, proof };

        (req, sk)
    }

    pub fn valid(&self, m: &[u8]) -> EcdaaError {
        // B = H(m)
        let mut b = G1::zero();
        b.set_hash_of(m);

        self.proof.valid(m, m, &b, &self.q)
    }
}
