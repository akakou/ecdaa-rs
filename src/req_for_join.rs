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
    pub fn generate(m: &Fr) -> (Self, Fr) {
        let mut b = G1::zero();
        let mut q = G1::zero();

        // B = H(m)
        b.set_hash_of(&m.serialize());

        // key pair (sk, q)
        let sk = rand_fr();

        // Q = B^sk
        G1::mul(&mut q, &b, &sk);

        let proof = SchnorrProof::generate(m, &sk, &b, &q);

        let req = Self { q, proof };

        (req, sk)
    }

    pub fn valid(&self, m: &Fr) -> EcdaaError {
        // B = H(m)
        let mut b = G1::zero();
        b.set_hash_of(&m.serialize());

        self.proof.valid(m, &b)
    }
}
