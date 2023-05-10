use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP},
    rand::RAND,
    sha3::{HASH256, SHA3},
};

use crate::{
    schnorr::SchnorrProof,
    utils::{export_big, hash_to_ecp},
    EcdaaError,
};

pub struct ReqForJoin {
    pub q: ECP,
    pub proof: SchnorrProof,
}

impl ReqForJoin {
    pub fn random(m: &[u8], mut rng: &mut RAND) -> Result<(Self, BIG), u32> {
        let b = hash_to_ecp(m)?.1;

        // key pair (sk, q)
        let sk = BIG::random(&mut rng);

        // Q = B^sk
        let q = b.mul(&sk);

        let proof = SchnorrProof::random(m, m, &sk, &b, &q, rng);
        let req = Self { q, proof };

        Ok((req, sk))
    }

    pub fn valid(&self, m: &[u8]) -> EcdaaError {
        // B = H(m)
        let b = hash_to_ecp(m)?.1;

        self.proof.valid(m, m, &b, &self.q)
    }
}
