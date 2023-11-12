use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP},
    rand::RAND,
};
use serde::{Deserialize, Serialize};

use crate::{schnorr::SchnorrProof, utils::hash_to_ecp, EcdaaError};

#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct ReqForJoin {
    pub q: ECP,
    pub proof: SchnorrProof,
}

impl ReqForJoin {
    pub fn random(m: &[u8], mut rng: &mut RAND) -> Result<(Self, BIG), EcdaaError> {
        let b = hash_to_ecp(m)?.0;

        // key pair (sk, q)
        let sk = BIG::random(&mut rng);

        // Q = B^sk
        let q = b.mul(&sk);

        let proof = SchnorrProof::random(m, &[], &sk, &b, &q, false, rng)?;
        let req = Self { q, proof };

        Ok((req, sk))
    }

    pub fn valid(&self, m: &[u8]) -> Result<(), EcdaaError> {
        let b = hash_to_ecp(m)?.0;
        self.proof.valid(m, &[], &b, &self.q, false)
    }
}
