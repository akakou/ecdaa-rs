use fp256bn_amcl::{fp256bn::big::BIG, rand::RAND};
use serde::{Deserialize, Serialize};

use crate::{
    cred::{Credential, RandomizedCredential},
    issuer::IPK,
    schnorr::SchnorrProof,
    EcdaaError,
};

#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct Signature {
    pub cred: RandomizedCredential,
    pub proof: SchnorrProof,
}

impl Signature {
    pub fn new(cred: RandomizedCredential, proof: SchnorrProof) -> Self {
        Self { cred, proof }
    }

    pub fn sign(
        m: &[u8],
        basename: &[u8],
        sk: &BIG,
        cred: &Credential,
        calc_k: bool,
        rng: &mut RAND,
    ) -> Result<Self, u32> {
        let random_cred: RandomizedCredential = RandomizedCredential::randomize(cred, rng);
        let proof =
            SchnorrProof::random(m, basename, sk, &random_cred.s, &random_cred.w, calc_k, rng);

        Ok(Self::new(random_cred, proof))
    }

    pub fn verify(&self, m: &[u8], basename: &[u8], ipk: &IPK, calc_k: bool) -> EcdaaError {
        self.cred.valid(ipk)?;
        self.proof
            .valid(m, basename, &self.cred.s, &self.cred.w, calc_k)?;
        Ok(())
    }
}
