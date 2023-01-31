use mcl_rust::Fr;

use crate::{
    cred::{Credential, RandomizedCredential},
    schnorr::SchnorrProof,
    EcdaaError,
};

pub struct Signature {
    pub cred: RandomizedCredential,
    pub proof: SchnorrProof,
}

impl Signature {
    pub fn new(cred: RandomizedCredential, proof: SchnorrProof) -> Self {
        Self { cred, proof }
    }

    pub fn generate(m: &Fr, sk: &Fr, cred: &Credential) -> Self {
        let random_cred = RandomizedCredential::randomize(cred);
        let proof = SchnorrProof::generate(m, sk, &random_cred.s, &random_cred.w);

        Self::new(random_cred, proof)
    }

    pub fn valid(&self, m: &Fr) -> EcdaaError {
        self.proof.valid(m, &self.cred.s)
    }
}
