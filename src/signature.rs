use mcl_rust::Fr;

use crate::{
    cred::{Credential, RandomizedCredential},
    issuer::IPK,
    schnorr::SchnorrProof,
};

pub struct Signature {
    pub cred: RandomizedCredential,
    pub proof: SchnorrProof,
}

impl Signature {
    pub fn new(cred: RandomizedCredential, proof: SchnorrProof) -> Self {
        Self { cred, proof }
    }

    pub fn random(m: &Fr, sk: &Fr, original_cred: &Credential, ipk: &IPK) -> Self {
        let cred = original_cred.randomize();
        let proof = SchnorrProof::random(m, sk, &cred.s, &cred.w);

        Self::new(cred, proof)
    }

    pub fn is_valid(&self, m: &Fr) -> Result<(), String> {
        self.proof.is_valid(m, &self.cred.s, &self.cred.w)
    }
}
