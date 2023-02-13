use mcl_rust::Fr;

use crate::{
    cred::{Credential, RandomizedCredential},
    issuer::IPK,
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

    pub fn generate(m: &[u8], basename: &[u8], sk: &Fr, cred: &Credential) -> Self {
        let random_cred = RandomizedCredential::randomize(cred);
        let proof = SchnorrProof::generate(m, basename, sk, &random_cred.s, &random_cred.w);

        Self::new(random_cred, proof)
    }

    pub fn valid(&self, m: &[u8], basename: &[u8], ipk: &IPK) -> EcdaaError {
        self.proof.valid(m, basename, &self.cred.s, &self.cred.w)?;
        self.cred.valid(ipk)?;

        Ok(())
    }
}
