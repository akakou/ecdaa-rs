use fp256bn_amcl::{fp256bn::big::BIG, rand::RAND};

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

    pub fn sign(m: &[u8], basename: &[u8], sk: &BIG, cred: &Credential, rng: &mut RAND) -> Self {
        let random_cred = RandomizedCredential::randomize(cred, rng);
        let proof = SchnorrProof::random(m, basename, sk, &random_cred.s, &random_cred.w, rng);

        Self::new(random_cred, proof)
    }

    pub fn verify(&self, m: &[u8], basename: &[u8], ipk: &IPK) -> EcdaaError {
        self.proof.valid(m, basename, &self.cred.s, &self.cred.w)?;
        self.cred.valid(ipk)?;
        Ok(())
    }
}
