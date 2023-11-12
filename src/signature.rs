use fp256bn_amcl::{fp256bn::big::BIG, rand::RAND};
use serde::{Deserialize, Serialize};

use crate::{
    cred::{randomize_cred, Credential},
    issuer::IPK,
    schnorr::SchnorrProof,
    EcdaaError,
};

#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct Signature {
    pub cred: Credential,
    pub proof: SchnorrProof,
}

impl Signature {
    pub fn new(cred: Credential, proof: SchnorrProof) -> Self {
        Self { cred, proof }
    }

    pub fn sign(
        m: &[u8],
        basename: &[u8],
        sk: &BIG,
        cred: &Credential,
        calc_k: bool,
        rng: &mut RAND,
    ) -> Result<Self, EcdaaError> {
        let random_cred: Credential = randomize_cred(cred, rng);
        let proof =
            SchnorrProof::random(m, basename, sk, &random_cred.b, &random_cred.d, calc_k, rng)?;

        Ok(Self::new(random_cred, proof))
    }

    pub fn verify(
        &self,
        m: &[u8],
        basename: &[u8],
        ipk: &IPK,
        calc_k: bool,
    ) -> Result<(), EcdaaError> {
        self.cred.valid(ipk)?;
        self.proof
            .valid(m, basename, &self.cred.b, &self.cred.d, calc_k)?;
        Ok(())
    }
}
