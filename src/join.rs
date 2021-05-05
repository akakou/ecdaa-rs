use bls12_381::{pairing, G1Projective, G2Affine, Scalar};
use group::{Curve, GroupEncoding};
use rand::RngCore;
use serde::{Serialize, Deserialize};

use super::core::{Issuer, Member, MemberCredential, IPK};
use super::utils::{calc_sha256_scalar, gen_rand_scalar};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ProofHavingSk {
    ecc_q: G1Projective,
    c_1: Scalar,
    s_1: Scalar,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ProofMemberCrendetialValid {
    c_2: Scalar,
    s_2: Scalar,
}

pub struct IssuerJoinProcess {
    issuer: Issuer,
    n: Option<Scalar>,
    ecc_q: Option<G1Projective>,
    l_j: Option<Scalar>,
    proof_member_credential_valid: Option<MemberCredential>,
}

impl IssuerJoinProcess {
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            n: None,
            ecc_q: None,
            l_j: None,
            proof_member_credential_valid: None,
        }
    }

    pub fn gen_nonce(&mut self, rng: &mut impl RngCore) -> Scalar {
        let n = gen_rand_scalar(rng);
        self.n = Some(n);

        n
    }

    pub fn is_proof_having_sk(&mut self, proof: &ProofHavingSk) -> bool {
        let sum = G1Projective::generator() * proof.s_1 + proof.ecc_q * (-proof.c_1);

        let mut left = Vec::new();

        left.append(sum.to_bytes().as_ref().to_vec().as_mut());
        left.append(proof.ecc_q.to_bytes().as_ref().to_vec().as_mut());
        left.append(self.n.unwrap().to_bytes().as_ref().to_vec().as_mut());

        let left = calc_sha256_scalar(&left);

        self.ecc_q = Some(proof.ecc_q);

        left == proof.c_1
    }

    pub fn gen_member_credential(&mut self, rng: &mut impl RngCore) -> MemberCredential {
        let ecc_q = self.ecc_q.expect("verify_proof_having_sk have never run.");

        let l_j = gen_rand_scalar(rng);
        let ecc_a = G1Projective::generator() * l_j;
        let ecc_b = ecc_a * self.issuer.isk.y;
        let ecc_c =
            ecc_a * self.issuer.isk.x + ecc_q * (self.issuer.isk.x * self.issuer.isk.y * l_j);
        let ecc_d = ecc_q * (l_j * self.issuer.isk.y);

        let member_credential = MemberCredential {
            ecc_a,
            ecc_b,
            ecc_c,
            ecc_d,
        };

        self.l_j = Some(l_j);
        self.proof_member_credential_valid = Some(member_credential);

        member_credential
    }

    pub fn prove_member_credential_valid(
        &mut self,
        rng: &mut impl RngCore,
    ) -> ProofMemberCrendetialValid {
        let msg_not_ready = "verify_proof_having_sk have never run.";
        let ecc_q = self.ecc_q.expect(msg_not_ready);
        let proof = self
            .proof_member_credential_valid
            .as_ref()
            .expect(msg_not_ready);
        let l_j = self.l_j.expect(msg_not_ready);

        let r_2 = gen_rand_scalar(rng);
        let ecc_u_2 = G1Projective::generator() * r_2;
        let ecc_v_2 = ecc_q * r_2;

        let mut c_2 = Vec::new();
        c_2.append(ecc_u_2.to_bytes().as_ref().to_vec().as_mut());
        c_2.append(ecc_v_2.to_bytes().as_ref().to_vec().as_mut());
        c_2.append(proof.ecc_b.to_bytes().as_ref().to_vec().as_mut());
        c_2.append(ecc_q.to_bytes().as_ref().to_vec().as_mut());
        c_2.append(proof.ecc_d.to_bytes().as_ref().to_vec().as_mut());
        let c_2 = calc_sha256_scalar(&c_2);

        let s_2 = r_2 + c_2 * l_j * self.issuer.isk.y;

        ProofMemberCrendetialValid { c_2, s_2 }
    }
}

pub struct MemberJoinProcess {
    ipk: IPK,
    sk: Scalar,
    ecc_q: G1Projective,
    n: Scalar,
    credential: Option<MemberCredential>,
}

impl MemberJoinProcess {
    pub fn random(ipk: IPK, n: Scalar, rng: &mut impl RngCore) -> Self {
        let sk = gen_rand_scalar(rng);
        let ecc_q = G1Projective::generator() * sk;

        Self {
            ipk,
            sk,
            ecc_q,
            n,
            credential: None,
        }
    }

    pub fn prove_haveing_sk(&self, rng: &mut impl RngCore) -> ProofHavingSk {
        let r_1 = gen_rand_scalar(rng);
        let ecc_u_1 = G1Projective::generator() * r_1;

        let mut c_1 = Vec::new();

        c_1.append(ecc_u_1.to_bytes().as_ref().to_vec().as_mut());
        c_1.append(self.ecc_q.to_bytes().as_ref().to_vec().as_mut());
        c_1.append(self.n.to_bytes().as_ref().to_vec().as_mut());

        let c_1 = calc_sha256_scalar(&c_1);
        let s_1 = r_1 + c_1 * self.sk;

        ProofHavingSk {
            ecc_q: self.ecc_q,
            c_1,
            s_1,
        }
    }

    pub fn is_member_credential_valid(
        &mut self,
        credential: MemberCredential,
        proof: &ProofMemberCrendetialValid,
    ) -> bool {
        if credential.ecc_a == G1Projective::generator() {
            return false;
        }

        {
            let first = G1Projective::generator() * proof.s_2 + credential.ecc_b * (-proof.c_2);

            let second = self.ecc_q * proof.s_2 + credential.ecc_d * (-proof.c_2);

            let mut left = Vec::new();
            left.append(first.to_bytes().as_ref().to_vec().as_mut());
            left.append(second.to_bytes().as_ref().to_vec().as_mut());
            left.append(credential.ecc_b.to_bytes().as_ref().to_vec().as_mut());
            left.append(self.ecc_q.to_bytes().as_ref().to_vec().as_mut());
            left.append(credential.ecc_d.to_bytes().as_ref().to_vec().as_mut());
            let left = calc_sha256_scalar(&left);

            if left != proof.c_2 {
                return false;
            }
        }

        if pairing(&credential.ecc_a.to_affine(), &self.ipk.ecc_y.to_affine())
            != pairing(&credential.ecc_b.to_affine(), &G2Affine::generator())
        {
            return false;
        }

        let sum = credential.ecc_a + credential.ecc_d;
        if pairing(&credential.ecc_c.to_affine(), &G2Affine::generator())
            != pairing(&sum.to_affine(), &self.ipk.ecc_x.to_affine())
        {
            return false;
        }

        self.credential = Some(credential);

        true
    }

    pub fn gen_member(self) -> Member {
        Member {
            sk: self.sk,
            ipk: self.ipk,
            credential: self
                .credential
                .expect("never passed is_member_credential_valid"),
        }
    }
}
