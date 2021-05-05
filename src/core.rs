use bls12_381::{pairing, G1Projective, G2Affine, G2Projective, Scalar};
use group::{Curve, GroupEncoding};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use alloc::vec::Vec;


use super::utils::{calc_sha256_scalar, gen_rand_scalar};

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ISK {
    pub x: Scalar,
    pub y: Scalar,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct IPK {
    pub ecc_x: G2Projective,
    pub ecc_y: G2Projective,
    pub c: Scalar,
    pub s_x: Scalar,
    pub s_y: Scalar,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Signature {
    c: Scalar,
    s: Scalar,
    ecc_r: G1Projective,
    ecc_s: G1Projective,
    ecc_t: G1Projective,
    ecc_w: G1Projective,
}

#[derive(Debug, Copy, Clone)]
pub struct Issuer {
    pub isk: ISK,
    pub ipk: IPK,
}

impl Issuer {
    pub fn random(rng: &mut impl RngCore) -> Self {
        let isk = Self::gen_isk(rng);
        let ipk = Self::gen_ipk(&isk, rng);

        return Self { isk, ipk };
    }

    fn gen_isk(rng: &mut impl RngCore) -> ISK {
        let x = gen_rand_scalar(rng);
        let y = gen_rand_scalar(rng);

        ISK { x, y }
    }

    fn gen_ipk(isk: &ISK, rng: &mut impl RngCore) -> IPK {
        let ecc_x = G2Projective::generator() * isk.x;
        let ecc_y = G2Projective::generator() * isk.y;

        let r_x = gen_rand_scalar(rng);
        let r_y = gen_rand_scalar(rng);

        let ecc_u_x = G2Projective::generator() * r_x;
        let ecc_u_y = G2Projective::generator() * r_y;

        let mut vec = Vec::new();
        vec.append(ecc_u_x.to_bytes().as_ref().to_vec().as_mut());
        vec.append(ecc_u_y.to_bytes().as_ref().to_vec().as_mut());
        vec.append(ecc_x.to_bytes().as_ref().to_vec().as_mut());
        vec.append(ecc_y.to_bytes().as_ref().to_vec().as_mut());
        let c = calc_sha256_scalar(&vec);

        let s_x = r_x + c * isk.x;
        let s_y = r_y + c * isk.y;

        IPK {
            ecc_x,
            ecc_y,
            c,
            s_x,
            s_y,
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct MemberCredential {
    pub ecc_a: G1Projective,
    pub ecc_b: G1Projective,
    pub ecc_c: G1Projective,
    pub ecc_d: G1Projective,
}

pub struct Member {
    pub sk: Scalar,
    pub ipk: IPK,
    pub credential: MemberCredential,
}

impl Member {
    pub fn sign(&self, msg: &[u8], rng: &mut impl RngCore) -> Signature {
        let l = gen_rand_scalar(rng);
        let ecc_r = self.credential.ecc_a * l;
        let ecc_s = self.credential.ecc_b * l;
        let ecc_t = self.credential.ecc_c * l;
        let ecc_w = self.credential.ecc_d * l;
        let r = gen_rand_scalar(rng);
        let ecc_u = ecc_s * r;

        let mut c = Vec::new();
        c.append(ecc_u.to_bytes().as_ref().to_vec().as_mut());
        c.append(ecc_s.to_bytes().as_ref().to_vec().as_mut());
        c.append(ecc_w.to_bytes().as_ref().to_vec().as_mut());
        c.append(msg.to_vec().as_mut());
        let c = calc_sha256_scalar(&c);

        let s = r + c * self.sk;

        Signature {
            c,
            s,
            ecc_r,
            ecc_s,
            ecc_t,
            ecc_w,
        }
    }
}

pub struct Verifier {
    ipk: IPK,
}

impl Verifier {
    pub fn new(ipk: IPK) -> Self {
        Self { ipk }
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> bool {
        {
            let first = signature.ecc_s * signature.s + signature.ecc_w * (-signature.c);

            let mut left = Vec::new();
            left.append(first.to_bytes().as_ref().to_vec().as_mut());
            left.append(signature.ecc_s.to_bytes().as_ref().to_vec().as_mut());
            left.append(signature.ecc_w.to_bytes().as_ref().to_vec().as_mut());
            left.append(msg.to_vec().as_mut());
            let left = calc_sha256_scalar(&left);

            if left != signature.c {
                return false;
            }
        }

        if pairing(&signature.ecc_r.to_affine(), &self.ipk.ecc_y.to_affine())
            != pairing(&signature.ecc_s.to_affine(), &G2Affine::generator())
        {
            return false;
        }

        let sum = signature.ecc_r + signature.ecc_w;
        if pairing(&signature.ecc_t.to_affine(), &G2Affine::generator())
            != pairing(&sum.to_affine(), &self.ipk.ecc_x.to_affine())
        {
            return false;
        }

        return true;
    }
}
