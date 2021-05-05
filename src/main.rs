#[macro_use] extern crate slice_as_array;


use bls12_381::{G1Projective, G2Projective, Scalar, pairing};
use rand::{thread_rng, RngCore};
use ff::Field;
use group::GroupEncoding;
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};

struct ISK {
    x: Scalar,
    y: Scalar
}

struct IPK {
    pub ecc_x: G2Projective,
    pub ecc_y: G2Projective,
    pub c: Scalar,
    pub s_x: Scalar,
    pub s_y: Scalar
}

struct Issuer {
    pub isk: ISK,
    pub ipk: IPK
}

struct Member {
    pub ipk: IPK,
}

fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)  
}

fn calc_sha256_scalar(vec: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(vec);
    let hashed = hasher.finalize().to_vec();

    let mut schalar: Vec<u64> = vec![0; hashed.len()/8];
    BigEndian::read_u64_into(&hashed, &mut schalar);
    let schalar = slice_as_array!(&schalar, [u64; 4]).expect("bad hash length");

    Scalar::from_raw(*schalar)
}

impl Issuer {
    pub fn random(rng: &mut impl RngCore) -> Self {        
        let isk = Self::gen_isk(rng);
        let ipk = Self::gen_ipk(&isk, rng);

        return Self {
            isk, ipk
        }
    }

    fn gen_isk(rng: &mut impl RngCore) -> ISK {
        let x = gen_rand_scalar(rng);
        let y = gen_rand_scalar(rng);

        ISK{x, y} 
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

        let c= calc_sha256_scalar(&vec);

        let s_x = r_x + c * isk.x;
        let s_y = r_y + c * isk.y;

        IPK {
            ecc_x,
            ecc_y,
            c,
            s_x,
            s_y
        }
    }
}

struct IssuerJoinProcess {
    issuer: Issuer,
    n: Option<Scalar>
}

impl IssuerJoinProcess {
    pub fn new(issuer: Issuer) -> Self {
        let n = None;
        Self { issuer, n }
    }

    pub fn gen_nonce(&mut self, rng: &mut impl RngCore) -> Scalar {
        let n = gen_rand_scalar(rng);
        self.n = Some(n);

        n
    }

    pub fn verify_proof_having_sk(&self, proof: &ProofHavingSk) -> bool {
        let sum = G1Projective::generator() * proof.s_1 
                + proof.ecc_q * (- proof.c_1);

        let mut left = Vec::new();

        left.append(sum.to_bytes().as_ref().to_vec().as_mut());
        left.append(proof.ecc_q.to_bytes().as_ref().to_vec().as_mut());
        left.append(self.n.unwrap().to_bytes().as_ref().to_vec().as_mut());

        let left= calc_sha256_scalar(&left);

        left == proof.c_1
    }
}

struct MemberJoinProcess {
    sk: Scalar,
    ecc_q: G1Projective,
    n: Scalar
}

struct ProofHavingSk {
    ecc_q: G1Projective,
    c_1: Scalar,
    s_1: Scalar
}

impl MemberJoinProcess {
    pub fn random(n: Scalar, rng: &mut impl RngCore) -> Self {
        let sk = gen_rand_scalar(rng);
        let ecc_q = G1Projective::generator() * sk;

        Self {
            sk,
            ecc_q,
            n
        }
    }

    pub fn prove_haveing_sk(&self, rng: &mut impl RngCore) -> ProofHavingSk{
        let r_1 = gen_rand_scalar(rng);
        let ecc_u_1 = G1Projective::generator() * r_1;
        
        let mut c_1 = Vec::new();

        c_1.append(ecc_u_1.to_bytes().as_ref().to_vec().as_mut());
        c_1.append(self.ecc_q.to_bytes().as_ref().to_vec().as_mut());
        c_1.append(self.n.to_bytes().as_ref().to_vec().as_mut());

        let c_1= calc_sha256_scalar(&c_1);
        let s_1 = r_1 + c_1 * self.sk;

        ProofHavingSk {
            ecc_q: self.ecc_q,
            c_1,
            s_1
        }
    }
}

fn main() {
}

#[test]
fn test() {
    let mut rng = thread_rng();
    let issuer = Issuer::random(&mut rng);
    let mut issuer_join_proces = IssuerJoinProcess::new(issuer);
    let n = issuer_join_proces.gen_nonce(&mut rng);
    let member_join_proces = MemberJoinProcess::random(n, &mut rng);
    let proof = member_join_proces.prove_haveing_sk(&mut rng);
    let is_valid= issuer_join_proces.verify_proof_having_sk(&proof);

    assert!(is_valid);
}
