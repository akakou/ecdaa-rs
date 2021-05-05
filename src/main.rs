#[macro_use] extern crate slice_as_array;


use bls12_381::{G1Projective, G2Projective, G2Affine, Scalar, pairing};
use rand::{thread_rng, RngCore};
use ff::Field;
use group::{Curve, GroupEncoding};
use sha2::{Sha256, Digest};
use byteorder::{ByteOrder, BigEndian};


#[derive(Debug, Copy, Clone)]
struct ISK {
    x: Scalar,
    y: Scalar
}

#[derive(Debug, Copy, Clone)]
struct IPK {
    pub ecc_x: G2Projective,
    pub ecc_y: G2Projective,
    pub c: Scalar,
    pub s_x: Scalar,
    pub s_y: Scalar
}

#[derive(Debug, Copy, Clone)]
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


struct ProofHavingSk {
    ecc_q: G1Projective,
    c_1: Scalar,
    s_1: Scalar
}

#[derive(Debug, Copy, Clone)]
struct MemberCredential {
    ecc_a: G1Projective,
    ecc_b: G1Projective,
    ecc_c: G1Projective,
    ecc_d: G1Projective
}

struct ProofMemberCrendetialValid {
    c_2: Scalar,
    s_2: Scalar
}

struct IssuerJoinProcess {
    issuer: Issuer,
    n: Option<Scalar>,
    ecc_q: Option<G1Projective>,
    l_j: Option<Scalar>,
    proof_member_credential_valid: Option<MemberCredential>
}

impl IssuerJoinProcess {
    pub fn new(issuer: Issuer) -> Self {
        Self { 
            issuer,
            n: None,
            ecc_q: None,
            l_j: None,
            proof_member_credential_valid: None
        }
    }

    pub fn gen_nonce(&mut self, rng: &mut impl RngCore) -> Scalar {
        let n = gen_rand_scalar(rng);
        self.n = Some(n);

        n
    }

    pub fn is_proof_having_sk(&mut self, proof: &ProofHavingSk) -> bool {
        let sum = G1Projective::generator() * proof.s_1 
                + proof.ecc_q * (- proof.c_1);

        let mut left = Vec::new();

        left.append(sum.to_bytes().as_ref().to_vec().as_mut());
        left.append(proof.ecc_q.to_bytes().as_ref().to_vec().as_mut());
        left.append(self.n.unwrap().to_bytes().as_ref().to_vec().as_mut());

        let left= calc_sha256_scalar(&left);

        self.ecc_q = Some(proof.ecc_q);

        left == proof.c_1
    }

    pub fn gen_member_credential(&mut self, rng: &mut impl RngCore) -> MemberCredential {
        let ecc_q = self.ecc_q.expect("verify_proof_having_sk have never run.");
        
        let l_j = gen_rand_scalar(rng);
        let ecc_a = G1Projective::generator() * l_j;
        let ecc_b = ecc_a * self.issuer.isk.y;
        let ecc_c = ecc_a * self.issuer.isk.x + 
                ecc_q * (self.issuer.isk.x * self.issuer.isk.y * l_j);
        let ecc_d = ecc_q * (l_j * self.issuer.isk.y);

        let member_credential = MemberCredential {
            ecc_a,
            ecc_b,
            ecc_c,
            ecc_d
        };

        self.l_j = Some(l_j);
        self.proof_member_credential_valid = Some(member_credential);

        member_credential
    }

    pub fn prove_member_credential_valid(&mut self, rng: &mut impl RngCore) -> ProofMemberCrendetialValid {
        let msg_not_ready = "verify_proof_having_sk have never run.";
        let ecc_q = self.ecc_q.expect(msg_not_ready);
        let proof = self.proof_member_credential_valid.as_ref().expect(msg_not_ready);
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

        ProofMemberCrendetialValid {
            c_2,
            s_2
        }
    }
}

struct MemberJoinProcess {
    ipk: IPK,
    sk: Scalar,
    ecc_q: G1Projective,
    n: Scalar
}


impl MemberJoinProcess {
    pub fn random(ipk: IPK, n: Scalar, rng: &mut impl RngCore) -> Self {
        let sk = gen_rand_scalar(rng);
        let ecc_q = G1Projective::generator() * sk;

        Self {
            ipk, 
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

    pub fn is_member_credential_valid(&self, credential: &MemberCredential, proof: &ProofMemberCrendetialValid) -> bool {
        if credential.ecc_a == G1Projective::generator() {
            return false;
        }

        {
            let first = G1Projective::generator() * proof.s_2 
                + credential.ecc_b * (- proof.c_2);

            let second = self.ecc_q * proof.s_2 
                + credential.ecc_d * (- proof.c_2);

            let mut left = Vec::new();
            left.append(first.to_bytes().as_ref().to_vec().as_mut());
            left.append(second.to_bytes().as_ref().to_vec().as_mut());
            left.append(credential.ecc_b.to_bytes().as_ref().to_vec().as_mut());
            left.append(self.ecc_q.to_bytes().as_ref().to_vec().as_mut());
            left.append(credential.ecc_d.to_bytes().as_ref().to_vec().as_mut());
            let left= calc_sha256_scalar(&left)
            ;
            println!("{}", left == proof.c_2);

            if left != proof.c_2 {
                return false;
            }
        }

        if pairing(&credential.ecc_a.to_affine(), &self.ipk.ecc_y.to_affine()) != pairing(&credential.ecc_b.to_affine(), &G2Affine::generator()) {
            return false;
        }

        let sum = credential.ecc_a + credential.ecc_d;
        if pairing(&credential.ecc_c.to_affine(), &G2Affine::generator()) != pairing(&sum.to_affine(), &self.ipk.ecc_x.to_affine()) {
            return false;
        }

        true
    }
}

fn main() {
}

#[test]
fn test() {
    let mut rng = thread_rng();

    let issuer = Issuer::random(&mut rng);
    
    let mut issuer_join_proces = IssuerJoinProcess::new(issuer.clone());
    let n = issuer_join_proces.gen_nonce(&mut rng);
    
    let member_join_proces = MemberJoinProcess::random(issuer.ipk, n, &mut rng);
    
    let proof = member_join_proces.prove_haveing_sk(&mut rng);
    let is_valid= issuer_join_proces.is_proof_having_sk(&proof);
    assert!(is_valid);

    let credential = issuer_join_proces.gen_member_credential(&mut rng);
    let proof = issuer_join_proces.prove_member_credential_valid(&mut rng);

    let is_valid= member_join_proces.is_member_credential_valid(&credential, &proof);
    assert!(is_valid);
}
