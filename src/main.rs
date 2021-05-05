#[macro_use] extern crate slice_as_array;


use bls12_381::{Scalar, G2Projective};
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

fn gen_rand_scalar(rng: &mut impl RngCore) -> Scalar {
    Scalar::random(rng)  
}

impl Issuer {
    pub fn new(rng: &mut impl RngCore) -> Self {
        // todo: be argument
        
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

        let ecc_u_x_bin = ecc_u_x.to_bytes();
        let ecc_u_y_bin = ecc_u_y.to_bytes();

        let ecc_x_bin = ecc_x.to_bytes();
        let ecc_y_bin = ecc_y.to_bytes();

        let mut vec = Vec::new();
        vec.append(ecc_u_x_bin.as_ref().to_vec().as_mut());
        vec.append(ecc_u_y_bin.as_ref().to_vec().as_mut());
        vec.append(ecc_x_bin.as_ref().to_vec().as_mut());
        vec.append(ecc_y_bin.as_ref().to_vec().as_mut());

        let mut hasher = Sha256::new();
        hasher.update(&vec);
        let hashed = hasher.finalize().to_vec();

        // let c:  = hashed.as_ref().read_u8().unwrap();
        let mut c: Vec<u64> = vec![0; hashed.len()/8];
        BigEndian::read_u64_into(&hashed, &mut c);
        let c = slice_as_array!(&c, [u64; 4]).expect("bad hash length");

        let c = Scalar::from_raw(*c);
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

fn main() {
    let mut rng = thread_rng();
    // let rng = Box::new(rng);
    let issuer = Issuer::new(&mut rng);

    println!("{}", issuer.ipk.c);

    println!("Hello, world!");
}
