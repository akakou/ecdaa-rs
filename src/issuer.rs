// use crate::{utils::g2, EcdaaError};
// use mcl_rust::{Fr, G2};

use alloc::{format, vec};
use fp256bn_amcl::fp256bn::ecp::ECP;
use fp256bn_amcl::fp256bn::ecp2::ECP2;
use fp256bn_amcl::fp256bn::{self, big};
use fp256bn_amcl::sha3::{HASH256, SHA3};
use fp256bn_amcl::{fp256bn::big::BIG, sha3};

use fp256bn_amcl::rand::RAND;

use crate::utils::{export_ecp, export_ecp2, g2, p};
use crate::EcdaaError;

// use crate::utils::rand_fr;

pub struct ISK {
    pub x: BIG,
    pub y: BIG,
}

impl ISK {
    pub fn new(x: BIG, y: BIG) -> Self {
        Self { x, y }
    }

    pub fn random(rng: &mut RAND) -> Self {
        let x = BIG::random(rng);
        let y = BIG::random(rng);

        Self::new(x, y)
    }
}

pub struct IPK {
    pub x: ECP2,
    pub y: ECP2,
    pub c: BIG,
    pub sx: BIG,
    pub sy: BIG,
}

impl IPK {
    pub fn new(x: ECP2, y: ECP2, c: BIG, sx: BIG, sy: BIG) -> Self {
        Self { x, y, c, sx, sy }
    }

    pub fn random(isk: &ISK, rng: &mut RAND) -> Self {
        // X = g2^x
        // Y = g2^y
        let x = ECP2::mul(&g2(), &isk.x);
        let y = ECP2::mul(&g2(), &isk.y);

        // pick rx, ry
        let rx = BIG::random(rng);
        let ry = BIG::random(rng);

        // Ux = g2^rx
        // Uy = g2^ry
        let ux = ECP2::mul(&g2(), &rx);
        let uy = ECP2::mul(&g2(), &ry);

        // c = Hash(ux|uy|g2|x|y)
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp2(&ux));
        sha.process_array(&export_ecp2(&uy));
        sha.process_array(&export_ecp2(&g2()));
        sha.process_array(&export_ecp2(&x));
        sha.process_array(&export_ecp2(&y));

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c = BIG::frombytes(&digest.to_vec());

        // sx = c . x + rx
        // sy = c . y + ry
        let mut sx = BIG::modmul(&isk.x, &c, &p());
        sx = BIG::modadd(&rx, &sx, &p());

        let mut sy: BIG = BIG::modmul(&isk.y, &c, &p());
        sy = BIG::modadd(&sy, &ry, &p());

        Self::new(x, y, c, sx, sy)
    }

    pub fn valid(&self) -> EcdaaError {
        // Ux = g2^sx . X^(-c)
        let mut ux = ECP2::mul(&g2(), &self.sx);
        let tmp = ECP2::mul(&self.x, &self.c);
        ux.sub(&tmp);

        // Uy = g2^sy . Y^(-c)
        let mut uy = ECP2::mul(&g2(), &self.sy);
        let tmp = ECP2::mul(&self.y, &self.c);
        uy.sub(&tmp);

        // c = Hash(ux|uy|g2|x|y)
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp2(&ux));
        sha.process_array(&export_ecp2(&uy));
        sha.process_array(&export_ecp2(&g2()));
        sha.process_array(&export_ecp2(&self.x));
        sha.process_array(&export_ecp2(&self.y));

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c = BIG::frombytes(&digest.to_vec());

        if BIG::comp(&c, &self.c) == 0 {
            Ok(())
        } else {
            #[cfg(feature = "tests")]
            println!("IPK is not valid ({:?} != {:?})", c, self.c);
            Err(0)
        }
    }
}
