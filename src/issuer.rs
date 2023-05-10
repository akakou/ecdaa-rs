// use crate::{utils::g2, EcdaaError};
// use mcl_rust::{Fr, G2};

use alloc::vec;
use fp256bn_amcl::fp256bn::ecp::ECP;
use fp256bn_amcl::fp256bn::ecp2::ECP2;
use fp256bn_amcl::fp256bn::{self, big};
use fp256bn_amcl::sha3::{HASH256, SHA3};
use fp256bn_amcl::{fp256bn::big::BIG, sha3};

use fp256bn_amcl::rand::RAND;

use crate::utils::{export_ecp, export_ecp2, g2, p};

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
        // let mut x = ECP2::zero();
        // let mut y = G2::zero();

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
        let c = BIG::frombytearray(&digest, 32);

        // sx = c . x + rx
        // sy = c . y + ry
        let mut sx = BIG::modmul(&c, &isk.x, &p());
        sx = BIG::modadd(&sx, &rx, &p());

        let mut sy: BIG = BIG::modmul(&c, &isk.y, &p());
        sy = BIG::modadd(&sy, &ry, &p());

        Self::new(x, y, c, sx, sy)
    }

    // pub fn valid(&self) -> EcdaaError {
    //     let g2 = g2();

    //     let mut tmp1 = G2::zero();
    //     let mut tmp2 = G2::zero();

    //     // // Ux = g2^sx * X^(-c)
    //     G2::mul(&mut tmp1, &g2, &self.sx);
    //     G2::mul(&mut tmp2, &self.x, &self.c);
    //     let ux = &tmp1 - &tmp2;

    //     // // Uy = g2^sy * Y^(-c)
    //     G2::mul(&mut tmp1, &g2, &self.sy);
    //     G2::mul(&mut tmp2, &self.y, &self.c);
    //     let uy = &tmp1 - &tmp2;

    //     let mut buf = vec![];
    //     buf.append(&mut ux.serialize());
    //     buf.append(&mut uy.serialize());
    //     buf.append(&mut g2.serialize());
    //     buf.append(&mut self.x.serialize());
    //     buf.append(&mut self.y.serialize());

    //     let mut c = Fr::zero();
    //     c.set_hash_of(&buf);

    //     if c == self.c {
    //         Ok(())
    //     } else {
    //         let msg = format!("IPK is not valid ({:?} != {:?}).", c, self.c);
    //         Err(msg)
    //     }
    // }
}
