use crate::{utils::g2, EcdaaError};
use mcl_rust::{Fr, G2};

use crate::utils::rand_fr;

pub struct ISK {
    pub x: Fr,
    pub y: Fr,
}

impl ISK {
    pub fn new(x: Fr, y: Fr) -> Self {
        crate::utils::initalize_mcl();

        Self { x, y }
    }

    pub fn random() -> Self {
        let x = rand_fr();
        let y = rand_fr();

        Self::new(x, y)
    }
}

pub struct IPK {
    pub x: G2,
    pub y: G2,
    pub c: Fr,
    pub sx: Fr,
    pub sy: Fr,
}

impl IPK {
    pub fn new(x: G2, y: G2, c: Fr, sx: Fr, sy: Fr) -> Self {
        crate::utils::initalize_mcl();

        Self { x, y, c, sx, sy }
    }

    pub fn generate(isk: &ISK) -> Self {
        // X = g2^x
        // Y = g2^y
        let mut x = G2::zero();
        let mut y = G2::zero();

        G2::mul(&mut x, &g2(), &isk.x);
        G2::mul(&mut y, &g2(), &isk.y);

        // pick rx, ry
        let rx = rand_fr();
        let ry = rand_fr();

        // Ux = g2^rx
        // Uy = g2^ry
        let mut ux = G2::zero();
        let mut uy = G2::zero();

        G2::mul(&mut ux, &g2(), &rx);
        G2::mul(&mut uy, &g2(), &ry);
        // let g2 = G2::zero();
        println!("g2: {:?}\n", g2().serialize());

        // c = Hash(ux|uy|g2|x|y)
        let mut buf = vec![];
        buf.append(&mut ux.serialize());
        buf.append(&mut uy.serialize());
        buf.append(&mut g2().serialize());
        buf.append(&mut x.serialize());
        buf.append(&mut y.serialize());

        let mut c = Fr::zero();
        c.set_hash_of(&buf);

        // sx = c . x + rx
        // sy = c . y + ry
        let sx = &(&c * &isk.x) + &rx;
        let sy = &(&c * &isk.y) + &ry;

        Self::new(x, y, c, sx, sy)
    }

    pub fn valid(&self) -> EcdaaError {
        let g2 = g2();

        let mut tmp1 = G2::zero();
        let mut tmp2 = G2::zero();

        // // Ux = g2^sx * X^(-c)
        G2::mul(&mut tmp1, &g2, &self.sx);
        G2::mul(&mut tmp2, &self.x, &self.c);
        let ux = &tmp1 - &tmp2;

        // // Uy = g2^sy * Y^(-c)
        G2::mul(&mut tmp1, &g2, &self.sy);
        G2::mul(&mut tmp2, &self.y, &self.c);
        let uy = &tmp1 - &tmp2;

        let mut buf = vec![];
        buf.append(&mut ux.serialize());
        buf.append(&mut uy.serialize());
        buf.append(&mut g2.serialize());
        buf.append(&mut self.x.serialize());
        buf.append(&mut self.y.serialize());

        let mut c = Fr::zero();
        c.set_hash_of(&buf);

        if c == self.c {
            Ok(())
        } else {
            let msg = format!("IPK is not valid ({:?} != {:?}).", c, self.c);
            Err(msg)
        }
    }
}
