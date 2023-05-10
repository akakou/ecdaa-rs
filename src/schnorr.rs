use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP},
    rand::RAND,
    sha3::{HASH256, SHA3},
};

use crate::{
    utils::{export_big, export_ecp, export_ecp2, p},
    EcdaaError,
};

pub struct SchnorrProof {
    pub c: BIG,
    pub s: BIG,
    pub n: BIG,
    pub k: ECP,
}

impl SchnorrProof {
    pub fn random(
        msg: &[u8],
        basename: &[u8],
        sk: &BIG,
        b: &ECP,
        q: &ECP,
        mut rng: &mut RAND,
    ) -> Self {
        let r = BIG::random(&mut rng);

        // E = B^r
        let e = q.mul(&r);

        // L = B^r
        let l = b.mul(&r);

        // K = B^sk
        let k = b.mul(&sk);

        // c2 = H(E, L, B, K, [S, W, basename, message])
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp(&e));
        sha.process_array(&export_ecp(&l));
        sha.process_array(&export_ecp(&b));
        sha.process_array(&export_ecp(&k));
        sha.process_array(&basename.to_vec());
        sha.process_array(&msg.to_vec());

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c2 = BIG::frombytes(&digest.to_vec());

        // c1 = H(n | c2)
        let n = BIG::random(&mut rng);

        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_big(&n));
        sha.process_array(&export_big(&c2));

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c = BIG::frombytes(&digest.to_vec());

        // s = r + c . sk
        let mut s = BIG::modmul(&c, &sk, &p());
        s = BIG::modadd(&r, &s, &p());

        Self { s, c, n, k }
    }

    pub fn valid(&self, msg: &[u8], basename: &[u8], b: &ECP, q: &ECP) -> EcdaaError {
        // E = B^s . Q^-c
        // ----------------
        // B^s . Q^-c
        //     = B^(r + c . sk) . Q^-c
        //     = B^(r + c . sk) . Q^-(c)
        //     = B^(r + c . sk) . B^-(c . sk)
        //     = B^r
        //     = E
        let mut e = b.mul(&self.s);
        let tmp = q.mul(&self.c);
        e.sub(&tmp);

        // L = B^s - K^c
        // ----------
        // B^s - K^c
        //     = B^(r + c . sk) - B^(c . sk)
        //     = B^r
        //     = L
        let mut l = b.mul(&self.s);
        let tmp = self.k.mul(&self.c);
        l.sub(&tmp);

        // c2 =  H(E, L, B, K, [S, W, basename, message])
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp(&e));
        sha.process_array(&export_ecp(&l));
        sha.process_array(&export_ecp(&b));
        sha.process_array(&export_ecp(&self.k));
        sha.process_array(&basename.to_vec());
        sha.process_array(&msg.to_vec());

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c2 = BIG::frombytes(&digest.to_vec());

        // c1 = H(n | c2)
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_big(&self.n));
        sha.process_array(&export_big(&c2));

        let mut digest = [0; 32];
        sha.hash(&mut digest);
        let c = BIG::frombytes(&digest.to_vec());

        if BIG::comp(&c, &self.c) == 0 {
            Ok(())
        } else {
            #[cfg(feature = "tests")]
            println!("{}", "schnorr proof is not valid".to_string());
            Err(0)
        }
    }
}
