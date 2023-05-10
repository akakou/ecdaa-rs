use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP},
    rand::RAND,
    sha3::{HASH256, SHA3},
};

use crate::{
    utils::{export_big, export_ecp, g1, p},
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
        hash: &ECP,
        mut rng: &mut RAND,
    ) -> Self {
        let r = BIG::random(&mut rng);

        // E = q^r
        let e = b.mul(&r);

        // L = B^r
        let l = hash.mul(&r);

        // K = B^sk
        let k = hash.mul(&sk);

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

    pub fn valid(&self, msg: &[u8], basename: &[u8], s: &ECP, w: &ECP, hash: &ECP) -> EcdaaError {
        // E = S^s . W^-c
        // ----------------
        // S^s . W^-c
        //     = S^(r + c . sk) . W^-c
        //     = S^(r + c . sk) . W^-(c)
        //     = B^l .(r + c . sk) . Q^-(c . r . l)
        //     = B  .(r + c . sk) . Q ^ - (c . r )
        //     = B ^ sk
        let mut e = s.mul(&self.s);
        let tmp = w.mul(&self.c);
        e.sub(&tmp);

        // L = B^s - K^c
        // ----------
        // B^s - K^c
        //     = B^(r + c . sk) - B^(c . sk)
        //     = B^r
        //     = L
        let mut l = hash.mul(&self.s);
        let tmp = self.k.mul(&self.c);
        l.sub(&tmp);

        // c2 =  H(E, L, B, K, [S, W, basename, message])
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp(&e));
        sha.process_array(&export_ecp(&l));
        sha.process_array(&export_ecp(&s));
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
