use fp256bn_amcl::{
    fp256bn::{big::BIG, ecp::ECP},
    rand::RAND,
    sha3::{HASH256, SHA3},
};
use serde::{Deserialize, Serialize};

use crate::{
    utils::{export_big, export_ecp, hash_to_ecp, p},
    EcdaaError,
};

#[derive(Deserialize, Serialize, Copy, Clone)]
pub struct SchnorrProof {
    pub c: BIG,
    pub s: BIG,
    pub n: BIG,
    pub k: Option<ECP>,
}

impl SchnorrProof {
    pub fn commit(
        sk: &BIG,
        b: &ECP,
        s: &ECP,
        calc_k: bool,
        mut rng: &mut RAND,
    ) -> (BIG, ECP, ECP, Option<ECP>) {
        let r = BIG::random(&mut rng);

        // E = S^r
        let e = s.mul(&r);

        // L = B^r
        let l = b.mul(&r);

        let k = if calc_k {
            // K = B^sk
            Some(b.mul(&sk))
        } else {
            None
        };

        return (r, e, l, k);
    }

    pub fn random(
        msg: &[u8],
        basename: &[u8],
        sk: &BIG,
        s: &ECP,
        w: &ECP,
        calc_k: bool,
        mut rng: &mut RAND,
    ) -> Self {
        let b = hash_to_ecp(basename).expect("hashing errror").1;

        let (r, e, l, k) = Self::commit(sk, &b, s, calc_k, &mut rng);

        // c' = H(E, S, W, [L, B, K, basename, message])
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp(&e));
        sha.process_array(&export_ecp(&s));
        sha.process_array(&export_ecp(&w));

        if calc_k {
            let unwraped_k = &k.expect("K");

            sha.process_array(&export_ecp(&l));
            sha.process_array(&export_ecp(&b));
            sha.process_array(&export_ecp(unwraped_k));
            sha.process_array(&basename.to_vec());
        }

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

    pub fn valid(&self, msg: &[u8], basename: &[u8], s: &ECP, w: &ECP, calc_k: bool) -> EcdaaError {
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

        // c' = H(E, S, W, [L, B, K, basename, message])
        let mut sha = SHA3::new(HASH256);
        sha.process_array(&export_ecp(&e));
        sha.process_array(&export_ecp(&s));
        sha.process_array(&export_ecp(&w));

        if calc_k {
            let b = hash_to_ecp(basename).expect("hashing errror").1;

            let k = match self.k {
                Some(k) => k,
                None => return Err(2),
            };

            // L = B^s - K^c
            // ----------
            // B^s - K^c
            //     = B^(r + c . sk) - B^(c . sk)
            //     = B^r
            //     = L
            let mut l = b.mul(&self.s);
            let tmp = self.k.expect("failed to get k").mul(&self.c);
            l.sub(&tmp);

            sha.process_array(&export_ecp(&l));
            sha.process_array(&export_ecp(&b));
            sha.process_array(&export_ecp(&k));
            sha.process_array(&basename.to_vec());
        }

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
