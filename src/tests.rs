use rand::thread_rng;
use alloc::vec;
use alloc::vec::Vec;

use super::core::{Issuer, Verifier, RogueList};
use super::join::{IssuerJoinProcess, MemberJoinProcess};


#[test]
fn test_flow() {
    let mut rng = thread_rng();

    let issuer = Issuer::random(&mut rng);

    let mut issuer_join_proces = IssuerJoinProcess::new(issuer.clone());
    let n = issuer_join_proces.gen_nonce(&mut rng);

    let mut member_join_proces = MemberJoinProcess::random(issuer.ipk, n, &mut rng);

    let proof = member_join_proces.prove_haveing_sk(&mut rng);
    let is_valid = issuer_join_proces.is_proof_having_sk(&proof);
    assert!(is_valid);

    let credential = issuer_join_proces.gen_member_credential(&mut rng);
    let proof = issuer_join_proces.prove_member_credential_valid(&mut rng);

    let is_valid = member_join_proces.is_member_credential_valid(credential, &proof);
    assert!(is_valid);

    let member = member_join_proces.gen_member();

    let msg: Vec<u8> = vec![2, 4, 3];
    let dummy: Vec<u8> = vec![2, 4, 4];

    let signature = member.sign(&msg, &mut rng);

    let verifier = Verifier::new(issuer.ipk);

    let result1 = verifier.verify(&signature, &msg);
    let result2 = verifier.verify(&signature, &dummy);    

    assert!(result1);
    assert!(!result2);

    let mut rl = RogueList {
        list: vec![]
    };
    let result3 = verifier.verify_revocation(&signature , &rl);
    rl.list.push(member.sk);

    let result4 = verifier.verify_revocation(&signature , &rl);

    assert!(result3);
    assert!(!result4);
}

#[test]
#[cfg(std)]
fn test_serde() {
    use serde_json;
    use super::core::ISK;

    let mut rng = thread_rng();
    let issuer = Issuer::random(&mut rng);

    let string = serde_json::to_string(&issuer.isk).unwrap();
    println!("{}", string);

    let isk : ISK = serde_json::from_str(&string).unwrap();
    println!("{:?}", isk);
}