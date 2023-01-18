use std::println;

use alloc::vec;
use alloc::vec::Vec;
use rand::thread_rng;

use crate::utils::rand_fr;

#[test]
fn test_random_fr() {
    let mut rng = thread_rng();
    let a = rand_fr(&mut rng);
    let b = rand_fr(&mut rng);

    println!("a = {}", a.get_str(10));
    println!("b = {}", b.get_str(10));
}
