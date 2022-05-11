
use fawkes_crypto::{
    circuit::{cs::{DebugCS, CS}, bool::CBool},
    core::{signal::Signal, sizedvec::SizedVec},
    engines::bn256::Fr,
};
use itertools::Itertools;

use keccak256::native::hash::keccak256;
use keccak256::circuit::hash::{c_keccak256};


fn perform_test(data:&[u8]) {
    let result = keccak256(data);
    let bits: SizedVec<bool,256> = (0..256).map(|i| result[i/8] & (1 << (i%8)) != 0).collect();
    let size = data.len();

    let data = data.iter().flat_map(|e| (0..8).map(|i| (*e >> i) & 1==1)).collect::<Vec<_>>();


    let ref mut cs = DebugCS::<Fr>::rc_new();
    let c_data = data.iter().map(|e| CBool::alloc(cs, Some(&e))).collect_vec();

    let mut n_constraints = cs.borrow().num_gates();
    let c_result = c_keccak256(&cs, &c_data);
    n_constraints = cs.borrow().num_gates() - n_constraints;

    c_result.assert_const(&bits);

    println!("keccak256([{} bytes]) constraints = {}", size, n_constraints);
    assert!(c_result.get_value().unwrap().iter().zip(bits.iter()).all(|(a,b)| a == b));

}





#[test]
fn test_circuit_short_value() {
    let data = b"A perfect hash function";
    perform_test(data);
}




#[test]
fn test_circuit_long_value() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a randomized algorithm in a number of operations";
    perform_test(data);
}



#[test]
fn test_circuit_bitrate_sized_value() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a";
    perform_test(data);
}



#[test]
fn test_circuit_bitrate_minus_one_sized_value() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by ";
    perform_test(data);
}



#[test]
fn test_circuit_zero_sized_value() {
    let data = b"";
    perform_test(data);
}

