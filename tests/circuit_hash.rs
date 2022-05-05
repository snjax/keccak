
use fawkes_crypto::{
    circuit::{cs::{DebugCS, CS}, num::CNum},
    core::{signal::Signal, sizedvec::SizedVec},
    engines::bn256::Fr,
    ff_uint::Num,
    borsh::BorshDeserialize
};
use itertools::Itertools;

use keccak256::native::hash::keccak256;
use keccak256::circuit::hash::{FILED_LIMB_SIZE, c_keccak256};

const FILED_LIMB_SIZE_BYTES: usize = FILED_LIMB_SIZE / 8;

fn perform_test(data:&[u8], is_big_endian:bool) {
    let result = keccak256(data);
    let bits: SizedVec<bool,256> = (0..256).map(|i| result[i/8] & (1 << (i%8)) != 0).collect();
    let size = data.len();
    let n_limbs = (size + FILED_LIMB_SIZE_BYTES - 1 ) / FILED_LIMB_SIZE_BYTES;

    let data: Vec<Num<Fr>> = data.iter().chain(std::iter::repeat(&0))
        .chunks(FILED_LIMB_SIZE_BYTES)
        .into_iter()
        .take(n_limbs)
        .map(|c| {
        
        
        let s = if is_big_endian {
            c.cloned().collect_vec().into_iter().rev().chain(std::iter::repeat(0)).take(32).collect_vec()
        } else {
            c.cloned().chain(std::iter::repeat(0)).take(32).collect_vec()
        };
        
        BorshDeserialize::try_from_slice(s.as_slice()).unwrap()

    }).collect_vec();

    let ref mut cs = DebugCS::rc_new();
    let c_data = data.iter().map(|e| CNum::alloc(cs, Some(e))).collect_vec();

    let mut n_constraints = cs.borrow().num_gates();
    let c_result = c_keccak256(&cs, &c_data, size, is_big_endian);
    n_constraints = cs.borrow().num_gates() - n_constraints;

    c_result.assert_const(&bits);

    println!("keccak256([{} bytes]) constraints = {}", size, n_constraints);
    assert!(c_result.get_value().unwrap().iter().zip(bits.iter()).all(|(a,b)| a == b));

}



#[test]
fn test_circuit_short_value_be() {
    let data = b"A perfect hash function";
    perform_test(data, true);
}

#[test]
fn test_circuit_short_value_le() {
    let data = b"A perfect hash function";
    perform_test(data, false);
}


#[test]
fn test_circuit_long_value_be() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a randomized algorithm in a number of operations";
    perform_test(data, true);
}

#[test]
fn test_circuit_long_value_le() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a randomized algorithm in a number of operations";
    perform_test(data, false);
}

#[test]
fn test_circuit_bitrate_sized_value_be() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a";
    perform_test(data, true);
}

#[test]
fn test_circuit_bitrate_sized_value_le() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a";
    perform_test(data, false);
}

#[test]
fn test_circuit_bitrate_minus_one_sized_value_be() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by ";
    perform_test(data, true);
}

#[test]
fn test_circuit_bitrate_minus_one_sized_value_le() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by ";
    perform_test(data, false);
}

#[test]
fn test_circuit_zero_sized_value_be() {
    let data = b"";
    perform_test(data, true);
}

#[test]
fn test_circuit_zero_sized_value_le() {
    let data = b"";
    perform_test(data, false);
}

