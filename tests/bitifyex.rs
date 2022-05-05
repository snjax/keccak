
use fawkes_crypto::{
    circuit::{cs::{DebugCS, CS}, num::CNum, bitify::{c_into_bits_le, c_from_bits_le}},
    core::{signal::Signal, sizedvec::SizedVec},
    engines::bn256::Fr,

    rand::{thread_rng, Rng},
    ff_uint::Num
};


use keccak256::circuit::bitifyex::{c_from_bits_le_ex, c_into_bits_le_ex};

#[test]
fn test_xor_2_nums() {
    let mut rng = thread_rng();

    let a: u64 = rng.gen();
    let b: u64 = rng.gen();
    let res2 = Num::<Fr>::from(a ^ b);

    let ref mut cs = DebugCS::rc_new();

    let c_a = CNum::alloc(cs, Some(&Num::from(a)));
    let c_b = CNum::alloc(cs, Some(&Num::from(b)));
    


    let mut n_constraints = cs.borrow().num_gates();
    
    let c_a_bits = c_into_bits_le(&c_a, 64);
    let c_b_bits = c_into_bits_le(&c_b, 64);
    
    let c_a_ex = c_from_bits_le_ex(&c_a_bits, 2, 0);
    let c_b_ex = c_from_bits_le_ex(&c_b_bits, 2, 0);

    let c_c_ex = c_a_ex+c_b_ex;

    let c_c_bits = c_into_bits_le_ex(&c_c_ex, 2*64, 2, 0);
    let res = c_from_bits_le(&c_c_bits);




    n_constraints = cs.borrow().num_gates() - n_constraints;

    res.assert_const(&res2);

    println!("xor 2 items constraints = {}", n_constraints);
    assert!(res.get_value().unwrap() == res2);
}


#[test]
fn test_xor_5_nums() {
    const NNUMS:usize = 5;
    const WINDOW:usize = 3;

    let mut rng = thread_rng();

    let (nums, res2) = {
        let t:[u64;NNUMS] = rng.gen();
        let res = Num::<Fr>::from(t.iter().cloned().reduce(std::ops::BitXor::bitxor).unwrap());
        let nums = t.iter().map(|&e| Num::<Fr>::from(e)).collect::<SizedVec<_, NNUMS>>();
        (nums, res)
    };

    let ref mut cs = DebugCS::rc_new();
    let c_nums = SizedVec::<CNum<_>, NNUMS>::alloc(cs, Some(&nums));
    let mut n_constraints = cs.borrow().num_gates();
    let c_nums_bits = c_nums.iter().map(|c| c_into_bits_le(c, 64)).collect::<SizedVec<_, NNUMS>>();
    let c_nums_ex = c_nums_bits.iter().map(|c| c_from_bits_le_ex(c, WINDOW, 0)).collect::<SizedVec<_, NNUMS>>();
    let c_res_ex = c_nums_ex.iter().cloned().reduce(std::ops::Add::add).unwrap();


    let c_res_bits = c_into_bits_le_ex(&c_res_ex, WINDOW*64, WINDOW, 0);
    let res = c_from_bits_le(&c_res_bits);

    n_constraints = cs.borrow().num_gates() - n_constraints;
    res.assert_const(&res2);
    println!("xor 5 items constraints = {}", n_constraints);
    assert!(res.get_value().unwrap() == res2);
}

