use fawkes_crypto::circuit::{num::CNum, bool::CBool, cs::CS, bitify::c_into_bits_le};
use fawkes_crypto::ff_uint::PrimeFieldParams;
use fawkes_crypto::ff_uint::Num;

pub fn c_from_bits_le_ex<C: CS>(bits: &[CBool<C>], window:usize, offset:usize) -> CNum<C> {
    assert!(bits.len() > 0, "should be positive number of bits");
    assert!(window > 0, "should be positive window size");
    assert!(bits.len() * window < C::Fr::MODULUS_BITS as usize, "window size too large");
    let mut k = Num::from(1 << offset);
    let mut acc = bits[0].to_num() * k;
    let multiplier = Num::from(1<<window);
    for i in 1..bits.len() {
        k = k * multiplier;
        acc += k * bits[i].to_num();   
    }
    acc
}

pub fn c_into_bits_le_ex<C: CS>(num: &CNum<C>, limit:usize, window:usize, offset:usize) -> Vec<CBool<C>> {
    assert!(window > 0, "should be positive window size");
    assert!(offset < window, "offset should be smaller than window size");
    assert!(limit < C::Fr::MODULUS_BITS as usize, "limit too large");
    assert!(limit % window == 0, "limit should be multiple of window size");

    let bits = c_into_bits_le(num, limit);
    bits.into_iter().skip(offset).step_by(window).collect()
}

