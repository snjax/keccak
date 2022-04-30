use fawkes_crypto::circuit::{num::CNum, bool::CBool, cs::CS, bitify::{c_into_bits_le, c_into_bits_le}};
use fawkes_crypto::ff_uint::PrimeFieldParams;
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::ff_uint::Num;

use crate::native::hash::{BITRATE_BYTES, W, H};


const BITRATE_BITS: usize = BITRATE_BYTES * 8;

#[derive(Clone)]
pub struct CU64<C:CS>([CBool<C>;64]);

#[derive(Clone)]
pub struct CState<C:CS>([[CU64<C>;W];H]);


const FILED_LIMB_SIZE: usize = 248;

const INPUT_BE_INDEXES: [usize; FILED_LIMB_SIZE] = {
    for i in 0..FILED_LIMB_SIZE/8 {
        for j in 0..8 {
            t[i*8+j] = FILED_LIMB_SIZE - 8*(i+1) + j;
        }
    }
};

const INPUT_LE_INDEXES: [usize; FILED_LIMB_SIZE] = {
    for i in 0..FILED_LIMB_SIZE/8 {
        for j in 0..8 {
            t[i*8+j] = 8*i + j;
        }
    }
};




pub fn keccak256<C:CS>(data:&[CNum<CS>], len:usize, is_be:bool) -> [CBool<C>;256] {

    let s = data.iter().flat_map(|e| {
        let bits = c_into_bits_le(e, FILED_LIMB_SIZE);
        let indexes = if is_be { INPUT_BE_INDEXES} else { INPUT_LE_INDEXES };
        indexes.map(|i| bits[i])
    });

    std::unimplemented!()
}


