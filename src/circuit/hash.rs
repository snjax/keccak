use fawkes_crypto::circuit::{num::CNum, bool::CBool, cs::{CS, RCS}, bitify::c_from_bits_le};
use fawkes_crypto::ff_uint::{PrimeFieldParams, Num, NumRepr};
use fawkes_crypto::core::sizedvec::SizedVec;
use fawkes_crypto::core::signal::Signal;
use std::{ops::Add, iter::repeat};


use crate::circuit::bitifyex::{c_from_bits_le_ex, c_into_bits_le_ex};


use crate::native::hash::{BITRATE_BYTES, W, H, NR, ROUND_CONSTANTS, ROTATION_CONSTANTS, BITRATE_CHUNKS, DIGEST_CHUNKS, DIGEST_BYTES};


type CU64<C> = SizedVec<CBool<C>, 64>;
type CState<C> = SizedVec<CU64<C>, {W*H}>;


// Circularly rotate 'value' to the left,
// treating it as a quantity of the given size in bits.
fn rol<C:CS>(value: &[CBool<C>], left:usize) -> Vec<CBool<C>> {
    let size = value.len();
    let left = left % size;
    value.iter().chain(value.iter())
        .skip(size-left)
        .take(size)
        .cloned()
        .collect()
}



pub fn c_keccak_f<C:CS>(state:&mut CState<C>) {
    fn round<C:CS>(state:&mut CState<C>, rc:u64) {
        let rc_ex = {
            let mut t = NumRepr::<<C::Fr as PrimeFieldParams>::Inner>::ZERO;
            for i in 0..64 {
                if (rc >> i) & 1 == 1 {
                    let n = 3*i + 1;
                    let limb = n / 64;
                    let bitpos = n % 64;
                    t.as_inner_mut().as_mut()[limb] |= 1 << bitpos;
                }
            }
            Num::from_uint_unchecked(t)
        };

        let one_ex = {
            let mut t = NumRepr::<<C::Fr as PrimeFieldParams>::Inner>::ZERO;
            for i in 0..64 { 
                let n = 3*i;
                let limb = n / 64;
                let bitpos = n % 64;
                t.as_inner_mut().as_mut()[limb] |= 1 << bitpos;
            }
            Num::from_uint_unchecked(t)
        };
        

        let c = state.as_slice().chunks(H).map(|row| {
            let  c = row.iter().map(|e|
                c_from_bits_le_ex(e.as_slice(), 3, 0) 
            ).reduce(CNum::add).unwrap();
            let bits = c_into_bits_le_ex(&c, 64*3, 3, 0);
            c_from_bits_le_ex(&bits, 2, 0)
        }).collect::<Vec<_>>();

        let theta:Vec<Vec<Vec<_>>> = (0..W).map(|x| {
            let d = &c[(W+x-1)%W] + &c[(x+1)%W]*Num::from(4u64);
            (0..H).map(|y| {
                let s = &d+c_from_bits_le_ex(state[x*H+y].as_slice(), 2, 0);
                let mut bits = c_into_bits_le_ex(&s, 65*2, 2, 0);
                let t = bits[64].clone();
                bits[0] ^= t;
                bits[0..64].to_vec()
            }).collect()
        }).collect();


        let rho_phi:Vec<Vec<_>> = (0..W).map(|x| {
            (0..H).map(|y| {
                let m = (3*y+x) % H;
                let bits = rol(&theta[m][x], ROTATION_CONSTANTS[x][m]);
                c_from_bits_le_ex(&bits, 3, 0)
            }).collect()
        }).collect();

        let chi:Vec<Vec<_>> = (0..W).map(|x| {
            (0..H).map(|y| {
                let a = &rho_phi[x][y];
                let b = &rho_phi[(x+1)%W][y];
                let c = &rho_phi[(x+2)%W][y];
                a*Num::from(2u64) + one_ex - b + c
            }).collect()
        }).collect();

        let mut iota = chi;

        iota[0][0]+=rc_ex;

        for x in 0..W {
            for y in 0..H {
                let bits = c_into_bits_le_ex(&iota[x][y], 3*64, 3, 1);
                state[x*H+y].as_mut_slice().clone_from_slice(&bits);
            }
        }
    }

    for i in 0..NR {
        round(state, ROUND_CONSTANTS[i]);
    }
}


fn c_absorb_block<C:CS>(state:&mut CState<C>, block:&[CBool<C>]) {
    for i in 0..BITRATE_CHUNKS {
        let t = i%W*H+i/W;
        let a = c_from_bits_le_ex(state[t].as_slice(), 2, 0);
        let b = c_from_bits_le_ex(&block[i*64..(i+1)*64], 2, 0);
        state[t].as_mut_slice().clone_from_slice(&c_into_bits_le_ex(&(a+b), 64*2, 2, 0));
    }
    c_keccak_f(state);
}


pub fn c_keccak256<C:CS>(cs: &RCS<C>, data:&[CBool<C>]) -> SizedVec<CBool<C>, 256> {
    let len = data.len();
    assert!(len % 8 == 0, "data length must be a multiple of 8");
    let c_false = &CBool::from_const(cs, &false);
    let c_true = &CBool::from_const(cs, &true);
    

    let n_blocks = len / (8 * BITRATE_BYTES) + 1;
    let total_len = n_blocks * 8* BITRATE_BYTES;

    let mut data = data.iter().chain(repeat(c_false)).take(total_len*8).cloned().collect::<Vec<_>>();

    data[len] = c_true.clone();
    data[total_len-1] = c_true.clone();

    let mut state: CState<C> = repeat(&repeat(c_false).take(64).cloned().collect()).take(W*H).cloned().collect();

    for i in 0..n_blocks {
        c_absorb_block(&mut state, &data[i*BITRATE_BYTES*8..(i+1)*BITRATE_BYTES*8]);
    }

    (0..DIGEST_CHUNKS).flat_map(|i| state[i%W*H+i/W].iter()).take(DIGEST_BYTES*8).cloned().collect()
}


pub fn c_keccak256_reduced<C:CS>(cs: &RCS<C>, data:&[CBool<C>]) -> CNum<C> {
    let h = c_keccak256(cs, data);
    c_from_bits_le(h.as_slice())

}

