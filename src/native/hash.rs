use std::{ops::BitXor};


pub const ROUND_CONSTANTS: [u64;24] = [
    0x0000000000000001,   0x0000000000008082,   0x800000000000808A,   0x8000000080008000,
    0x000000000000808B,   0x0000000080000001,   0x8000000080008081,   0x8000000000008009,
    0x000000000000008A,   0x0000000000000088,   0x0000000080008009,   0x000000008000000A,
    0x000000008000808B,   0x800000000000008B,   0x8000000000008089,   0x8000000000008003,
    0x8000000000008002,   0x8000000000000080,   0x000000000000800A,   0x800000008000000A,
    0x8000000080008081,   0x8000000000008080,   0x0000000080000001,   0x8000000080008008
];

pub const ROTATION_CONSTANTS: [[usize;5];5] = [
    [  0,  1, 62, 28, 27, ],
    [ 36, 44,  6, 55, 20, ],
    [  3, 10, 43, 25, 39, ],
    [ 41, 45, 15, 21,  8, ],
    [ 18,  2, 61, 56, 14, ]
];

pub const BITRATE_BYTES:usize = 136;
pub const BITRATE_CHUNKS:usize = BITRATE_BYTES / 8;
pub const WIDTH_BYTES:usize = 200;
pub const WIDTH_CHUNKS:usize = WIDTH_BYTES / 8;
pub const W:usize = 5;
pub const H:usize = 5;
pub const LANEW:usize = 64;
pub const NR:usize = 24;
pub const DIGEST_BYTES:usize = 32;
pub const DIGEST_CHUNKS:usize = DIGEST_BYTES / 8;

pub struct State(pub [[u64;W];H]);

impl State {
    pub fn new() -> Self {
        let state = [[0;W];H];
        State(state)
    }
}
pub struct Block(pub [u64;BITRATE_CHUNKS]);


// Circularly rotate 'value' to the left,
// treating it as a quantity of the given size in bits.
const fn rol(value: u64, left:usize) -> u64 {
    if left == 0 {
        value
    } else {
        let top = value >> (u64::BITS as usize - left);
        let bot = value << left;
        bot | top
    }
}

// Read keccak256 block from the given slice.
fn read_block(data:&mut&[u8]) -> Block {
    let mut res = [0; BITRATE_CHUNKS];
    let len = data.len();
    let block = if len >= BITRATE_BYTES {
        let res = data[..BITRATE_BYTES].to_vec();
        *data = &data[BITRATE_BYTES..len];
        res
    } else {
        let padlen = BITRATE_BYTES - len;
        let res = if padlen > 1 {
            data.iter().cloned().chain(std::iter::once(0x01).chain(std::iter::repeat(0x00).take(padlen-2)).chain(std::iter::once(0x80))).collect()
        } else {
            data.iter().cloned().chain(std::iter::once(0x81)).collect()
        };
        *data = &data[len..len];
        res
    };

    for i in 0..BITRATE_CHUNKS {
        res[i] = u64::from_le_bytes(block[i*8..(i+1)*8].try_into().unwrap());
    }

    Block(res)
}


fn absorb_block(state:&mut State, block:&Block) {
    for i in 0..BITRATE_CHUNKS {
        state.0[i%W][i/W] ^= block.0[i];
    }
    keccak_f(state);
}


pub fn keccak256(data:&[u8]) -> [u8;DIGEST_BYTES] {
    let mut state = State::new();

    let mut data = data;
    let n_blocks = data.len() / BITRATE_BYTES + 1;
    for _ in 0 .. n_blocks {
        let block = read_block(&mut data);
        absorb_block(&mut state, &block);
    }


    let mut res = [0; DIGEST_BYTES];
    for i in 0..DIGEST_CHUNKS {
        res[i*8..(i+1)*8].copy_from_slice(&state.0[i%W][i/W].to_le_bytes());
    }
    res
}

fn keccak_f(state:&mut State) {
    fn round(state:&mut State, rc:u64) {

        //theta
        let c = state.0.iter().map(|row| row.iter().fold(0, u64::bitxor)).collect::<Vec<_>>();
        for x in 0..W {
            let d = c[(W+x-1)%W] ^ rol(c[(x+1)%W], 1);
            for y in 0..H {
                state.0[x][y] ^= d;
            }
        }

        //rho & pi
        let mut b = [[0;W];H];
        for x in 0..W {
            for y in 0..H {
                b[y % W][(2 * x + 3 * y) % H] = rol(state.0[x][y], ROTATION_CONSTANTS[y][x]);
            }
        }

        //chi
        for x in 0..W {
            for y in 0..H {
                state.0[x][y] = b[x][y] ^ ((!b[(x + 1) % W][y]) & b[(x + 2) % W][y])
            }
        }

        //iota
        state.0[0][0] ^= rc;
    }

    for i in 0..NR {
        round(state, ROUND_CONSTANTS[i]);
    }
}

