use keccak256::native::hash::keccak256;
use hex::encode;

#[test]
fn test_short_value() {
    let data = b"A perfect hash function";
    assert_eq!(encode(&keccak256(data)), "d2694ffc7370e33901d1309e7d66a76798ee84023e94724f6f3c313f0a4ffa56");
}

#[test]
fn test_long_value() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a randomized algorithm in a number of operations";
    assert_eq!(encode(&keccak256(data)), "60d820b069bdb4545c690a11e8f8e6e444878010228920dd1598925a8fc2edcf");
}
#[test]
fn test_bitrate_sized_value() {
    let data = b"A perfect hash function for a specific set S that can be evaluated in constant time, and with values in a small range, can be found by a";
    assert_eq!(encode(&keccak256(data)), "cbc4b8ef339db1aaa81db0865c8010717a80b2314934d12c805653a0eb9b44f6");
}

#[test]
fn test_zero_sized_value() {
    let data = b"";
    assert_eq!(encode(&keccak256(data)), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}