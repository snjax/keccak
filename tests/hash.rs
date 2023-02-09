use fawkes_crypto_keccak256::native::hash::keccak256;
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
fn test_long_value_2() {
    let data = b"In computer science, a perfect hash function h for a set S is a hash function that maps distinct elements in S to a set of m integers, with no collisions. In mathematical terms, it is an injective function. Perfect hash functions may be used to implement a lookup table with constant worst-case access time. A perfect hash function can, as any hash function, be used to implement hash tables, with the advantage that no collision resolution has to be implemented. In addition, if the keys are not the data and if it is known that queried keys will be valid, then the keys do not need to be stored in the lookup table, saving space. Disadvantages of perfect hash functions are that S needs to be known for the construction of the perfect hash function. Non-dynamic perfect hash functions need to be re-constructed if S changes. For frequently changing S dynamic perfect hash functions may be used at the cost of additional space.[1] The space requirement to store the perfect hash function is in O(n). The important performance parameters for perfect hash functions are the evaluation time, which should be constant, the construction time, and the representation size.";
    assert_eq!(encode(&keccak256(data)), "7c9232f4303dcbf7a0121c622154441549050e85b29997ef38fe8e42e745f5db");
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