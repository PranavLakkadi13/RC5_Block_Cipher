use std::vec;

fn main() {
    println!("Hello, world!");
}

/*

A and B are plain text in 2 words
S -- generated from the the private key K
S -- is the extended key (imp sizeOf(s) = 2 * (r + 1))

    ENCRYPTION-

A = A + S[0]
B = B + S[1]
For i = 1, to 2 * (r + 1)
    A = ((A ^ B) << B ) + S[2 * i]
    B = ((B ^ A) << A) + S[2 * i + 1]

*/

// So here the type Word has so many traits that it has inherited
// since this is our custom type we are telling rust on how to handle the operation
pub trait Word:
    Clone
    + Copy
    + std::ops::AddAssign
    + std::ops::BitXor<Output = Self>
    + std::ops::Shl<Output = Self>
    + std::ops::Shr<Output = Self>
    + std::ops::Add<Output = Self>
    + std::ops::SubAssign
    + std::ops::Sub<Output = Self>
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
{
    const ZERO: Self;
    const BYTES: usize;
    const P: Self;
    const Q: Self;

    fn from_u8(val: u8) -> Self;
    fn from_usize(val: usize) -> Self;
}

// the genric inherits the trait Word
// this is the function that accepts a generic so that it can be used for all the input data sizes 32bit, 16bit, 64bit, 128bit
pub fn encrypt<W: Word>(plain_text: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    // TODO: extend the key
    let t = 2 * (rounds + 1);
    let s: Vec<W> = vec![W::ZERO; t];

    let [mut a, mut b] = plain_text;

    // to allow this feature of '+=' we need to make sure the Word inherits the AddAsign trait
    // also to allow the compiler to copy the values from the vec to the var 'a' and 'b' we need to explicitly give the copy permission so we use the copy trait
    a += s[0];
    b += s[1];

    for i in 1..t {
        a = ((a ^ b) << b) + s[2 * i];
        b = ((b ^ a) << a) + s[2 * i + 1];
    }

    [a, b]
}

/*

A and B are plain text in 2 words
S -- generated from the the private key K
S -- is the extended key (imp sizeOf(s) = 2 * (r + 1))

    DECRYPTION-

For i =  2 * (r + 1) to 1:
    B = (B - S[2 * i + 1] >> A) ^ A
    A = (A - S[2 * i] >> B) ^ B

B = B - S[1]
A = A - S[0]
*/

pub fn decrypt<W: Word>(cipher_text: [W; 2], key: Vec<u8>, rounds: usize) -> [W; 2] {
    // to extend key
    let t = 2 * (rounds + 1);
    let s: Vec<W> = vec![W::ZERO; t];

    let [mut a, mut b] = cipher_text;

    for i in t..1 {
        b = ((b - s[2 * i + 1]) >> a) ^ a;
        a = ((a - s[2 * i]) >> b) ^ b;
    }

    a -= s[0];
    b -= s[1];

    [a, b]
}

/*

    KEY EXPANSION

w -- word length in bytes (A word in RC5 is just a group of bits. its basically the block of data )
r -- encryption/decryption rounds
b -- original key length in bytes

1. Transform the original key in an array of words of L:

    key -- 0x01 0x02 0x03 0x04 0x05 (the key is 5 bytes)
    word -- u32 --> w -- 4 (since 32 bits is 4 bytes)

    // also this values should be in little endian
    L = [0x01020304, 0x05000000] (padding is allowed in block ciphers and in hex a pair of values is a byte)

    c = max(1,ceil(8*b/w))
    for i = b - 1 .. 0:
        L[i/w] = (L[i/w] << 8) + key[i]


2. Initialise an array S:

    To initialise the array we know that we use the constant values as per the paper
    Uses two constants P and Q (magic constants derived from e and φ)
    // since thse P and Q are constants and are depended on word we will declare them as constant in the trait

    S[0] = P
    for i = 1 .. (t - 1):
        S[i] = S[i-1] + Q


3. Mix S and L:

    i = j = 0
    A = B = 0
    do 3 * max(t,c) times:
        A = S[i] = (S[i] + A + B) << 3
        B = L[j] = (L[j] + A + B) << (A + B)
        i = (i + j) mod t
        j = (i + j) mod c

input: key: Vec<u8>
output: S: Vec<W>
*/

// here i am giving the generic value as the function arg since it is using it and returning the generic type
pub fn expand_key<W: Word>(key: Vec<u8>, rounds: usize) -> Vec<W> {
    let b = key.len(); // original key length
    let w = W::BYTES;
    let t = 2 * (rounds + 1);

    // the ceil(8*b/w) = (8 * b + (w - 1))/w --> we will verify this
    let temp = (8 * b + (w - 1)) / w;
    let c = std::cmp::max(1, temp);

    let mut key_l = vec![W::ZERO; c];

    // this step transforms the key from a array of bytes to array of word -----> SETP 1
    for i in (b - 1)..0 {
        //  L[i/w] = (L[i/w] << 8) + key[i]
        // here we will need to handle the case of overflows since rust would just panic and revert but the overflow is expected 
        key_l[i / w] = (key_l[i / w] << W::from_u8(8u8)) + W::from_u8(key[i]); // the issue here was that the key[i] is a byte and the key_l is a word so cant add them both directly
    }

    // INITIALISING THE ARRAY S: ----> STEP 2
    let mut key_s = vec![W::ZERO; t];
    key_s[0] = W::P;
    for i in 1..t {
        key_s[i] = key_s[i - 1] + W::Q;
    }

    // HERE WE WILL MIX THE S AND L: ---> SETP 3
    // we do these steps.....
    // i = j = 0
    // A = B = 0
    // do 3 * max(t,c) times:
    //     A = S[i] = (S[i] + A + B) << 3
    //     B = L[j] = (L[j] + A + B) << (A + B)
    //     i = (i + j) mod t
    //     j = (i + j) mod c

    let mut i = 0;
    let mut j = 0usize;
    let mut a = W::ZERO;
    let mut b = W::ZERO;

    let iters = std::cmp::max(t, c);

    for _ in 0..iters {
        key_s[i] = (key_s[i] + a + b) << W::from_u8(3u8);
        a = key_s[i];
        key_l[j] = (key_l[j] + a + b) << (a + b);
        b = key_l[j];
        i = (i + j) % t;
        j = (i + j) % c;
    }

    key_s
}


// will left shift x by y and not overflow
pub fn rotate_left<W: Word>(x: W, y: W) -> W {

    // gives the number of bits as Bytes is the word size in bytes
    let w = W::BYTES * 8;
    (x << y & W::from_usize((w - 1))) | (x >> ( W::from_usize(w) - (y - W::from_usize(w - 1)))) 
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test] // here we are going to see how normal bit shift works and later understand on how its different from rotation 
    fn test_left_right_shift() { // doing but shidt will lead to data loss so it is not intended behaviour 
        let a = 0x77u8;
        println!("a = {:2x?}", a);
        println!("a << 1 = {:2x?}", a << 1);
        println!("a << 7 = {:2x?}", a << 7);
        // println!("a << 8 = {:2x?}", a << 8); // this will overflow rust wont allow 
        println!("a << 8 = {:2x?}", rotate_left(a, Word::from_u8(8u8)));
    }
}
